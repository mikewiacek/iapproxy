package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	iapTunnelEndpoint = "wss://tunnel.cloudproxy.app/v4/connect"
	iapScope          = "https://www.googleapis.com/auth/cloud-platform"
	subprotocolName   = "relay.tunnel.cloudproxy.app"
	tunnelOrigin      = "bot:iap-tunneler"
	
	// Subprotocol constants from Python implementation
	SUBPROTOCOL_TAG_CONNECT_SUCCESS_SID   = 0x0001
	SUBPROTOCOL_TAG_RECONNECT_SUCCESS_ACK = 0x0002
	SUBPROTOCOL_TAG_DATA                  = 0x0004
	SUBPROTOCOL_TAG_ACK                   = 0x0007

	// Performance tuning constants
	readBufferSize   = 32 * 1024  // 32KB read buffer (larger than default)
	writeBufferSize  = 32 * 1024  // 32KB write buffer
	maxFrameSize     = 16 * 1024  // 16KB max frame size (matches Python)
	channelBufferSize = 64        // Buffer for channels
)

type Config struct {
	ProjectID     string
	Zone          string
	Instance      string
	Port          int
	LocalPort     int
	LocalHost     string
	Verbosity     string
	ListenOnStdin bool
}

func main() {
	var config Config
	
	// Parse flags first
	flag.StringVar(&config.ProjectID, "project", "", "Google Cloud project ID")
	flag.StringVar(&config.Zone, "zone", "", "Zone of the instance")
	flag.IntVar(&config.LocalPort, "local-port", 0, "Local port to listen on")
	flag.StringVar(&config.LocalHost, "local-host", "127.0.0.1", "Local host to bind to")
	flag.StringVar(&config.Verbosity, "verbosity", "warning", "Verbosity level")
	flag.BoolVar(&config.ListenOnStdin, "listen-on-stdin", false, "Listen on stdin instead of creating local port")
	
	flag.Parse()

	// Get positional arguments (instance name and port)
	args := flag.Args()
	if len(args) < 2 {
		log.Fatal("Usage: iap-tunnel [flags] INSTANCE_NAME PORT")
	}

	config.Instance = args[0]
	
	port, err := strconv.Atoi(args[1])
	if err != nil {
		log.Fatalf("Invalid port: %s", args[1])
	}
	config.Port = port

	// Validate required fields
	if config.ProjectID == "" {
		log.Fatal("Project ID is required (use --project flag)")
	}
	if config.Zone == "" {
		log.Fatal("Zone is required (use --zone flag)")
	}

	if config.Verbosity == "debug" {
		log.Printf("Starting IAP tunnel to %s:%d in project %s, zone %s", 
			config.Instance, config.Port, config.ProjectID, config.Zone)
	}

	tunnel, err := NewIAPTunnel(config)
	if err != nil {
		log.Fatalf("Failed to create tunnel: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if config.Verbosity == "debug" {
			log.Println("Shutting down...")
		}
		cancel()
	}()

	if err := tunnel.Start(ctx); err != nil {
		log.Fatalf("Failed to start tunnel: %v", err)
	}
}

type IAPTunnel struct {
	config               Config
	client               *http.Client
	tokenSource          oauth2.TokenSource
	connectionSid        string
	totalBytesReceived   int64
	connected            bool
	connectMutex         sync.Mutex
	connectCond          *sync.Cond
}

func NewIAPTunnel(config Config) (*IAPTunnel, error) {
	ctx := context.Background()

	// Get OAuth2 token source - this is what gcloud uses
	tokenSource, err := google.DefaultTokenSource(ctx, iapScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}

	// Create HTTP client with OAuth2 transport
	client := oauth2.NewClient(ctx, tokenSource)

	tunnel := &IAPTunnel{
		config:      config,
		client:      client,
		tokenSource: tokenSource,
	}
	tunnel.connectCond = sync.NewCond(&tunnel.connectMutex)

	return tunnel, nil
}

func (t *IAPTunnel) Start(ctx context.Context) error {
	if t.config.ListenOnStdin {
		return t.startStdinTunnel(ctx)
	} else {
		return t.startPortTunnel(ctx)
	}
}

func (t *IAPTunnel) waitForConnection() {
	t.connectMutex.Lock()
	defer t.connectMutex.Unlock()
	
	for !t.connected {
		t.connectCond.Wait()
	}
}

func (t *IAPTunnel) startStdinTunnel(ctx context.Context) error {
	// Connect to IAP WebSocket
	ws, err := t.connectWebSocket(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IAP: %w", err)
	}
	defer ws.Close()

	return t.handleBidirectionalTransfer(ctx, ws, os.Stdin, os.Stdout)
}

func (t *IAPTunnel) startPortTunnel(ctx context.Context) error {
	localPort := t.config.LocalPort
	if localPort == 0 {
		localPort = 0 // Let system assign port
	}
	
	localAddr := fmt.Sprintf("%s:%d", t.config.LocalHost, localPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", localAddr, err)
	}
	defer listener.Close()

	actualPort := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Listening on port [%d].\n", actualPort)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return nil
				}
				log.Printf("Accept error: %v", err)
				continue
			}

			go t.handleConnection(ctx, conn)
		}
	}
}

func (t *IAPTunnel) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Connect to IAP WebSocket for this connection
	ws, err := t.connectWebSocket(ctx)
	if err != nil {
		log.Printf("Failed to connect to IAP for connection: %v", err)
		return
	}
	defer ws.Close()

	t.handleBidirectionalTransfer(ctx, ws, conn, conn)
}

// Optimized bidirectional transfer with buffering and batching
func (t *IAPTunnel) handleBidirectionalTransfer(ctx context.Context, ws *websocket.Conn, reader io.Reader, writer io.Writer) error {
	// Buffered channels for better performance
	wsToLocal := make(chan []byte, channelBufferSize)
	localToWs := make(chan []byte, channelBufferSize)
	done := make(chan error, 4)

	// WebSocket reader - handles incoming messages
	go func() {
		defer func() { done <- nil }()
		for {
			messageType, data, err := ws.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) && t.config.Verbosity == "debug" {
					log.Printf("WebSocket read error: %v", err)
				}
				return
			}
			if messageType == websocket.BinaryMessage {
				if extractedData := t.extractDataFromWebSocketMessage(data); extractedData != nil {
					select {
					case wsToLocal <- extractedData:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// WebSocket writer - handles outgoing messages with batching
	go func() {
		defer func() { done <- nil }()
		
		// Use a ticker for periodic flushing to reduce latency
		ticker := time.NewTicker(5 * time.Millisecond) // Small flush interval
		defer ticker.Stop()
		
		var batch [][]byte
		var batchSize int
		
		flushBatch := func() {
			if len(batch) == 0 {
				return
			}
			
			// Send batched data as individual frames (IAP protocol requirement)
			for _, data := range batch {
				frame := t.createSubprotocolDataFrame(data)
				if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					if t.config.Verbosity == "debug" {
						log.Printf("WebSocket write error: %v", err)
					}
					return
				}
			}
			batch = batch[:0]
			batchSize = 0
		}
		
		for {
			select {
			case data := <-localToWs:
				batch = append(batch, data)
				batchSize += len(data)
				
				// Flush if batch gets too large or we have many messages
				if batchSize > maxFrameSize || len(batch) > 10 {
					flushBatch()
				}
				
			case <-ticker.C:
				// Periodic flush to reduce latency
				flushBatch()
				
			case <-ctx.Done():
				flushBatch() // Final flush
				return
			}
		}
	}()

	// Wait for connection to be established
	t.waitForConnection()

	// Local reader - optimized with larger buffer
	go func() {
		defer func() { done <- nil }()
		buffer := make([]byte, readBufferSize)
		for {
			n, err := reader.Read(buffer)
			if err == io.EOF {
				return
			}
			if err != nil {
				if t.config.Verbosity == "debug" {
					log.Printf("Local read error: %v", err)
				}
				return
			}
			
			// Copy the data since we're reusing the buffer
			data := make([]byte, n)
			copy(data, buffer[:n])
			
			select {
			case localToWs <- data:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Local writer - optimized with buffering
	go func() {
		defer func() { done <- nil }()
		
		// Use a larger buffer for writing
		writeBuffer := make([]byte, 0, writeBufferSize)
		ticker := time.NewTicker(2 * time.Millisecond) // Very frequent flushes
		defer ticker.Stop()
		
		flushBuffer := func() {
			if len(writeBuffer) == 0 {
				return
			}
			if _, err := writer.Write(writeBuffer); err != nil {
				if t.config.Verbosity == "debug" {
					log.Printf("Local write error: %v", err)
				}
				return
			}
			writeBuffer = writeBuffer[:0]
		}
		
		for {
			select {
			case data := <-wsToLocal:
				// Accumulate in buffer
				if len(writeBuffer)+len(data) > writeBufferSize {
					flushBuffer()
				}
				writeBuffer = append(writeBuffer, data...)
				
				// Flush immediately if buffer is getting large
				if len(writeBuffer) > writeBufferSize/2 {
					flushBuffer()
				}
				
			case <-ticker.C:
				// Frequent flushes for low latency
				flushBuffer()
				
			case <-ctx.Done():
				flushBuffer() // Final flush
				return
			}
		}
	}()

	// Wait for any goroutine to finish (indicating connection closed)
	select {
	case <-done:
	case <-ctx.Done():
	}

	return nil
}

func (t *IAPTunnel) connectWebSocket(ctx context.Context) (*websocket.Conn, error) {
	// Get OAuth2 access token
	token, err := t.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Build the WebSocket URL with query parameters like gcloud does
	params := url.Values{}
	params.Set("project", t.config.ProjectID)
	params.Set("port", strconv.Itoa(t.config.Port))
	params.Set("newWebsocket", "true")  // Enable new websocket protocol
	params.Set("zone", t.config.Zone)
	params.Set("instance", t.config.Instance)
	params.Set("interface", "nic0")

	wsURL := fmt.Sprintf("%s?%s", iapTunnelEndpoint, params.Encode())

	// Create WebSocket headers exactly like the Python implementation
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token.AccessToken)
	headers.Set("User-Agent", "google-cloud-sdk gcloud/go-iap-tunnel")
	headers.Set("Origin", tunnelOrigin)

	// Create WebSocket dialer with optimized configuration
	dialer := websocket.Dialer{
		HandshakeTimeout:  30 * time.Second,
		Subprotocols:      []string{subprotocolName},
		ReadBufferSize:    readBufferSize,  // Larger read buffer
		WriteBufferSize:   writeBufferSize, // Larger write buffer
		// Disable compression for better performance (IAP doesn't need it)
		EnableCompression: false,
		TLSClientConfig: &tls.Config{
			ServerName: "tunnel.cloudproxy.app",
		},
	}
	
	if t.config.Verbosity == "debug" {
		log.Printf("Connecting to WebSocket: %s", wsURL)
		log.Printf("Using subprotocol: %s", subprotocolName)
		log.Printf("Buffer sizes: read=%d, write=%d", readBufferSize, writeBufferSize)
	}

	ws, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("websocket dial failed (status %d): %s, error: %w", resp.StatusCode, string(body), err)
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	// Set optimized WebSocket parameters
	ws.SetReadLimit(maxFrameSize * 2) // Allow larger messages
	ws.SetReadDeadline(time.Time{})   // No read timeout
	ws.SetWriteDeadline(time.Time{})  // No write timeout
	
	// Set ping/pong handlers for connection health
	ws.SetPingHandler(func(appData string) error {
		return ws.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
	})

	if t.config.Verbosity == "debug" {
		log.Printf("WebSocket connected successfully")
	}

	return ws, nil
}

// Optimized WebSocket message extraction
func (t *IAPTunnel) extractDataFromWebSocketMessage(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Extract tag using big-endian uint16
	tag := binary.BigEndian.Uint16(data[0:2])
	payload := data[2:]

	switch tag {
	case SUBPROTOCOL_TAG_DATA:
		// Extract data length and data
		if len(payload) < 4 {
			return nil
		}
		dataLen := binary.BigEndian.Uint32(payload[0:4])
		if len(payload) < int(4+dataLen) {
			return nil
		}
		actualData := payload[4 : 4+dataLen]
		t.totalBytesReceived += int64(len(actualData))
		return actualData

	case SUBPROTOCOL_TAG_CONNECT_SUCCESS_SID:
		// Handle connection success with SID
		if len(payload) < 4 {
			return nil
		}
		sidLen := binary.BigEndian.Uint32(payload[0:4])
		if len(payload) < int(4+sidLen) {
			return nil
		}
		sidData := payload[4 : 4+sidLen]
		t.connectionSid = string(sidData)
		
		t.connectMutex.Lock()
		t.connected = true
		t.connectCond.Broadcast()
		t.connectMutex.Unlock()
		
		if t.config.Verbosity == "debug" {
			log.Printf("Connection established with SID: %s", t.connectionSid)
		}
		return nil

	case SUBPROTOCOL_TAG_RECONNECT_SUCCESS_ACK:
		// Handle reconnection success
		t.connectMutex.Lock()
		t.connected = true
		t.connectCond.Broadcast()
		t.connectMutex.Unlock()
		
		if t.config.Verbosity == "debug" {
			log.Printf("Reconnection successful")
		}
		return nil

	case SUBPROTOCOL_TAG_ACK:
		// Handle ACK - just debug log
		if t.config.Verbosity == "debug" && len(payload) >= 8 {
			ackBytes := binary.BigEndian.Uint64(payload[0:8])
			log.Printf("Received ACK: %d bytes", ackBytes)
		}
		return nil

	default:
		if t.config.Verbosity == "debug" {
			log.Printf("Unknown subprotocol tag: 0x%04x", tag)
		}
		return nil
	}
}

// Create a subprotocol data frame matching Python's CreateSubprotocolDataFrame
func (t *IAPTunnel) createSubprotocolDataFrame(data []byte) []byte {
	// Format: >HI{len}s = big-endian uint16 (tag) + big-endian uint32 (length) + data
	frame := make([]byte, 6+len(data))
	
	// Write tag (big-endian uint16)
	binary.BigEndian.PutUint16(frame[0:2], SUBPROTOCOL_TAG_DATA)
	
	// Write data length (big-endian uint32)  
	binary.BigEndian.PutUint32(frame[2:6], uint32(len(data)))
	
	// Write data
	copy(frame[6:], data)
	
	return frame
}
