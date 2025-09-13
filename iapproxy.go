// Command iapproxy provides a high-performance IAP TCP tunnel for connecting to Google Cloud VM instances.
//
// This tool creates a secure tunnel through Google Cloud Identity-Aware Proxy (IAP) to connect
// to VM instances without requiring external IP addresses or VPN connections. It replicates the
// functionality of 'gcloud compute start-iap-tunnel' with enhanced performance and reliability.
//
// # Usage
//
//	iapproxy [flags] INSTANCE_NAME PORT
//
// # Examples
//
// Create a tunnel to SSH into a VM instance:
//
//	iapproxy --project=my-project --zone=us-central1-a my-vm 22
//
// Create a tunnel with a specific local port:
//
//	iapproxy --project=my-project --zone=us-central1-a --local-port=2222 my-vm 22
//
// Create a tunnel using stdin/stdout (useful for ProxyCommand):
//
//	iapproxy --project=my-project --zone=us-central1-a --listen-on-stdin my-vm 22
//
// Use with SSH ProxyCommand in ~/.ssh/config:
//
//	Host my-vm.iap
//	    HostName my-vm
//	    User myuser
//	    Port 22
//	    ProxyCommand iapproxy --project=my-project --zone=us-central1-a --listen-on-stdin %h %p
//
// # Authentication
//
// This tool uses Google Cloud Application Default Credentials (ADC). Ensure you are
// authenticated using one of these methods:
//
//	gcloud auth login
//	gcloud auth application-default login
//	export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
//
// # IAM Permissions
//
// The authenticated user or service account needs the following IAM roles:
//
//	roles/iap.tunnelResourceAccessor
//	roles/compute.instanceAdmin.v1 (or roles/compute.viewer for read-only access)
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/golang/glog"
	"github.com/gorilla/websocket"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// IAP tunnel endpoint and protocol constants.
const (
	iapTunnelEndpoint = "wss://tunnel.cloudproxy.app/v4/connect"
	iapScope          = "https://www.googleapis.com/auth/cloud-platform"
	subprotocolName   = "relay.tunnel.cloudproxy.app"
	tunnelOrigin      = "bot:iap-tunneler"
)

// Subprotocol tag constants from the IAP specification.
const (
	subprotocolTagConnectSuccessSID   = 0x0001
	subprotocolTagReconnectSuccessACK = 0x0002
	subprotocolTagData                = 0x0004
	subprotocolTagACK                 = 0x0007
)

// Buffer and connection configuration constants.
const (
	readBufferSize  = 16 * 1024 // 16KB read buffer
	writeBufferSize = 16 * 1024 // 16KB write buffer
	maxFrameSize    = 16 * 1024 // 16KB max frame size

	maxRetries        = 3
	retryBackoff      = 1 * time.Second
	connectionTimeout = 30 * time.Second
	writeTimeout      = 10 * time.Second
	readTimeout       = 60 * time.Second

	tokenRefreshBuffer       = 5 * time.Minute  // Refresh token 5 minutes before expiry
	healthCheckInterval      = 30 * time.Second // Check connection health
	maxIdleTime              = 5 * time.Minute  // Max time without data transfer
	localHealthCheckInterval = 5 * time.Second  // Check local connection health
	maxLocalReadTimeout      = 30 * time.Second // Max time to wait for local read

	proactiveTokenRefreshInterval = 20 * time.Minute // Refresh every 20 minutes
	tokenRefreshJitter            = 2 * time.Minute  // Add randomness to avoid thundering herd
	maxTokenAge                   = 25 * time.Minute // Force refresh after this time
	tokenErrorRetryInterval       = 1 * time.Minute  // Retry after token errors
)

// Config holds the tunnel configuration parameters.
type Config struct {
	ProjectID     string
	Zone          string
	Instance      string
	Port          int
	LocalPort     int
	LocalHost     string
	ListenOnStdin bool
	LogFile       string // Keep this for explicit log file control beyond log
}

// connectionStats tracks tunnel performance and reliability metrics.
type connectionStats struct {
	bytesReceived    int64
	bytesSent        int64
	connections      int64
	reconnects       int64
	tokenRefreshes   int64
	wsConnections    int64
	wsErrors         int64
	localErrors      int64
	healthChecks     int64
	idleTimeouts     int64
	tokenErrors      int64
	sessionExpiries  int64
	proactiveRefresh int64

	startTime        time.Time
	lastTokenRefresh time.Time
	lastReconnect    time.Time
	lastActivity     time.Time
	lastTokenError   time.Time
}

// addTokenError increments the token error counter.
func (s *connectionStats) addTokenError() {
	atomic.AddInt64(&s.tokenErrors, 1)
	s.lastTokenError = time.Now()
}

// addReceived increments the bytes received counter.
func (s *connectionStats) addReceived(bytes int64) {
	atomic.AddInt64(&s.bytesReceived, bytes)
}

// addSent increments the bytes sent counter.
func (s *connectionStats) addSent(bytes int64) {
	atomic.AddInt64(&s.bytesSent, bytes)
}

// addConnection increments the connection counter.
func (s *connectionStats) addConnection() {
	atomic.AddInt64(&s.connections, 1)
}

// addTokenRefresh increments the token refresh counter and updates timestamp.
func (s *connectionStats) addTokenRefresh() {
	atomic.AddInt64(&s.tokenRefreshes, 1)
	s.lastTokenRefresh = time.Now()
}

// addWSConnection increments the WebSocket connection counter.
func (s *connectionStats) addWSConnection() {
	atomic.AddInt64(&s.wsConnections, 1)
}

// addWSError increments the WebSocket error counter.
func (s *connectionStats) addWSError() {
	atomic.AddInt64(&s.wsErrors, 1)
}

// addLocalError increments the local connection error counter.
func (s *connectionStats) addLocalError() {
	atomic.AddInt64(&s.localErrors, 1)
}

// addReconnect increments the reconnect counter and updates timestamp.
func (s *connectionStats) addReconnect() {
	atomic.AddInt64(&s.reconnects, 1)
	s.lastReconnect = time.Now()
}

// updateActivity updates the last activity timestamp.
func (s *connectionStats) updateActivity() {
	s.lastActivity = time.Now()
}

// addHealthCheck increments the health check counter.
func (s *connectionStats) addHealthCheck() {
	atomic.AddInt64(&s.healthChecks, 1)
}

// addIdleTimeout increments the idle timeout counter.
func (s *connectionStats) addIdleTimeout() {
	atomic.AddInt64(&s.idleTimeouts, 1)
}

// addProactiveRefresh increments the proactive token refresh counter.
func (s *connectionStats) addProactiveRefresh() {
	atomic.AddInt64(&s.proactiveRefresh, 1)
}

func main() {
	defer log.Flush()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config, err := parseFlags()
	if err != nil {
		log.Exitf("Configuration error: %v", err)
	}

	tunnel, err := NewIAPTunnel(ctx, config)
	if err != nil {
		log.Exitf("Failed to create tunnel: %v", err)
	}

	setupSignalHandlers(ctx, cancel, tunnel)

	// Start statistics reporting if debug logging is enabled (log V(2))
	if log.V(2) {
		go tunnel.reportStats(ctx)
	}

	if err := tunnel.Start(ctx); err != nil && err != context.Canceled {
		log.Exitf("Tunnel failed: %v", err)
	}
}

// parseFlags parses and validates command line arguments.
func parseFlags() (Config, error) {
	var config Config

	flag.StringVar(&config.ProjectID, "project", "", "Google Cloud project ID")
	flag.StringVar(&config.Zone, "zone", "", "Zone of the instance")
	flag.IntVar(&config.LocalPort, "local-port", 0, "Local port to listen on")
	flag.StringVar(&config.LocalHost, "local-host", "127.0.0.1", "Local host to bind to")
	flag.BoolVar(&config.ListenOnStdin, "listen-on-stdin", false, "Listen on stdin instead of creating local port")
	flag.StringVar(&config.LogFile, "log-file", "", "Log file path (in addition to log settings) to log stats on receiving a SIGUSR1 signal")

	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		return config, fmt.Errorf("usage: iap-tunnel [flags] INSTANCE_NAME PORT")
	}

	config.Instance = args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return config, fmt.Errorf("invalid port: %s", args[1])
	}
	config.Port = port

	if config.ProjectID == "" {
		return config, fmt.Errorf("project ID is required (use --project flag)")
	}
	if config.Zone == "" {
		return config, fmt.Errorf("zone is required (use --zone flag)")
	}

	return config, nil
}

// setupSignalHandlers configures signal handling for graceful shutdown and stats dumping.
func setupSignalHandlers(ctx context.Context, cancel context.CancelFunc, tunnel *IAPTunnel) {
	sigChan := make(chan os.Signal, 1)
	statsChan := make(chan os.Signal, 1)

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(statsChan, syscall.SIGUSR1)

	go func() {
		<-sigChan
		log.V(1).Info("Received shutdown signal")
		cancel()
	}()

	go func() {
		for {
			<-statsChan
			tunnel.dumpStats()
		}
	}()
}

// IAPTunnel manages the IAP tunnel connection and data transfer.
type IAPTunnel struct {
	config             Config
	client             *http.Client
	tokenSource        oauth2.TokenSource
	connectionSID      string
	totalBytesReceived int64 // Total bytes received across all connections
	connected          bool
	connectMutex       sync.RWMutex
	connectCond        *sync.Cond
	stats              *connectionStats
	activeConnections  sync.Map // Track active connection IDs for monitoring

	currentToken  *oauth2.Token
	tokenMutex    sync.RWMutex
	lastTokenTime time.Time
}

// NewIAPTunnel creates a new IAP tunnel instance.
func NewIAPTunnel(ctx context.Context, config Config) (*IAPTunnel, error) {
	tokenSource, err := google.DefaultTokenSource(ctx, iapScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}

	// Get initial token
	initialToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get initial token: %w", err)
	}

	client := oauth2.NewClient(ctx, tokenSource)
	client.Timeout = connectionTimeout

	tunnel := &IAPTunnel{
		config:        config,
		client:        client,
		tokenSource:   tokenSource,
		currentToken:  initialToken,
		lastTokenTime: time.Now(),
		stats: &connectionStats{
			startTime:    time.Now(),
			lastActivity: time.Now(),
		},
	}
	tunnel.connectCond = sync.NewCond(&tunnel.connectMutex)

	log.V(1).Infof("IAP tunnel created for %s:%d in %s/%s", config.Instance, config.Port, config.ProjectID, config.Zone)

	return tunnel, nil
}

// reportStats periodically reports tunnel statistics in debug mode.
func (t *IAPTunnel) reportStats(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			activeConns := 0
			t.activeConnections.Range(func(key, value interface{}) bool {
				activeConns++
				return true
			})

			log.V(2).Infof("Stats: received=%d bytes, sent=%d bytes, total_received=%d, connections=%d, active=%d, reconnects=%d",
				atomic.LoadInt64(&t.stats.bytesReceived),
				atomic.LoadInt64(&t.stats.bytesSent),
				atomic.LoadInt64(&t.totalBytesReceived),
				atomic.LoadInt64(&t.stats.connections),
				activeConns,
				atomic.LoadInt64(&t.stats.reconnects))
		case <-ctx.Done():
			return
		}
	}
}

// waitForConnection waits until the tunnel connection is established.
func (t *IAPTunnel) waitForConnection(ctx context.Context) error {
	t.connectMutex.Lock()
	defer t.connectMutex.Unlock()

	for !t.connected {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			t.connectCond.Wait()
		}
	}
	return nil
}

// setConnected updates the connection state and broadcasts to waiting goroutines.
func (t *IAPTunnel) setConnected(connected bool) {
	t.connectMutex.Lock()
	defer t.connectMutex.Unlock()

	t.connected = connected
	if connected {
		t.connectCond.Broadcast()
	}
}

// Start begins the tunnel operation in either stdin or port listening mode.
func (t *IAPTunnel) Start(ctx context.Context) error {
	// Start proactive token refresh service
	go t.runTokenRefreshService(ctx)

	if t.config.ListenOnStdin {
		return t.startStdinTunnel(ctx)
	}
	return t.startPortTunnel(ctx)
}

// startStdinTunnel handles tunnel operations using stdin/stdout.
func (t *IAPTunnel) startStdinTunnel(ctx context.Context) error {
	log.V(1).Info("Starting stdin tunnel mode")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			ws, err := t.connectWebSocketWithRetry(ctx)
			if err != nil {
				return fmt.Errorf("failed to connect to IAP: %w", err)
			}

			t.setConnected(false)
			err = t.handleBidirectionalTransfer(ctx, ws, os.Stdin, os.Stdout, "stdin")

			// Clean shutdown of WebSocket
			ws.SetWriteDeadline(time.Now().Add(1 * time.Second))
			ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			ws.Close()

			if err == context.Canceled || err == context.DeadlineExceeded {
				return err
			}

			log.Warningf("Connection lost, retrying: %v", err)

			select {
			case <-time.After(retryBackoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// startPortTunnel handles tunnel operations using a local TCP port.
func (t *IAPTunnel) startPortTunnel(ctx context.Context) error {
	localAddr := fmt.Sprintf("%s:%d", t.config.LocalHost, t.config.LocalPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", localAddr, err)
	}
	defer listener.Close()

	actualPort := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Listening on port [%d].\n", actualPort)
	log.V(1).Infof("Started port tunnel mode on %s:%d", t.config.LocalHost, actualPort)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return ctx.Err()
				}
				log.Errorf("Accept error: %v", err)
				continue
			}

			t.stats.addConnection()
			connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
			log.V(2).Infof("Accepted new connection: %s", connID)

			go t.handleConnection(ctx, conn, connID)
		}
	}
}

// handleConnection manages a single client connection through the tunnel.
func (t *IAPTunnel) handleConnection(ctx context.Context, conn net.Conn, connID string) {
	defer func() {
		conn.Close()
		t.activeConnections.Delete(connID)
		log.V(2).Infof("Connection %s closed", connID)
	}()

	// Track this connection
	t.activeConnections.Store(connID, time.Now())

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
			ws, err := t.connectWebSocketWithRetry(connCtx)
			if err != nil {
				log.Errorf("Failed to connect to IAP for connection %s: %v", connID, err)
				return
			}

			err = t.handleBidirectionalTransfer(connCtx, ws, conn, conn, connID)
			ws.Close()

			if err == context.Canceled || err == context.DeadlineExceeded {
				return
			}

			// Check if the connection is still valid
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 1)
			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			log.Warningf("WebSocket connection lost for %s, retrying: %v", connID, err)
			t.setConnected(false)
			t.stats.addReconnect()

			select {
			case <-time.After(retryBackoff):
			case <-connCtx.Done():
				return
			}
		}
	}
}

// connectWebSocketWithRetry attempts to establish a WebSocket connection with retry logic.
func (t *IAPTunnel) connectWebSocketWithRetry(ctx context.Context) (*websocket.Conn, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			ws, err := t.connectWebSocket(ctx)
			if err == nil {
				return ws, nil
			}

			if t.isTokenRelatedError(err) {
				log.Warningf("Token-related error detected, forcing token refresh: %v", err)
				t.stats.addTokenError()

				if _, refreshErr := t.refreshToken(ctx, "error recovery"); refreshErr != nil {
					log.Errorf("Failed to refresh token for error recovery: %v", refreshErr)
				}
			}

			t.stats.addWSError()
			lastErr = err
			log.Warningf("WebSocket connection attempt %d failed: %v", attempt, err)

			if attempt < maxRetries {
				backoff := time.Duration(attempt) * retryBackoff
				log.V(1).Infof("Retrying in %v", backoff)
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to connect after %d attempts, last error: %w", maxRetries, lastErr)
}

// isTokenRelatedError checks if an error is related to authentication or authorization.
func (t *IAPTunnel) isTokenRelatedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "token")
}

// handleBidirectionalTransfer manages data transfer between local and WebSocket connections.
func (t *IAPTunnel) handleBidirectionalTransfer(ctx context.Context, ws *websocket.Conn, reader io.Reader, writer io.Writer, connID string) error {
	transferCtx, transferCancel := context.WithCancel(ctx)
	defer transferCancel()

	errChan := make(chan error, 4)

	// WebSocket message reader
	go t.runWebSocketReader(transferCtx, ws, writer, errChan, transferCancel, connID)

	// Local reader to WebSocket writer
	go t.runLocalReader(transferCtx, ws, reader, errChan, transferCancel, connID)

	// Health monitor
	go t.runHealthMonitor(transferCtx, errChan, connID)

	// Wait for connection to be established
	if err := t.waitForConnection(transferCtx); err != nil {
		return err
	}

	log.V(2).Infof("Bidirectional transfer started for connection %s", connID)

	// Wait for first error or context cancellation
	select {
	case err := <-errChan:
		time.Sleep(50 * time.Millisecond) // Give other goroutines time to clean up
		if err != nil {
			return err
		}
		return fmt.Errorf("connection closed")
	case <-transferCtx.Done():
		return transferCtx.Err()
	}
}

// runWebSocketReader handles reading messages from the WebSocket connection.
func (t *IAPTunnel) runWebSocketReader(ctx context.Context, ws *websocket.Conn, writer io.Writer, errChan chan<- error, cancel context.CancelFunc, connID string) {
	defer func() {
		log.V(3).Infof("WebSocket reader goroutine exiting for %s", connID)
		cancel()
		errChan <- nil
	}()

	consecutiveErrors := 0
	const maxConsecutiveErrors = 3

	for {
		select {
		case <-ctx.Done():
			return
		default:
			ws.SetReadDeadline(time.Now().Add(readTimeout))

			messageType, data, err := ws.ReadMessage()
			if err != nil {
				consecutiveErrors++

				if websocket.IsCloseError(err, 4080, 4004) {
					log.Errorf("IAP connection error (code in close) for %s: %v", connID, err)
					errChan <- fmt.Errorf("IAP connection error: %w", err)
					return
				}

				if consecutiveErrors >= maxConsecutiveErrors {
					log.Errorf("Too many consecutive read errors (%d) for %s, forcing reconnect", consecutiveErrors, connID)
					errChan <- fmt.Errorf("consecutive error threshold exceeded")
					return
				}

				if !isExpectedCloseError(err) {
					log.Warningf("WebSocket read error #%d for %s: %v", consecutiveErrors, connID, err)
					t.stats.addWSError()
					time.Sleep(100 * time.Millisecond)
					continue
				}
				return
			}

			consecutiveErrors = 0

			if messageType == websocket.BinaryMessage {
				if extractedData := t.extractDataFromWebSocketMessage(data); extractedData != nil {
					dataLen := int64(len(extractedData))
					t.stats.addReceived(dataLen)
					atomic.AddInt64(&t.totalBytesReceived, dataLen)
					t.stats.updateActivity()

					log.V(3).Infof("Received %d bytes from WebSocket for %s", len(extractedData), connID)

					if netConn, ok := writer.(net.Conn); ok {
						netConn.SetWriteDeadline(time.Now().Add(writeTimeout))
					}

					if _, err := writer.Write(extractedData); err != nil {
						log.Errorf("Local write error for %s: %v", connID, err)
						t.stats.addLocalError()
						errChan <- err
						return
					}
				}
			}
		}
	}
}

// runLocalReader handles reading data from the local connection and sending to WebSocket.
func (t *IAPTunnel) runLocalReader(ctx context.Context, ws *websocket.Conn, reader io.Reader, errChan chan<- error, cancel context.CancelFunc, connID string) {
	defer func() {
		log.V(3).Infof("Local reader goroutine exiting for %s", connID)
		cancel()
		errChan <- nil
	}()

	buffer := make([]byte, maxFrameSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := reader.Read(buffer)
			if err == io.EOF {
				log.V(2).Infof("Local connection %s closed (EOF)", connID)
				return
			}
			if err != nil {
				if isTimeoutError(err) {
					continue
				}
				log.Errorf("Local read error for %s: %v", connID, err)
				t.stats.addLocalError()
				errChan <- err
				return
			}

			if n > 0 {
				data := make([]byte, n)
				copy(data, buffer[:n])

				frame := t.createSubprotocolDataFrame(data)
				ws.SetWriteDeadline(time.Now().Add(writeTimeout))

				if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					log.Errorf("WebSocket write error for %s: %v", connID, err)
					t.stats.addWSError()
					errChan <- err
					return
				}

				t.stats.addSent(int64(n))
				t.stats.updateActivity()
				log.V(3).Infof("Sent %d bytes to WebSocket for %s", n, connID)
			}
		}
	}
}

// runHealthMonitor monitors connection health and triggers reconnects if needed.
func (t *IAPTunnel) runHealthMonitor(ctx context.Context, errChan chan<- error, connID string) {
	defer func() { errChan <- nil }()

	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.stats.addHealthCheck()

			timeSinceActivity := time.Since(t.stats.lastActivity)
			if timeSinceActivity > maxIdleTime {
				log.Warningf("Connection %s idle for %v, forcing reconnect", connID, timeSinceActivity)
				t.stats.addIdleTimeout()
				errChan <- fmt.Errorf("idle timeout after %v", timeSinceActivity)
				return
			}

			log.V(3).Infof("Health check for %s: last activity %v ago", connID, timeSinceActivity)

		case <-ctx.Done():
			return
		}
	}
}

// connectWebSocket establishes a WebSocket connection to the IAP tunnel endpoint.
func (t *IAPTunnel) connectWebSocket(ctx context.Context) (*websocket.Conn, error) {
	token, err := t.getValidToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get valid token: %w", err)
	}

	// Build WebSocket URL with cache buster
	params := url.Values{}
	params.Set("project", t.config.ProjectID)
	params.Set("port", strconv.Itoa(t.config.Port))
	params.Set("newWebsocket", "true")
	params.Set("zone", t.config.Zone)
	params.Set("instance", t.config.Instance)
	params.Set("interface", "nic0")
	params.Set("_", fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63()))

	wsURL := fmt.Sprintf("%s?%s", iapTunnelEndpoint, params.Encode())

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token.AccessToken)
	headers.Set("User-Agent", "google-cloud-sdk gcloud/go-iap-tunnel")
	headers.Set("Origin", tunnelOrigin)

	log.V(2).Infof("Using token that expires at: %v (in %v)", token.Expiry, time.Until(token.Expiry))

	dialer := websocket.Dialer{
		HandshakeTimeout:  connectionTimeout,
		Subprotocols:      []string{subprotocolName},
		ReadBufferSize:    readBufferSize,
		WriteBufferSize:   writeBufferSize,
		EnableCompression: false,
		TLSClientConfig: &tls.Config{
			ServerName: "tunnel.cloudproxy.app",
		},
	}

	log.V(1).Infof("Connecting to WebSocket: %s", wsURL)

	ws, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("websocket dial failed (status %d): %s, error: %w", resp.StatusCode, string(body), err)
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	// Handle pong responses
	ws.SetPongHandler(func(appData string) error {
		log.V(3).Info("Received pong")
		return nil
	})

	t.stats.addWSConnection()
	log.V(1).Info("WebSocket connected successfully")
	return ws, nil
}

// extractDataFromWebSocketMessage parses IAP subprotocol messages and extracts data payload.
func (t *IAPTunnel) extractDataFromWebSocketMessage(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	tag := binary.BigEndian.Uint16(data[0:2])
	payload := data[2:]

	switch tag {
	case subprotocolTagData:
		if len(payload) < 4 {
			return nil
		}
		dataLen := binary.BigEndian.Uint32(payload[0:4])
		if len(payload) < int(4+dataLen) {
			return nil
		}
		return payload[4 : 4+dataLen]

	case subprotocolTagConnectSuccessSID:
		if len(payload) < 4 {
			return nil
		}
		sidLen := binary.BigEndian.Uint32(payload[0:4])
		if len(payload) < int(4+sidLen) {
			return nil
		}
		sidData := payload[4 : 4+sidLen]
		t.connectionSID = string(sidData)
		t.setConnected(true)
		log.V(1).Infof("Connection established with SID: %s", t.connectionSID)
		return nil

	case subprotocolTagReconnectSuccessACK:
		t.setConnected(true)
		log.V(1).Info("Reconnection successful")
		return nil

	case subprotocolTagACK:
		if log.V(3) && len(payload) >= 8 {
			ackBytes := binary.BigEndian.Uint64(payload[0:8])
			log.V(3).Infof("Received ACK: %d bytes", ackBytes)
		}
		return nil

	default:
		log.V(2).Infof("Unknown subprotocol tag: 0x%04x", tag)
		return nil
	}
}

// createSubprotocolDataFrame creates an IAP subprotocol data frame.
func (t *IAPTunnel) createSubprotocolDataFrame(data []byte) []byte {
	frame := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(frame[0:2], subprotocolTagData)
	binary.BigEndian.PutUint32(frame[2:6], uint32(len(data)))
	copy(frame[6:], data)
	return frame
}

// getValidToken returns a valid OAuth2 token, refreshing if necessary.
func (t *IAPTunnel) getValidToken(ctx context.Context) (*oauth2.Token, error) {
	t.tokenMutex.RLock()
	currentToken := t.currentToken
	lastTokenTime := t.lastTokenTime
	t.tokenMutex.RUnlock()

	now := time.Now()
	tokenAge := now.Sub(lastTokenTime)

	shouldRefresh := false
	refreshReason := ""

	if currentToken == nil {
		shouldRefresh = true
		refreshReason = "no current token"
	} else if currentToken.Expiry.Before(now.Add(tokenRefreshBuffer)) {
		shouldRefresh = true
		refreshReason = "token expiring soon"
	} else if tokenAge > maxTokenAge {
		shouldRefresh = true
		refreshReason = "token too old"
	} else if tokenAge > proactiveTokenRefreshInterval {
		jitter := time.Duration(rand.Int63n(int64(tokenRefreshJitter)))
		if tokenAge > proactiveTokenRefreshInterval+jitter {
			shouldRefresh = true
			refreshReason = "proactive refresh"
		}
	}

	if shouldRefresh {
		return t.refreshToken(ctx, refreshReason)
	}

	return currentToken, nil
}

// refreshToken obtains a fresh OAuth2 token from the token source.
func (t *IAPTunnel) refreshToken(ctx context.Context, reason string) (*oauth2.Token, error) {
	t.tokenMutex.Lock()
	defer t.tokenMutex.Unlock()

	// Double-check if another goroutine already refreshed
	if reason == "proactive refresh" && time.Since(t.lastTokenTime) < proactiveTokenRefreshInterval {
		log.V(2).Info("Token was already refreshed by another goroutine")
		return t.currentToken, nil
	}

	log.V(1).Infof("Refreshing token: %s", reason)

	tokenCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	freshTokenSource, err := google.DefaultTokenSource(tokenCtx, iapScope)
	if err != nil {
		t.stats.addTokenError()
		return nil, fmt.Errorf("failed to create fresh token source: %w", err)
	}

	newToken, err := freshTokenSource.Token()
	if err != nil {
		t.stats.addTokenError()
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	if newToken.AccessToken == "" {
		t.stats.addTokenError()
		return nil, fmt.Errorf("received empty access token")
	}

	// Update stored token
	t.currentToken = newToken
	t.lastTokenTime = time.Now()

	// Update token source for OAuth client
	t.tokenSource = oauth2.StaticTokenSource(newToken)
	t.client = oauth2.NewClient(tokenCtx, t.tokenSource)
	t.client.Timeout = connectionTimeout

	if reason == "proactive refresh" {
		t.stats.addProactiveRefresh()
	} else {
		t.stats.addTokenRefresh()
	}

	log.V(1).Infof("Token refreshed successfully, expires: %v", newToken.Expiry)
	return newToken, nil
}

// runTokenRefreshService proactively refreshes tokens to avoid expiry.
func (t *IAPTunnel) runTokenRefreshService(ctx context.Context) {
	initialDelay := proactiveTokenRefreshInterval + time.Duration(rand.Int63n(int64(tokenRefreshJitter)))
	ticker := time.NewTicker(initialDelay)
	defer ticker.Stop()

	log.V(1).Infof("Started proactive token refresh service (interval: %v)", proactiveTokenRefreshInterval)

	for {
		select {
		case <-ticker.C:
			ticker.Reset(proactiveTokenRefreshInterval)

			if _, err := t.getValidToken(ctx); err != nil {
				log.Errorf("Proactive token refresh failed: %v", err)
				ticker.Reset(tokenErrorRetryInterval)
			}

		case <-ctx.Done():
			log.V(1).Info("Token refresh service stopped")
			return
		}
	}
}

// dumpStats outputs comprehensive tunnel statistics.
func (t *IAPTunnel) dumpStats() {
	uptime := time.Since(t.stats.startTime)
	received := atomic.LoadInt64(&t.stats.bytesReceived)
	sent := atomic.LoadInt64(&t.stats.bytesSent)
	totalReceived := atomic.LoadInt64(&t.totalBytesReceived)
	connections := atomic.LoadInt64(&t.stats.connections)
	reconnects := atomic.LoadInt64(&t.stats.reconnects)
	tokenRefreshes := atomic.LoadInt64(&t.stats.tokenRefreshes)
	wsConnections := atomic.LoadInt64(&t.stats.wsConnections)
	wsErrors := atomic.LoadInt64(&t.stats.wsErrors)
	localErrors := atomic.LoadInt64(&t.stats.localErrors)
	healthChecks := atomic.LoadInt64(&t.stats.healthChecks)
	idleTimeouts := atomic.LoadInt64(&t.stats.idleTimeouts)

	// Count active connections
	activeConns := 0
	t.activeConnections.Range(func(key, value interface{}) bool {
		activeConns++
		return true
	})

	var buf strings.Builder

	buf.WriteString("\n=== IAP Tunnel Statistics ===\n")
	buf.WriteString(fmt.Sprintf("Runtime:\n"))
	buf.WriteString(fmt.Sprintf("  Uptime: %v\n", uptime.Round(time.Second)))
	buf.WriteString(fmt.Sprintf("  Started: %s\n", t.stats.startTime.Format("2006-01-02 15:04:05")))

	buf.WriteString(fmt.Sprintf("\nData Transfer:\n"))
	buf.WriteString(fmt.Sprintf("  Current session received: %d (%.2f MB)\n", received, float64(received)/(1024*1024)))
	buf.WriteString(fmt.Sprintf("  Current session sent: %d (%.2f MB)\n", sent, float64(sent)/(1024*1024)))
	buf.WriteString(fmt.Sprintf("  Total bytes received (all sessions): %d (%.2f MB)\n", totalReceived, float64(totalReceived)/(1024*1024)))
	buf.WriteString(fmt.Sprintf("  Session total: %d (%.2f MB)\n", received+sent, float64(received+sent)/(1024*1024)))

	if uptime.Seconds() > 0 {
		buf.WriteString(fmt.Sprintf("  Avg throughput: %.2f KB/s in, %.2f KB/s out\n",
			float64(received)/uptime.Seconds()/1024,
			float64(sent)/uptime.Seconds()/1024))
	}

	buf.WriteString(fmt.Sprintf("\nConnections:\n"))
	buf.WriteString(fmt.Sprintf("  Total local connections: %d\n", connections))
	buf.WriteString(fmt.Sprintf("  Active connections: %d\n", activeConns))
	buf.WriteString(fmt.Sprintf("  WebSocket connections: %d\n", wsConnections))
	buf.WriteString(fmt.Sprintf("  Reconnects: %d\n", reconnects))
	if !t.stats.lastReconnect.IsZero() {
		buf.WriteString(fmt.Sprintf("  Last reconnect: %s (%v ago)\n",
			t.stats.lastReconnect.Format("15:04:05"),
			time.Since(t.stats.lastReconnect).Round(time.Second)))
	}

	buf.WriteString(fmt.Sprintf("\nAuthentication:\n"))
	buf.WriteString(fmt.Sprintf("  Token refreshes: %d\n", tokenRefreshes))
	if !t.stats.lastTokenRefresh.IsZero() {
		buf.WriteString(fmt.Sprintf("  Last token refresh: %s (%v ago)\n",
			t.stats.lastTokenRefresh.Format("15:04:05"),
			time.Since(t.stats.lastTokenRefresh).Round(time.Second)))
	}

	buf.WriteString(fmt.Sprintf("\nErrors:\n"))
	buf.WriteString(fmt.Sprintf("  WebSocket errors: %d\n", wsErrors))
	buf.WriteString(fmt.Sprintf("  Local connection errors: %d\n", localErrors))

	if wsConnections > 0 {
		errorRate := float64(wsErrors) / float64(wsConnections) * 100
		buf.WriteString(fmt.Sprintf("  WebSocket error rate: %.1f%%\n", errorRate))
	}

	if connections > 0 {
		reconnectRate := float64(reconnects) / float64(connections) * 100
		buf.WriteString(fmt.Sprintf("  Reconnect rate: %.1f%%\n", reconnectRate))
	}

	buf.WriteString(fmt.Sprintf("\nHealth Monitoring:\n"))
	buf.WriteString(fmt.Sprintf("  Health checks: %d\n", healthChecks))
	buf.WriteString(fmt.Sprintf("  Idle timeouts: %d\n", idleTimeouts))
	if !t.stats.lastActivity.IsZero() {
		buf.WriteString(fmt.Sprintf("  Last activity: %s (%v ago)\n",
			t.stats.lastActivity.Format("15:04:05"),
			time.Since(t.stats.lastActivity).Round(time.Second)))
	}

	buf.WriteString("=============================\n\n")

	log.Infof("SIGUSR1 Stats Dump:\n%s", buf.String())

	// Also write to additional log file if specified
	if t.config.LogFile != "" {
		if f, err := os.OpenFile(t.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			f.WriteString(fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), buf.String()))
			f.Close()
		}
	}
}

// isExpectedCloseError checks if a WebSocket close error is expected during normal operation.
func isExpectedCloseError(err error) bool {
	return websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseAbnormalClosure,
		websocket.CloseNoStatusReceived,
		4080, // IAP "error while receiving from client"
		4004, // IAP "reauthentication required"
	)
}

// isTimeoutError checks if an error is a network timeout.
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
