// Command iapproxy provides a high-performance IAP TCP tunnel for connecting to Google Cloud VM instances.
//
// This tool creates a secure tunnel through Google Cloud Identity-Aware Proxy (IAP) to connect
// to VM instances without requiring external IP addresses or VPN connections. It implements
// Google's IAP WebSocket relay protocol v4 with optimized performance and reliability.
//
// # Protocol Overview
//
// The IAP tunnel uses a WebSocket-based relay protocol that exchanges binary frames:
//
//   - CONNECT_SUCCESS_SID (0x0001): Establishes session with server-assigned ID
//   - DATA (0x0004): Carries application data up to 16KB per frame
//   - ACK (0x0007): Acknowledges received bytes to prevent flow control stalls
//
// The protocol enforces single-reader/single-writer semantics and requires acknowledgment
// of received data within 1MB to maintain optimal throughput.
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
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	log "github.com/golang/glog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// IAP WebSocket relay protocol constants
const (
	// iapTunnelEndpoint is the WebSocket endpoint for IAP tunnel connections
	iapTunnelEndpoint = "wss://tunnel.cloudproxy.app/v4/connect"
	// iapScope defines the OAuth2 scope required for IAP access
	iapScope = "https://www.googleapis.com/auth/cloud-platform"
	// subprotocolName is the WebSocket subprotocol name for IAP relay
	subprotocolName = "relay.tunnel.cloudproxy.app"
	// tunnelOrigin identifies this client to the IAP service
	tunnelOrigin = "bot:iap-tunneler"
)

// IAP relay protocol message tags as defined in the v4 specification
const (
	// tagConnectSuccessSID indicates successful connection establishment with session ID
	tagConnectSuccessSID = 0x0001
	// tagReconnectSuccessACK indicates successful reconnection with acknowledgment
	tagReconnectSuccessACK = 0x0002
	// tagData carries application data payload
	tagData = 0x0004
	// tagACK acknowledges received bytes for flow control
	tagACK = 0x0007
)

// Protocol limits and timing constants based on IAP specification
const (
	// maxFrameSize is the maximum payload size per DATA frame (16KB)
	maxFrameSize = 16 * 1024
	// maxMessageSize includes frame header plus maximum payload
	maxMessageSize = 6 + maxFrameSize
	// relayBufferSize for local I/O operations
	relayBufferSize = 16 * 1024
	// ackThreshold triggers acknowledgment to prevent server stalls (1MB)
	ackThreshold = 1024 * 1024

	// Connection management
	maxRetries        = 3
	retryBackoff      = 1 * time.Second
	connectionTimeout = 30 * time.Second
	writeTimeout      = 10 * time.Second
	readTimeout       = 60 * time.Second

	// Token management
	tokenRefreshBuffer            = 5 * time.Minute
	proactiveTokenRefreshInterval = 20 * time.Minute
	tokenRefreshJitter            = 2 * time.Minute
	maxTokenAge                   = 25 * time.Minute
	tokenErrorRetryInterval       = 1 * time.Minute
)

// relayBufferPool reuses 16KB buffers for local I/O operations to reduce GC pressure.
var relayBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, relayBufferSize)
	},
}

// getRelayBuffer obtains a buffer from the pool for relay operations.
func getRelayBuffer() []byte {
	return relayBufferPool.Get().([]byte)
}

// putRelayBuffer returns a buffer to the pool if it's the expected size.
func putRelayBuffer(buf []byte) {
	if len(buf) == relayBufferSize {
		relayBufferPool.Put(buf)
	}
}

// Config holds tunnel configuration parameters parsed from command line flags.
type Config struct {
	ProjectID     string // Google Cloud project ID
	Zone          string // VM instance zone
	Instance      string // VM instance name
	Port          int    // Target port on the VM
	LocalPort     int    // Local port to bind (0 = auto-assign)
	LocalHost     string // Local host to bind to
	ListenOnStdin bool   // Use stdin/stdout instead of TCP socket
	LogFile       string // Optional log file path
}

// Stats tracks tunnel performance and reliability metrics using atomic operations
// for thread-safe access across multiple goroutines.
type Stats struct {
	bytesReceived    int64 // Total bytes received from WebSocket
	bytesSent        int64 // Total bytes sent to WebSocket
	connections      int64 // Number of local connections accepted
	reconnects       int64 // Number of WebSocket reconnections
	tokenRefreshes   int64 // Number of token refresh operations
	wsConnections    int64 // Number of WebSocket connection attempts
	wsErrors         int64 // Number of WebSocket errors
	localErrors      int64 // Number of local I/O errors
	tokenErrors      int64 // Number of token-related errors
	proactiveRefresh int64 // Number of proactive token refreshes
	acksReceived     int64 // Number of ACK frames received
	acksSent         int64 // Number of ACK frames sent

	startTime        time.Time // Tunnel start time
	lastTokenRefresh time.Time // Last successful token refresh
	lastReconnect    time.Time // Last WebSocket reconnection
	lastActivity     time.Time // Last data transfer activity
	lastTokenError   time.Time // Last token error
}

// Thread-safe stat increment methods
func (s *Stats) incACKReceived()          { atomic.AddInt64(&s.acksReceived, 1) }
func (s *Stats) incACKSent()              { atomic.AddInt64(&s.acksSent, 1) }
func (s *Stats) incBytesReceived(n int64) { atomic.AddInt64(&s.bytesReceived, n) }
func (s *Stats) incBytesSent(n int64)     { atomic.AddInt64(&s.bytesSent, n) }
func (s *Stats) incConnections()          { atomic.AddInt64(&s.connections, 1) }
func (s *Stats) incReconnects()           { atomic.AddInt64(&s.reconnects, 1); s.lastReconnect = time.Now() }
func (s *Stats) incTokenRefreshes() {
	atomic.AddInt64(&s.tokenRefreshes, 1)
	s.lastTokenRefresh = time.Now()
}
func (s *Stats) incWSConnections()    { atomic.AddInt64(&s.wsConnections, 1) }
func (s *Stats) incWSErrors()         { atomic.AddInt64(&s.wsErrors, 1) }
func (s *Stats) incLocalErrors()      { atomic.AddInt64(&s.localErrors, 1) }
func (s *Stats) incTokenErrors()      { atomic.AddInt64(&s.tokenErrors, 1); s.lastTokenError = time.Now() }
func (s *Stats) incProactiveRefresh() { atomic.AddInt64(&s.proactiveRefresh, 1) }
func (s *Stats) updateActivity()      { s.lastActivity = time.Now() }

// StreamClosedError indicates the tunnel stream has been closed and cannot be used.
type StreamClosedError struct {
	message string
}

func (e *StreamClosedError) Error() string {
	return e.message
}

// Tunnel manages an IAP WebSocket tunnel connection with automatic reconnection,
// token refresh, and flow control. It implements the single-reader/single-writer
// pattern required by the IAP relay protocol.
//
// The tunnel maintains exactly one active WebSocket connection at a time and
// coordinates all I/O operations through semaphores to prevent protocol violations.
type Tunnel struct {
	config Config
	client *http.Client
	stats  *Stats

	// Connection state
	sessionID          string
	totalBytesReceived int64
	connected          bool
	connectMutex       sync.RWMutex
	connectCond        *sync.Cond
	activeConnections  sync.Map

	// OAuth2 token management
	tokenSource   oauth2.TokenSource
	currentToken  *oauth2.Token
	tokenMutex    sync.RWMutex
	lastTokenTime time.Time

	// Protocol flow control - single reader/writer enforcement
	readerSemaphore chan struct{}
	writerSemaphore chan struct{}

	// Stream lifecycle management
	closed               int32 // atomic flag
	forceCloseCancel     context.CancelFunc
	forceCloseCancelOnce sync.Once

	// ACK protocol state (protected by single reader/writer semantics)
	bytesReceived   uint64 // Total bytes received in current session
	lastAckSent     uint64 // Last ACK value sent to server
	lastAckReceived uint64 // Last ACK value received from server
}

// NewTunnel creates a new IAP tunnel with the given configuration.
// It establishes OAuth2 credentials and initializes the tunnel state.
func NewTunnel(ctx context.Context, config Config) (*Tunnel, error) {
	tokenSource, err := google.DefaultTokenSource(ctx, iapScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}

	initialToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get initial token: %w", err)
	}

	client := oauth2.NewClient(ctx, tokenSource)
	client.Timeout = connectionTimeout

	tunnel := &Tunnel{
		config:        config,
		client:        client,
		tokenSource:   tokenSource,
		currentToken:  initialToken,
		lastTokenTime: time.Now(),
		stats: &Stats{
			startTime:    time.Now(),
			lastActivity: time.Now(),
		},
		readerSemaphore: make(chan struct{}, 1),
		writerSemaphore: make(chan struct{}, 1),
	}

	// Initialize semaphores as available
	tunnel.readerSemaphore <- struct{}{}
	tunnel.writerSemaphore <- struct{}{}

	tunnel.connectCond = sync.NewCond(&tunnel.connectMutex)

	log.V(1).Infof("IAP tunnel created for %s:%d in %s/%s",
		config.Instance, config.Port, config.ProjectID, config.Zone)
	return tunnel, nil
}

// isStreamClosed checks if the tunnel stream has been closed.
func (t *Tunnel) isStreamClosed() error {
	if atomic.LoadInt32(&t.closed) == 1 {
		return &StreamClosedError{"tunnel stream is closed"}
	}
	return nil
}

// closeStream marks the stream as closed and cancels any pending operations.
func (t *Tunnel) closeStream() {
	atomic.StoreInt32(&t.closed, 1)
	t.forceCloseCancelOnce.Do(func() {
		if t.forceCloseCancel != nil {
			t.forceCloseCancel()
		}
	})
}

// reportStats periodically logs tunnel statistics for monitoring and debugging.
func (t *Tunnel) reportStats(ctx context.Context) {
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

			log.V(2).Infof("Stats: received=%d bytes, sent=%d bytes, total_received=%d, connections=%d, active=%d, reconnects=%d, acks_sent=%d, acks_received=%d",
				atomic.LoadInt64(&t.stats.bytesReceived),
				atomic.LoadInt64(&t.stats.bytesSent),
				atomic.LoadInt64(&t.totalBytesReceived),
				atomic.LoadInt64(&t.stats.connections),
				activeConns,
				atomic.LoadInt64(&t.stats.reconnects),
				atomic.LoadInt64(&t.stats.acksSent),
				atomic.LoadInt64(&t.stats.acksReceived))
		case <-ctx.Done():
			return
		}
	}
}

// waitForConnection blocks until the WebSocket connection is established.
func (t *Tunnel) waitForConnection(ctx context.Context) error {
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

// setConnected updates the connection state and notifies waiting goroutines.
func (t *Tunnel) setConnected(connected bool) {
	t.connectMutex.Lock()
	defer t.connectMutex.Unlock()

	t.connected = connected
	if connected {
		atomic.StoreInt32(&t.closed, 0) // Reset closed flag
		t.connectCond.Broadcast()
	}
}

// Start begins the tunnel operation in either stdin or port listening mode.
func (t *Tunnel) Start(ctx context.Context) error {
	go t.runTokenRefreshService(ctx)

	if t.config.ListenOnStdin {
		return t.startStdinMode(ctx)
	}
	return t.startPortMode(ctx)
}

// startStdinMode runs the tunnel in stdin/stdout mode for SSH ProxyCommand usage.
func (t *Tunnel) startStdinMode(ctx context.Context) error {
	log.V(1).Info("Starting stdin tunnel mode")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			ws, err := t.connectWithRetry(ctx)
			if err != nil {
				return fmt.Errorf("failed to connect to IAP: %w", err)
			}

			t.setConnected(false)

			if err := t.establishConnection(ctx, ws); err != nil {
				ws.Close(websocket.StatusNormalClosure, "")
				if err == context.Canceled || err == context.DeadlineExceeded {
					return err
				}
				log.Warningf("Connection establishment failed, retrying: %v", err)
				select {
				case <-time.After(retryBackoff):
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}

			err = t.relayData(ctx, ws, os.Stdin, os.Stdout, "stdin")
			ws.Close(websocket.StatusNormalClosure, "")

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

// startPortMode runs the tunnel in TCP port listening mode.
func (t *Tunnel) startPortMode(ctx context.Context) error {
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

			// Optimize TCP settings for low latency
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			t.stats.incConnections()
			connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
			log.V(2).Infof("Accepted connection: %s", connID)

			go t.handleConnection(ctx, conn, connID)
		}
	}
}

// handleConnection manages a single TCP connection by establishing a WebSocket
// tunnel and relaying data bidirectionally.
func (t *Tunnel) handleConnection(ctx context.Context, conn net.Conn, connID string) {
	defer func() {
		conn.Close()
		t.activeConnections.Delete(connID)
		log.V(2).Infof("Connection %s closed", connID)
	}()

	t.activeConnections.Store(connID, time.Now())
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
			ws, err := t.connectWithRetry(connCtx)
			if err != nil {
				log.Errorf("Failed to connect to IAP for connection %s: %v", connID, err)
				return
			}

			t.setConnected(false)

			if err := t.establishConnection(connCtx, ws); err != nil {
				ws.Close(websocket.StatusNormalClosure, "")
				if err == context.Canceled || err == context.DeadlineExceeded {
					return
				}
				log.Warningf("Connection establishment failed for %s, retrying: %v", connID, err)
				select {
				case <-time.After(retryBackoff):
				case <-connCtx.Done():
					return
				}
				continue
			}

			err = t.relayData(connCtx, ws, conn, conn, connID)
			ws.Close(websocket.StatusNormalClosure, "")

			if err == context.Canceled || err == context.DeadlineExceeded {
				return
			}

			// Check if local connection is still alive
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 1)
			if _, err = conn.Read(buf); err != nil {
				return
			}

			log.Warningf("WebSocket connection lost for %s, retrying: %v", connID, err)
			t.setConnected(false)
			t.stats.incReconnects()

			select {
			case <-time.After(retryBackoff):
			case <-connCtx.Done():
				return
			}
		}
	}
}

// relayData implements the IAP relay protocol by running separate reader and writer
// goroutines that coordinate through the single-reader/single-writer semaphores.
//
// The protocol requires:
//   - Only one reader and one writer active at a time
//   - ACK frames sent when received data exceeds threshold (1MB)
//   - Proper frame construction for DATA and ACK messages
func (t *Tunnel) relayData(ctx context.Context, ws *websocket.Conn, reader io.Reader, writer io.Writer, connID string) error {
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	t.forceCloseCancel = relayCancel

	log.V(2).Infof("Starting relay for connection %s", connID)

	errChan := make(chan error, 2)

	// WebSocket reader goroutine - processes incoming frames
	go func() {
		defer func() {
			t.closeStream()
			errChan <- nil
		}()

		messageBuffer := make([]byte, maxMessageSize)

		for {
			select {
			case <-relayCtx.Done():
				return
			default:
				messageType, data, err := t.readWebSocket(relayCtx, ws)
				if err != nil {
					if !isExpectedCloseError(err) {
						log.V(3).Infof("WebSocket read error for %s: %v", connID, err)
						t.stats.incWSErrors()
					}
					return
				}

				if messageType == websocket.MessageBinary && len(data) >= 2 {
					tag := binary.BigEndian.Uint16(data[0:2])

					switch tag {
					case tagData:
						payload := t.extractDataPayload(data, messageBuffer)
						if payload != nil {
							dataLen := int64(len(payload))
							t.stats.incBytesReceived(dataLen)
							atomic.AddInt64(&t.totalBytesReceived, dataLen)
							t.stats.updateActivity()

							// Update ACK state (single reader - no race condition)
							t.bytesReceived += uint64(dataLen)

							log.V(3).Infof("Received %d bytes from WebSocket for %s", len(payload), connID)

							// Write to local connection
							if _, err := writer.Write(payload); err != nil {
								log.Errorf("Local write error for %s: %v", connID, err)
								t.stats.incLocalErrors()
								return
							}

							// Send ACK if threshold exceeded to prevent server stalls
							if t.bytesReceived-t.lastAckSent >= ackThreshold {
								if err := t.sendACK(relayCtx, ws, t.bytesReceived); err != nil {
									return
								}
								t.lastAckSent = t.bytesReceived
								t.stats.incACKSent()
								log.V(3).Infof("Sent ACK for %d bytes during read", t.bytesReceived)
							}
						}
					case tagACK:
						// Process acknowledgment from server
						if len(data) >= 10 {
							ack := binary.BigEndian.Uint64(data[2:10])
							t.lastAckReceived = ack
							t.stats.incACKReceived()
							log.V(3).Infof("Received ACK: %d", ack)
						}
					}
				}
			}
		}
	}()

	// Local reader goroutine - sends data to WebSocket
	go func() {
		defer func() {
			t.closeStream()
			errChan <- nil
		}()

		buffer := getRelayBuffer()
		defer putRelayBuffer(buffer)

		for {
			select {
			case <-relayCtx.Done():
				return
			default:
				n, err := reader.Read(buffer)
				if err == io.EOF {
					log.V(2).Infof("Reader %s closed (EOF)", connID)
					return
				}
				if err != nil {
					if !isTimeoutError(err) {
						log.Errorf("Read error for %s: %v", connID, err)
						t.stats.incLocalErrors()
					}
					return
				}

				if n > 0 {
					// Send pending ACK first if needed
					if t.lastAckSent < t.bytesReceived {
						if err := t.sendACK(relayCtx, ws, t.bytesReceived); err != nil {
							return
						}
						t.lastAckSent = t.bytesReceived
						t.stats.incACKSent()
						log.V(3).Infof("Sent pending ACK for %d bytes", t.bytesReceived)
					}

					// Send data frame
					if err := t.sendData(relayCtx, ws, buffer[:n]); err != nil {
						return
					}

					t.stats.incBytesSent(int64(n))
					t.stats.updateActivity()
					log.V(3).Infof("Sent %d bytes to WebSocket for %s", n, connID)
				}
			}
		}
	}()

	// Wait for first goroutine to complete
	select {
	case err := <-errChan:
		// Wait briefly for other goroutine to finish
		select {
		case <-errChan:
		case <-time.After(50 * time.Millisecond):
		}
		return err
	case <-relayCtx.Done():
		return relayCtx.Err()
	}
}

// extractDataPayload extracts the data payload from a DATA frame.
// Returns nil if the frame is invalid or not a DATA frame.
func (t *Tunnel) extractDataPayload(data []byte, messageBuffer []byte) []byte {
	if len(data) < 6 { // Tag (2) + Length (4) minimum
		return nil
	}

	tag := binary.BigEndian.Uint16(data[0:2])
	if tag != tagData {
		return nil
	}

	dataLength := binary.BigEndian.Uint32(data[2:6])
	if dataLength == 0 || dataLength > maxFrameSize {
		return nil
	}

	if len(data) < int(6+dataLength) {
		return nil
	}

	return data[6 : 6+dataLength]
}

// sendData constructs and sends a DATA frame with the given payload.
func (t *Tunnel) sendData(ctx context.Context, ws *websocket.Conn, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("data payload cannot be empty")
	}
	if len(data) > maxFrameSize {
		return fmt.Errorf("data payload exceeds maximum frame size of %d bytes", maxFrameSize)
	}

	// Construct DATA frame: Tag(2) + Length(4) + Data(n)
	frame := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(frame[0:2], tagData)
	binary.BigEndian.PutUint32(frame[2:6], uint32(len(data)))
	copy(frame[6:], data)

	return t.writeWebSocket(ctx, ws, frame)
}

// sendACK constructs and sends an ACK frame with the given acknowledgment value.
func (t *Tunnel) sendACK(ctx context.Context, ws *websocket.Conn, ackBytes uint64) error {
	// Construct ACK frame: Tag(2) + Ack(8) = 10 bytes total
	frame := make([]byte, 10)
	binary.BigEndian.PutUint16(frame[0:2], tagACK)
	binary.BigEndian.PutUint64(frame[2:10], ackBytes)
	return t.writeWebSocket(ctx, ws, frame)
}

// readWebSocket performs a thread-safe WebSocket read operation using the
// single-reader semaphore to prevent protocol violations.
func (t *Tunnel) readWebSocket(ctx context.Context, ws *websocket.Conn) (websocket.MessageType, []byte, error) {
	select {
	case <-t.readerSemaphore:
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
	defer func() { t.readerSemaphore <- struct{}{} }()

	if err := t.isStreamClosed(); err != nil {
		return 0, nil, err
	}

	readerCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	return ws.Read(readerCtx)
}

// writeWebSocket performs a thread-safe WebSocket write operation using the
// single-writer semaphore to prevent protocol violations.
func (t *Tunnel) writeWebSocket(ctx context.Context, ws *websocket.Conn, data []byte) error {
	select {
	case <-t.writerSemaphore:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { t.writerSemaphore <- struct{}{} }()

	if err := t.isStreamClosed(); err != nil {
		return err
	}

	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	err := ws.Write(writeCtx, websocket.MessageBinary, data)
	if err != nil {
		atomic.StoreInt32(&t.closed, 1)
		t.stats.incWSErrors()
	}
	return err
}

// connectWithRetry attempts to establish a WebSocket connection with exponential backoff.
func (t *Tunnel) connectWithRetry(ctx context.Context) (*websocket.Conn, error) {
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

			if t.isTokenError(err) {
				log.Warningf("Token error detected, forcing refresh: %v", err)
				t.stats.incTokenErrors()

				if _, refreshErr := t.refreshToken(ctx, "error recovery"); refreshErr != nil {
					log.Errorf("Failed to refresh token: %v", refreshErr)
				}
			}

			t.stats.incWSErrors()
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

// isTokenError checks if an error is related to OAuth2 token issues.
func (t *Tunnel) isTokenError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "token")
}

// establishConnection waits for the initial CONNECT_SUCCESS_SID message
// that indicates the tunnel session has been established.
func (t *Tunnel) establishConnection(ctx context.Context, ws *websocket.Conn) error {
	establishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		select {
		case <-establishCtx.Done():
			return establishCtx.Err()
		default:
			readerCtx, readerCancel := context.WithTimeout(establishCtx, readTimeout)
			messageType, data, err := ws.Read(readerCtx)
			readerCancel()

			if err != nil {
				return fmt.Errorf("failed to read connection establishment message: %w", err)
			}

			if messageType != websocket.MessageBinary || len(data) < 2 {
				continue
			}

			tag := binary.BigEndian.Uint16(data[0:2])
			payload := data[2:]

			switch tag {
			case tagConnectSuccessSID:
				if len(payload) < 4 {
					return fmt.Errorf("invalid CONNECT_SUCCESS_SID message")
				}
				sidLen := binary.BigEndian.Uint32(payload[0:4])
				if len(payload) < int(4+sidLen) {
					return fmt.Errorf("truncated CONNECT_SUCCESS_SID message")
				}
				sidData := payload[4 : 4+sidLen]
				t.sessionID = string(sidData)
				t.setConnected(true)
				log.V(1).Infof("Connection established with session ID: %s", t.sessionID)
				return nil

			case tagACK:
				if len(payload) >= 8 {
					ackBytes := binary.BigEndian.Uint64(payload[0:8])
					log.V(3).Infof("Received initial ACK: %d bytes", ackBytes)
					t.lastAckReceived = ackBytes
					t.stats.incACKReceived()
				}

			default:
				log.V(2).Infof("Received unknown message during establishment: 0x%04x", tag)
			}
		}
	}
}

// connectWebSocket establishes a WebSocket connection to the IAP tunnel endpoint.
func (t *Tunnel) connectWebSocket(ctx context.Context) (*websocket.Conn, error) {
	token, err := t.getValidToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get valid token: %w", err)
	}

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

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: "tunnel.cloudproxy.app",
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	options := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Timeout:   connectionTimeout,
			Transport: transport,
		},
		HTTPHeader:   headers,
		Subprotocols: []string{subprotocolName},
	}

	log.V(1).Infof("Connecting to WebSocket: %s", wsURL)

	dialCtx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()

	ws, resp, err := websocket.Dial(dialCtx, wsURL, options)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("websocket dial failed (status %d): %s, error: %w", resp.StatusCode, string(body), err)
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	t.stats.incWSConnections()
	log.V(1).Info("WebSocket connected successfully")
	return ws, nil
}

// getValidToken returns a valid OAuth2 token, refreshing if necessary.
func (t *Tunnel) getValidToken(ctx context.Context) (*oauth2.Token, error) {
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
func (t *Tunnel) refreshToken(ctx context.Context, reason string) (*oauth2.Token, error) {
	t.tokenMutex.Lock()
	defer t.tokenMutex.Unlock()

	if reason == "proactive refresh" && time.Since(t.lastTokenTime) < proactiveTokenRefreshInterval {
		log.V(2).Info("Token was already refreshed by another goroutine")
		return t.currentToken, nil
	}

	log.V(1).Infof("Refreshing token: %s", reason)

	tokenCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	freshTokenSource, err := google.DefaultTokenSource(tokenCtx, iapScope)
	if err != nil {
		t.stats.incTokenErrors()
		return nil, fmt.Errorf("failed to create fresh token source: %w", err)
	}

	newToken, err := freshTokenSource.Token()
	if err != nil {
		t.stats.incTokenErrors()
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	if newToken.AccessToken == "" {
		t.stats.incTokenErrors()
		return nil, fmt.Errorf("received empty access token")
	}

	t.currentToken = newToken
	t.lastTokenTime = time.Now()

	t.tokenSource = oauth2.StaticTokenSource(newToken)
	t.client = oauth2.NewClient(tokenCtx, t.tokenSource)
	t.client.Timeout = connectionTimeout

	if reason == "proactive refresh" {
		t.stats.incProactiveRefresh()
	} else {
		t.stats.incTokenRefreshes()
	}

	log.V(1).Infof("Token refreshed successfully, expires: %v", newToken.Expiry)
	return newToken, nil
}

// runTokenRefreshService proactively refreshes OAuth2 tokens to prevent
// authentication interruptions during long-running tunnel sessions.
func (t *Tunnel) runTokenRefreshService(ctx context.Context) {
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

// DumpStats logs detailed tunnel statistics for debugging and monitoring.
func (t *Tunnel) DumpStats() {
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
	acksSent := atomic.LoadInt64(&t.stats.acksSent)
	acksReceived := atomic.LoadInt64(&t.stats.acksReceived)

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

	if uptime.Seconds() > 0 {
		buf.WriteString(fmt.Sprintf("  Avg throughput: %.2f MB/s in, %.2f MB/s out\n",
			float64(received)/uptime.Seconds()/(1024*1024),
			float64(sent)/uptime.Seconds()/(1024*1024)))
	}

	buf.WriteString(fmt.Sprintf("\nConnections:\n"))
	buf.WriteString(fmt.Sprintf("  Total local connections: %d\n", connections))
	buf.WriteString(fmt.Sprintf("  Active connections: %d\n", activeConns))
	buf.WriteString(fmt.Sprintf("  WebSocket connections: %d\n", wsConnections))
	buf.WriteString(fmt.Sprintf("  Reconnects: %d\n", reconnects))

	buf.WriteString(fmt.Sprintf("\nAuthentication:\n"))
	buf.WriteString(fmt.Sprintf("  Token refreshes: %d\n", tokenRefreshes))

	buf.WriteString(fmt.Sprintf("\nFlow Control:\n"))
	buf.WriteString(fmt.Sprintf("  ACKs sent: %d\n", acksSent))
	buf.WriteString(fmt.Sprintf("  ACKs received: %d\n", acksReceived))

	buf.WriteString(fmt.Sprintf("\nConnection Health:\n"))
	if !t.stats.lastActivity.IsZero() {
		buf.WriteString(fmt.Sprintf("  Last activity: %s (%v ago)\n",
			t.stats.lastActivity.Format("15:04:05"),
			time.Since(t.stats.lastActivity).Round(time.Second)))
	}
	buf.WriteString(fmt.Sprintf("  Stream closed: %t\n", atomic.LoadInt32(&t.closed) == 1))

	buf.WriteString(fmt.Sprintf("\nErrors:\n"))
	buf.WriteString(fmt.Sprintf("  WebSocket errors: %d\n", wsErrors))
	buf.WriteString(fmt.Sprintf("  Local connection errors: %d\n", localErrors))

	if wsConnections > 0 {
		errorRate := float64(wsErrors) / float64(wsConnections) * 100
		buf.WriteString(fmt.Sprintf("  WebSocket error rate: %.1f%%\n", errorRate))
	}

	buf.WriteString("=============================\n\n")

	log.Infof("SIGUSR1 Stats Dump:\n%s", buf.String())

	if t.config.LogFile != "" {
		if f, err := os.OpenFile(t.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			f.WriteString(fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), buf.String()))
			f.Close()
		}
	}
}

// Utility functions

// isExpectedCloseError checks if a WebSocket close error is expected and benign.
func isExpectedCloseError(err error) bool {
	var closeErr websocket.CloseError
	if !errors.As(err, &closeErr) {
		return false
	}

	expectedCodes := []websocket.StatusCode{
		websocket.StatusNormalClosure,
		websocket.StatusGoingAway,
		websocket.StatusAbnormalClosure,
		1005, // StatusNoStatusReceived
		4080, // IAP "error while receiving from client"
		4004, // IAP "reauthentication required"
	}

	for _, code := range expectedCodes {
		if closeErr.Code == code {
			return true
		}
	}
	return false
}

// isTimeoutError checks if an error is a network timeout.
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// Main application logic

func main() {
	defer log.Flush()
	runtime.GOMAXPROCS(runtime.NumCPU())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config, err := parseFlags()
	if err != nil {
		log.Exitf("Configuration error: %v", err)
	}

	tunnel, err := NewTunnel(ctx, config)
	if err != nil {
		log.Exitf("Failed to create tunnel: %v", err)
	}

	setupSignalHandlers(ctx, cancel, tunnel)

	if log.V(2) {
		go tunnel.reportStats(ctx)
	}

	if err := tunnel.Start(ctx); err != nil && err != context.Canceled {
		log.Exitf("Tunnel failed: %v", err)
	}
}

// parseFlags parses command line flags and returns tunnel configuration.
func parseFlags() (Config, error) {
	var config Config

	flag.StringVar(&config.ProjectID, "project", "", "Google Cloud project ID")
	flag.StringVar(&config.Zone, "zone", "", "Zone of the instance")
	flag.IntVar(&config.LocalPort, "local-port", 0, "Local port to listen on")
	flag.StringVar(&config.LocalHost, "local-host", "127.0.0.1", "Local host to bind to")
	flag.BoolVar(&config.ListenOnStdin, "listen-on-stdin", false, "Listen on stdin instead of creating local port")
	flag.StringVar(&config.LogFile, "log-file", "", "Log file path")

	// On macOS, glog does not default to /tmp when --log_dir is unset.
	// Set /tmp as the default log directory before flag.Parse() so it
	// behaves like Linux. User-specified --log_dir still takes precedence.
	if runtime.GOOS == "darwin" && flag.Lookup("log_dir").Value.String() == "" {
		const d = "/tmp"
		_ = os.MkdirAll(d, 0o755) // ensure directory exists
		_ = flag.Set("log_dir", d)
	}

	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		return config, fmt.Errorf("usage: iapproxy [flags] INSTANCE_NAME PORT")
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

// setupSignalHandlers configures graceful shutdown and stats dumping.
func setupSignalHandlers(ctx context.Context, cancel context.CancelFunc, tunnel *Tunnel) {
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
			tunnel.DumpStats()
		}
	}()
}
