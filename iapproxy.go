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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// tagData carries application data payload
	tagData = 0x0004
	// tagACK acknowledges received bytes for flow control
	tagACK = 0x0007
)

// Protocol limits and timing constants based on IAP specification
const (
	// maxFrameSize is the maximum payload size per DATA frame (16KB)
	maxFrameSize = 16 * 1024
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

	// WebSocket keepalive settings
	websocketPingInterval = 30 * time.Second // WebSocket ping interval to prevent idle connection drops
	websocketPingTimeout  = 10 * time.Second // Timeout for ping response

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

// Stats tracks tunnel performance and reliability metrics using atomics for
// counters and a mutex for the activity timestamp.
type Stats struct {
	bytesReceived    int64 // Total bytes received from WebSocket
	bytesSent        int64 // Total bytes sent to WebSocket
	connections      int64 // Number of local connections accepted
	reconnects       int64 // Number of WebSocket reconnections
	tokenRefreshes   int64 // Number of token refresh operations
	wsConnections    int64 // Number of successful WebSocket connections
	wsErrors         int64 // Number of WebSocket errors
	localErrors      int64 // Number of local I/O errors
	tokenErrors      int64 // Number of token-related errors
	proactiveRefresh int64 // Number of proactive token refreshes
	acksReceived     int64 // Number of ACK frames received
	acksSent         int64 // Number of ACK frames sent

	startTime     time.Time // Tunnel start time
	lastActivity  time.Time // Last data transfer activity
	activityMutex sync.RWMutex
}

// Thread-safe stat increment methods
func (s *Stats) incACKReceived()          { atomic.AddInt64(&s.acksReceived, 1) }
func (s *Stats) incACKSent()              { atomic.AddInt64(&s.acksSent, 1) }
func (s *Stats) incBytesReceived(n int64) { atomic.AddInt64(&s.bytesReceived, n) }
func (s *Stats) incBytesSent(n int64)     { atomic.AddInt64(&s.bytesSent, n) }
func (s *Stats) incConnections()          { atomic.AddInt64(&s.connections, 1) }
func (s *Stats) incReconnects()           { atomic.AddInt64(&s.reconnects, 1) }
func (s *Stats) incTokenRefreshes()       { atomic.AddInt64(&s.tokenRefreshes, 1) }
func (s *Stats) incWSConnections()        { atomic.AddInt64(&s.wsConnections, 1) }
func (s *Stats) incWSErrors()             { atomic.AddInt64(&s.wsErrors, 1) }
func (s *Stats) incLocalErrors()          { atomic.AddInt64(&s.localErrors, 1) }
func (s *Stats) incTokenErrors()          { atomic.AddInt64(&s.tokenErrors, 1) }
func (s *Stats) incProactiveRefresh()     { atomic.AddInt64(&s.proactiveRefresh, 1) }
func (s *Stats) updateActivity() {
	s.activityMutex.Lock()
	s.lastActivity = time.Now()
	s.activityMutex.Unlock()
}

type relaySession struct {
	ackMutex        sync.Mutex
	bytesReceived   uint64
	lastAckSent     uint64
	writerSemaphore chan struct{}
}

func newRelaySession() *relaySession {
	session := &relaySession{writerSemaphore: make(chan struct{}, 1)}
	session.writerSemaphore <- struct{}{}
	return session
}

type localRelayError struct {
	err error
}

func (e *localRelayError) Error() string { return e.err.Error() }
func (e *localRelayError) Unwrap() error { return e.err }

// Tunnel manages an IAP WebSocket tunnel connection with automatic reconnection,
// token refresh, and flow control. It implements the single-reader/single-writer
// pattern required by the IAP relay protocol.
//
// Each WebSocket relay maintains its own protocol and flow-control state.
type Tunnel struct {
	config Config
	client *http.Client
	stats  *Stats

	activeConnections sync.Map

	// OAuth2 token management
	currentToken  *oauth2.Token
	tokenMutex    sync.RWMutex
	lastTokenTime time.Time
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

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: "tunnel.cloudproxy.app",
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Timeout: connectionTimeout, Transport: transport}

	tunnel := &Tunnel{
		config:        config,
		client:        client,
		currentToken:  initialToken,
		lastTokenTime: time.Now(),
		stats: &Stats{
			startTime:    time.Now(),
			lastActivity: time.Now(),
		},
	}

	log.Infof("Loaded credentials for IAP tunnel to %s:%d in %s/%s",
		config.Instance, config.Port, config.ProjectID, config.Zone)
	return tunnel, nil
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

			log.V(2).Infof("Stats: received=%d bytes, sent=%d bytes, connections=%d, active=%d, reconnects=%d, ws_errors=%d, token_errors=%d, acks_sent=%d, acks_received=%d",
				atomic.LoadInt64(&t.stats.bytesReceived),
				atomic.LoadInt64(&t.stats.bytesSent),
				atomic.LoadInt64(&t.stats.connections),
				activeConns,
				atomic.LoadInt64(&t.stats.reconnects),
				atomic.LoadInt64(&t.stats.wsErrors),
				atomic.LoadInt64(&t.stats.tokenErrors),
				atomic.LoadInt64(&t.stats.acksSent),
				atomic.LoadInt64(&t.stats.acksReceived))
		case <-ctx.Done():
			return
		}
	}
}

// Start begins the tunnel operation in either stdin or port listening mode.
func (t *Tunnel) Start(ctx context.Context) error {
	if t.config.ListenOnStdin {
		log.Infof("Starting IAP tunnel in stdin/stdout mode")
	} else {
		log.Infof("Starting IAP port-forwarding mode to %s:%d", t.config.Instance, t.config.Port)
	}
	go t.runTokenRefreshService(ctx)

	if t.config.ListenOnStdin {
		return t.startStdinMode(ctx)
	}
	return t.startPortMode(ctx)
}

// startStdinMode runs the tunnel in stdin/stdout mode for SSH ProxyCommand usage.
func (t *Tunnel) startStdinMode(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			ws, err := t.connectWithRetry(ctx)
			if err != nil {
				return fmt.Errorf("failed to connect to IAP: %w", err)
			}

			session, err := t.establishConnection(ctx, ws)
			if err != nil {
				ws.Close(websocket.StatusNormalClosure, "")
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Warningf("IAP tunnel setup failed; retrying in %v: %v", retryBackoff, err)
				select {
				case <-time.After(retryBackoff):
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}

			err = t.relayData(ctx, ws, session, os.Stdin, os.Stdout, "stdin")
			ws.Close(websocket.StatusNormalClosure, "")

			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				log.Infof("stdin closed; ending IAP tunnel")
				return nil
			}
			if err == nil {
				return nil
			}
			log.Errorf("IAP tunnel relay failed in stdin mode: %v", err)
			return fmt.Errorf("stdin relay failed: %w", err)
		}
	}
}

// startPortMode runs the tunnel in TCP port listening mode.
func (t *Tunnel) startPortMode(ctx context.Context) error {
	localAddr := net.JoinHostPort(t.config.LocalHost, strconv.Itoa(t.config.LocalPort))
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", localAddr, err)
	}
	defer listener.Close()
	stopListener := context.AfterFunc(ctx, func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorf("Failed to close listener during shutdown: %v", err)
		}
	})
	defer stopListener()

	actualPort := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Listening on port [%d].\n", actualPort)
	log.Infof("Listening on %s; forwarding to %s:%d",
		listener.Addr(), t.config.Instance, t.config.Port)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return ctx.Err()
				}
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Temporary() {
					log.Warningf("Temporary local listener error; retrying in %v: %v", retryBackoff, err)
					select {
					case <-time.After(retryBackoff):
						continue
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return fmt.Errorf("failed to accept local connection: %w", err)
			}

			// Optimize TCP settings for low latency
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				if err := tcpConn.SetNoDelay(true); err != nil {
					log.Warningf("Failed to enable TCP_NODELAY for %s: %v", conn.RemoteAddr(), err)
				}
				if err := tcpConn.SetKeepAlive(true); err != nil {
					log.Warningf("Failed to enable TCP keepalive for %s: %v", conn.RemoteAddr(), err)
				}
				if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
					log.Warningf("Failed to set TCP keepalive period for %s: %v", conn.RemoteAddr(), err)
				}
			}

			t.stats.incConnections()
			connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
			log.Infof("Accepted local connection %s", connID)

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
		log.Infof("Local connection %s closed", connID)
	}()

	t.activeConnections.Store(connID, struct{}{})
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
			ws, err := t.connectWithRetry(connCtx)
			if err != nil {
				log.Errorf("Failed to establish IAP tunnel for local connection %s: %v", connID, err)
				return
			}

			session, err := t.establishConnection(connCtx, ws)
			if err != nil {
				ws.Close(websocket.StatusNormalClosure, "")
				if connCtx.Err() != nil {
					return
				}
				log.Warningf("IAP setup failed for local connection %s; retrying in %v: %v", connID, retryBackoff, err)
				select {
				case <-time.After(retryBackoff):
				case <-connCtx.Done():
					return
				}
				continue
			}

			err = t.relayData(connCtx, ws, session, conn, conn, connID)
			ws.Close(websocket.StatusNormalClosure, "")

			if err == nil {
				return
			}
			if connCtx.Err() != nil {
				return
			}
			var localErr *localRelayError
			if errors.As(err, &localErr) {
				return
			}

			log.Warningf("IAP tunnel lost for local connection %s; reconnecting in %v: %v", connID, retryBackoff, err)
			t.stats.incReconnects()

			select {
			case <-time.After(retryBackoff):
			case <-connCtx.Done():
				return
			}
		}
	}
}

// relayData implements the IAP relay protocol with independent reader and writer
// goroutines for a single WebSocket session.
//
// The protocol requires:
//   - Only one reader and one writer active at a time
//   - ACK frames sent when received data exceeds threshold (1MB)
//   - Proper frame construction for DATA and ACK messages
func (t *Tunnel) relayData(ctx context.Context, ws *websocket.Conn, session *relaySession, reader io.Reader, writer io.Writer, connID string) error {
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	log.V(2).Infof("Starting relay for connection %s", connID)

	errChan := make(chan error, 3) // Buffered for 3 goroutines: reader, writer, and keepalive

	// WebSocket keepalive goroutine - sends periodic pings to prevent idle connection drops
	go func() {
		ticker := time.NewTicker(websocketPingInterval)
		defer ticker.Stop()
		var keepaliveErr error
		defer func() { errChan <- keepaliveErr }()

		for {
			select {
			case <-relayCtx.Done():
				return
			case <-ticker.C:
				pingCtx, cancel := context.WithTimeout(relayCtx, websocketPingTimeout)
				err := ws.Ping(pingCtx)
				cancel()

				if err != nil {
					if relayCtx.Err() == nil && !isExpectedCloseError(err) {
						log.Warningf("WebSocket keepalive failed for %s: %v", connID, err)
						t.stats.incWSErrors()
					}
					keepaliveErr = err
					return
				}
				log.V(3).Infof("Sent WebSocket ping for connection %s", connID)
			}
		}
	}()

	// WebSocket reader goroutine - processes incoming frames
	go func() {
		var readerErr error
		defer func() { errChan <- readerErr }()

		for {
			select {
			case <-relayCtx.Done():
				return
			default:
				messageType, data, err := t.readWebSocket(relayCtx, ws)
				if err != nil {
					readerErr = err
					if relayCtx.Err() == nil && !isExpectedCloseError(err) {
						log.Warningf("WebSocket read failed for %s: %v", connID, err)
						t.stats.incWSErrors()
					}
					return
				}

				if messageType == websocket.MessageBinary && len(data) >= 2 {
					tag := binary.BigEndian.Uint16(data[0:2])

					switch tag {
					case tagData:
						payload, err := t.extractDataPayload(data)
						if err != nil {
							readerErr = fmt.Errorf("invalid IAP DATA frame: %w", err)
							log.Errorf("Invalid IAP DATA frame for %s: %v", connID, err)
							return
						}
						if len(payload) > 0 {
							dataLen := int64(len(payload))
							t.stats.incBytesReceived(dataLen)
							t.stats.updateActivity()

							session.ackMutex.Lock()
							session.bytesReceived += uint64(dataLen)
							ackDue := session.bytesReceived-session.lastAckSent >= ackThreshold
							session.ackMutex.Unlock()

							log.V(3).Infof("Received %d bytes from WebSocket for %s", len(payload), connID)

							// Write to local connection
							if err := writeFull(writer, payload); err != nil {
								log.Errorf("Local write error for %s: %v", connID, err)
								t.stats.incLocalErrors()
								readerErr = &localRelayError{err: err}
								return
							}

							// Send ACK if threshold exceeded to prevent server stalls
							if ackDue {
								if err := t.sendPendingACK(relayCtx, ws, session, true); err != nil {
									readerErr = err
									return
								}
							}
						}
					case tagACK:
						if len(data) < 10 {
							readerErr = fmt.Errorf("invalid IAP ACK frame: got %d bytes, need at least 10", len(data))
							log.Errorf("%v for %s", readerErr, connID)
							return
						}
						ack := binary.BigEndian.Uint64(data[2:10])
						t.stats.incACKReceived()
						log.V(3).Infof("Received ACK: %d", ack)
					default:
						log.V(2).Infof("Ignoring unknown IAP frame tag 0x%04x for %s", tag, connID)
					}
				} else if messageType == websocket.MessageBinary {
					readerErr = fmt.Errorf("invalid IAP frame: binary message is only %d bytes", len(data))
					log.Errorf("%v for %s", readerErr, connID)
					return
				} else if messageType != websocket.MessageBinary {
					log.V(2).Infof("Ignoring non-binary WebSocket message type %d for %s", messageType, connID)
				}
			}
		}
	}()

	// Local reader goroutine - sends data to WebSocket
	go func() {
		var writerErr error
		defer func() { errChan <- writerErr }()

		buffer := getRelayBuffer()
		defer putRelayBuffer(buffer)

		for {
			select {
			case <-relayCtx.Done():
				return
			default:
				n, err := reader.Read(buffer)
				if n > 0 {
					// Send pending ACK first if needed
					if err := t.sendPendingACK(relayCtx, ws, session, false); err != nil {
						writerErr = err
						return
					}

					// Send data frame
					if err := t.sendData(relayCtx, ws, session, buffer[:n]); err != nil {
						writerErr = err
						return
					}

					t.stats.incBytesSent(int64(n))
					t.stats.updateActivity()
					log.V(3).Infof("Sent %d bytes to WebSocket for %s", n, connID)
				}
				if err != nil {
					if err == io.EOF {
						log.V(2).Infof("Reader %s closed (EOF)", connID)
					} else if !isTimeoutError(err) {
						log.Errorf("Read error for %s: %v", connID, err)
						t.stats.incLocalErrors()
					}
					writerErr = &localRelayError{err: err}
					return
				}
			}
		}
	}()

	// Stop the relay as soon as either direction ends. A deadline interrupts a
	// blocked TCP read so it cannot survive into a subsequent relay session.
	firstErr := <-errChan
	relayCancel()
	tcpReader, isTCPReader := reader.(net.Conn)
	if isTCPReader {
		if err := tcpReader.SetReadDeadline(time.Now()); err != nil {
			log.V(2).Infof("Failed to interrupt local read for %s: %v", connID, err)
		}
		if err := tcpReader.SetWriteDeadline(time.Now()); err != nil {
			log.V(2).Infof("Failed to interrupt local write for %s: %v", connID, err)
		}
	}
	if isTCPReader {
		for i := 0; i < 2; i++ {
			<-errChan
		}
	} else {
		for i := 0; i < 2; i++ {
			select {
			case <-errChan:
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if isTCPReader {
		if err := tcpReader.SetReadDeadline(time.Time{}); err != nil {
			log.V(2).Infof("Failed to clear local read deadline for %s: %v", connID, err)
		}
		if err := tcpReader.SetWriteDeadline(time.Time{}); err != nil {
			log.V(2).Infof("Failed to clear local write deadline for %s: %v", connID, err)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return firstErr
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return fmt.Errorf("writer returned invalid byte count %d for %d bytes", n, len(data))
		}
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (t *Tunnel) sendPendingACK(ctx context.Context, ws *websocket.Conn, session *relaySession, requireThreshold bool) error {
	session.ackMutex.Lock()
	defer session.ackMutex.Unlock()

	if session.bytesReceived <= session.lastAckSent {
		return nil
	}
	if requireThreshold && session.bytesReceived-session.lastAckSent < ackThreshold {
		return nil
	}

	ackBytes := session.bytesReceived
	if err := t.sendACK(ctx, ws, session, ackBytes); err != nil {
		return err
	}
	session.lastAckSent = ackBytes
	t.stats.incACKSent()
	log.V(3).Infof("Sent ACK for %d bytes", ackBytes)
	return nil
}

// extractDataPayload extracts the data payload from a DATA frame.
func (t *Tunnel) extractDataPayload(data []byte) ([]byte, error) {
	if len(data) < 6 { // Tag (2) + Length (4) minimum
		return nil, fmt.Errorf("frame header is truncated")
	}

	tag := binary.BigEndian.Uint16(data[0:2])
	if tag != tagData {
		return nil, fmt.Errorf("unexpected frame tag 0x%04x", tag)
	}

	dataLength := binary.BigEndian.Uint32(data[2:6])
	if dataLength == 0 || dataLength > maxFrameSize {
		return nil, fmt.Errorf("invalid payload length %d", dataLength)
	}

	if len(data) != int(6+dataLength) {
		return nil, fmt.Errorf("frame length %d does not match payload length %d", len(data), dataLength)
	}

	return data[6:], nil
}

// sendData constructs and sends a DATA frame with the given payload.
func (t *Tunnel) sendData(ctx context.Context, ws *websocket.Conn, session *relaySession, data []byte) error {
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

	return t.writeWebSocket(ctx, ws, session, frame)
}

// sendACK constructs and sends an ACK frame with the given acknowledgment value.
func (t *Tunnel) sendACK(ctx context.Context, ws *websocket.Conn, session *relaySession, ackBytes uint64) error {
	// Construct ACK frame: Tag(2) + Ack(8) = 10 bytes total
	frame := make([]byte, 10)
	binary.BigEndian.PutUint16(frame[0:2], tagACK)
	binary.BigEndian.PutUint64(frame[2:10], ackBytes)
	return t.writeWebSocket(ctx, ws, session, frame)
}

// readWebSocket reads from the single active reader for this WebSocket session.
func (t *Tunnel) readWebSocket(ctx context.Context, ws *websocket.Conn) (websocket.MessageType, []byte, error) {
	// Don't use a read timeout here - the reader must be able to continuously
	// read to process control frames (like PONG responses to our PING keepalives).
	// The coder/websocket library requires an active Reader to process pongs.
	return ws.Read(ctx)
}

// writeWebSocket serializes writes within a WebSocket session.
func (t *Tunnel) writeWebSocket(ctx context.Context, ws *websocket.Conn, session *relaySession, data []byte) error {
	select {
	case <-session.writerSemaphore:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { session.writerSemaphore <- struct{}{} }()

	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	err := ws.Write(writeCtx, websocket.MessageBinary, data)
	if err != nil {
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
			log.Infof("Connecting to IAP for %s:%d in %s/%s (attempt %d/%d)",
				t.config.Instance, t.config.Port, t.config.ProjectID, t.config.Zone, attempt, maxRetries)
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
			log.Warningf("IAP connection attempt %d/%d failed: %v", attempt, maxRetries, err)

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
func (t *Tunnel) establishConnection(ctx context.Context, ws *websocket.Conn) (*relaySession, error) {
	session := newRelaySession()
	establishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		select {
		case <-establishCtx.Done():
			return nil, establishCtx.Err()
		default:
			readerCtx, readerCancel := context.WithTimeout(establishCtx, readTimeout)
			messageType, data, err := ws.Read(readerCtx)
			readerCancel()

			if err != nil {
				return nil, fmt.Errorf("failed to read connection establishment message: %w", err)
			}

			if messageType != websocket.MessageBinary || len(data) < 2 {
				continue
			}

			tag := binary.BigEndian.Uint16(data[0:2])
			payload := data[2:]

			switch tag {
			case tagConnectSuccessSID:
				if len(payload) < 4 {
					return nil, fmt.Errorf("invalid CONNECT_SUCCESS_SID message")
				}
				sidLen := binary.BigEndian.Uint32(payload[0:4])
				sidEnd := uint64(4) + uint64(sidLen)
				if sidEnd > uint64(len(payload)) {
					return nil, fmt.Errorf("truncated CONNECT_SUCCESS_SID message")
				}
				log.Infof("IAP tunnel established for instance %s, port %d", t.config.Instance, t.config.Port)
				return session, nil

			case tagACK:
				if len(payload) >= 8 {
					ackBytes := binary.BigEndian.Uint64(payload[0:8])
					log.V(3).Infof("Received initial ACK: %d bytes", ackBytes)
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

	options := &websocket.DialOptions{
		HTTPClient:   t.client,
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

	log.Infof("Refreshing OAuth token: %s", reason)

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

	if reason == "proactive refresh" {
		t.stats.incProactiveRefresh()
	} else {
		t.stats.incTokenRefreshes()
	}

	log.Infof("OAuth token refreshed successfully; expires at %s", newToken.Expiry.Format(time.RFC3339))
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
	connections := atomic.LoadInt64(&t.stats.connections)
	reconnects := atomic.LoadInt64(&t.stats.reconnects)
	tokenRefreshes := atomic.LoadInt64(&t.stats.tokenRefreshes)
	proactiveRefreshes := atomic.LoadInt64(&t.stats.proactiveRefresh)
	tokenErrors := atomic.LoadInt64(&t.stats.tokenErrors)
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
	buf.WriteString(fmt.Sprintf("  Total received: %d (%.2f MB)\n", received, float64(received)/(1024*1024)))
	buf.WriteString(fmt.Sprintf("  Total sent: %d (%.2f MB)\n", sent, float64(sent)/(1024*1024)))

	if uptime.Seconds() > 0 {
		buf.WriteString(fmt.Sprintf("  Avg throughput: %.2f MB/s in, %.2f MB/s out\n",
			float64(received)/uptime.Seconds()/(1024*1024),
			float64(sent)/uptime.Seconds()/(1024*1024)))
	}

	buf.WriteString(fmt.Sprintf("\nConnections:\n"))
	buf.WriteString(fmt.Sprintf("  Total local connections: %d\n", connections))
	buf.WriteString(fmt.Sprintf("  Active connections: %d\n", activeConns))
	buf.WriteString(fmt.Sprintf("  Successful WebSocket connections: %d\n", wsConnections))
	buf.WriteString(fmt.Sprintf("  Reconnects: %d\n", reconnects))

	buf.WriteString(fmt.Sprintf("\nAuthentication:\n"))
	buf.WriteString(fmt.Sprintf("  Token refreshes: %d\n", tokenRefreshes))
	buf.WriteString(fmt.Sprintf("  Proactive token refreshes: %d\n", proactiveRefreshes))
	buf.WriteString(fmt.Sprintf("  Token errors: %d\n", tokenErrors))

	buf.WriteString(fmt.Sprintf("\nFlow Control:\n"))
	buf.WriteString(fmt.Sprintf("  ACKs sent: %d\n", acksSent))
	buf.WriteString(fmt.Sprintf("  ACKs received: %d\n", acksReceived))

	buf.WriteString(fmt.Sprintf("\nConnection Health:\n"))
	t.stats.activityMutex.RLock()
	lastActivity := t.stats.lastActivity
	t.stats.activityMutex.RUnlock()
	if !lastActivity.IsZero() {
		buf.WriteString(fmt.Sprintf("  Last activity: %s (%v ago)\n",
			lastActivity.Format("15:04:05"),
			time.Since(lastActivity).Round(time.Second)))
	}
	buf.WriteString(fmt.Sprintf("\nErrors:\n"))
	buf.WriteString(fmt.Sprintf("  WebSocket errors: %d\n", wsErrors))
	buf.WriteString(fmt.Sprintf("  Local connection errors: %d\n", localErrors))

	buf.WriteString("=============================\n\n")

	log.Infof("SIGUSR1 Stats Dump:\n%s", buf.String())

	if t.config.LogFile != "" {
		f, err := os.OpenFile(t.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Errorf("Failed to open stats log file %q: %v", t.config.LogFile, err)
			return
		}
		if _, err := f.WriteString(fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), buf.String())); err != nil {
			log.Errorf("Failed to write stats log file %q: %v", t.config.LogFile, err)
		}
		if err := f.Close(); err != nil {
			log.Errorf("Failed to close stats log file %q: %v", t.config.LogFile, err)
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
	var netErr net.Error
	if errors.As(err, &netErr) {
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
	log.Infof("Initializing IAP proxy for %s:%d in %s/%s",
		config.Instance, config.Port, config.ProjectID, config.Zone)

	tunnel, err := NewTunnel(ctx, config)
	if err != nil {
		log.Exitf("Failed to create tunnel: %v", err)
	}

	setupSignalHandlers(ctx, cancel, tunnel)

	if log.V(2) {
		go tunnel.reportStats(ctx)
	}

	if err := tunnel.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
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

	if f := flag.Lookup("alsologtostderr"); f == nil {
		return config, fmt.Errorf("glog flag alsologtostderr is unavailable")
	} else if f.Value.String() == "false" {
		if err := flag.Set("alsologtostderr", "true"); err != nil {
			return config, fmt.Errorf("failed to enable stderr logging: %w", err)
		}
	}

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
	if port < 1 || port > 65535 {
		return config, fmt.Errorf("port must be between 1 and 65535: %d", port)
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
