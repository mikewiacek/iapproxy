# IAP Proxy

A high-performance Go implementation of Google Cloud Identity-Aware Proxy (IAP) TCP tunneling, providing fast and reliable connections to Google Compute Engine instances without external IPs.

## Why This Tool?

The standard `gcloud compute start-iap-tunnel` command can suffer from performance bottlenecks and connection instability. This Go implementation delivers:

- **Superior Performance**: Native type safe code is more efficient than interpreted languages

- **Stable Connections**: Implements Google's IAP WebSocket relay protocol v4 with proper flow control

- **Responsive Interactive Sessions**: Optimized ACK protocol prevents server-side stalls

- **Drop-in Replacement**: Fully compatible with existing SSH workflows and configurations

- **Better Reliability**: Automatic reconnection, proactive token refresh, and robust error handling

## Protocol Implementation

This tool implements Google's IAP WebSocket relay protocol v4 with the following optimizations:

- **Single Reader/Writer Pattern**: Prevents protocol violations through semaphore coordination

- **Adaptive ACK Strategy**: Sends acknowledgments during writes (like Google's C# implementation) plus 1MB safety threshold

- **16KB Frame Size**: Matches Google's specification for optimal data transfer

- **Proactive Flow Control**: Prevents server buffer overflows that cause connection stalls

## Installation

### Prerequisites

- Go 1.19 or later
- Google Cloud SDK (`gcloud`) installed and authenticated
- Proper IAP permissions for your GCP project

### Build from Source

```bash
git clone https://github.com/mikewiacek/iapproxy.git
cd iapproxy
go mod tidy
go build -o iapproxy
```

### Install Binary

```bash

# Install to system PATH
sudo cp iapproxy /usr/local/bin/

# Or use go install (if you have the repo)
go install
```

## Usage

### Basic Commands

```bash

# Start a tunnel (auto-assigns local port)
iapproxy --project=my-project --zone=us-central1-a my-instance 22

# Use specific local port
iapproxy --project=my-project --zone=us-central1-a --local-port=2222 my-instance 22

# SSH ProxyCommand mode (for SSH config)
iapproxy --listen-on-stdin --project=my-project --zone=us-central1-a my-instance 22

```

### SSH Integration

#### Method 1: SSH Config (Recommended)

Add to your `~/.ssh/config`:

```ssh

Host my-vm
  HostName placeholder # This value is ignored
  User your-username
  Port 22
  IdentityFile ~/.ssh/google_compute_engine
  CheckHostIP no
  IdentitiesOnly yes
  UserKnownHostsFile ~/.ssh/google_compute_known_hosts
  ProxyCommand iapproxy --listen-on-stdin --project=my-project --zone=us-central1-a my-instance %p
  ProxyUseFdpass no
  ServerAliveInterval 60
  ServerAliveCountMax 3
```

Then connect simply with:

```bash
ssh my-vm
```

#### Method 2: One-time SSH Command

```bash
ssh -o ProxyCommand="iapproxy --listen-on-stdin --project=my-project --zone=us-central1-a my-instance 22" user@placeholder
```

#### Method 3: Port Forwarding

```bash
# Terminal 1: Start the tunnel
iapproxy --project=my-project --zone=us-central1-a --local-port=2222 my-instance 22

# Terminal 2: Connect via tunnel
ssh -p 2222 user@localhost
```

## Command Options

| Flag | Description | Default |
|------|-------------|---------|
| `--project` | Google Cloud project ID (required) | |
| `--zone` | Zone of the instance (required) | |
| `--local-host` | Local host to bind to | `127.0.0.1` |
| `--local-port` | Local port to listen on (0 = auto-assign) | `0` |
| `--listen-on-stdin` | Use stdin/stdout for SSH ProxyCommand | `false` |
| `--log-file` | Log file path | |
| `-v` | Verbose logging level (1-3) | |

## Performance Features

### Adaptive Flow Control

- **Bidirectional ACK Strategy**: Sends acknowledgments before each write (Google's C# behavior)

- **1MB Safety Threshold**: Prevents stalls during receive-only periods

- **Optimized Buffer Management**: 16KB relay buffers with object pooling

### Connection Management

- **Automatic Reconnection**: Seamless recovery from network interruptions

- **Proactive Token Refresh**: Prevents authentication interruptions

- **Single Reader/Writer**: Enforces protocol compliance to prevent server errors

### Monitoring

- **Real-time Statistics**: Monitor throughput, connections, and errors

- **Debug Logging**: Detailed protocol tracing with `-v 3`

- **Stats Dump**: Send `SIGUSR1` for detailed performance report

## Requirements

### Google Cloud Setup

1. **Enable IAP API**:

```bash
gcloud services enable iap.googleapis.com
```

2. **Configure Firewall** (allow IAP traffic):

```bash
gcloud compute firewall-rules create allow-ssh-ingress-from-iap \
--direction=INGRESS \
--action=allow \
--rules=tcp:22 \
--source-ranges=35.235.240.0/20
```

3. **Grant IAP Permissions**:

```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
--member=user:your-email@domain.com \
--role=roles/iap.tunnelResourceAccessor
```

### Authentication

The tool uses Google's Application Default Credentials in this order:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable

2. User credentials from `gcloud auth application-default login`

3. User credentials from `gcloud auth login`

4. Service account attached to compute resource

5. Google Cloud SDK default service account

## Advanced Usage

### Multiple Tunnels

```bash
# Tunnel to different ports simultaneously
iapproxy --project=my-project --zone=us-central1-a --local-port=2222 my-instance 22 &
iapproxy --project=my-project --zone=us-central1-a --local-port=3389 my-instance 3389 &
```

### Debugging Connection Issues

```bash
# Enable detailed protocol logging
iapproxy -v 3 --project=my-project --zone=us-central1-a my-instance 22

# Monitor performance in real-time
kill -USR1 $(pidof iapproxy) # Dumps stats to log
```

### Performance Tuning

```bash
# The tool automatically optimizes for your network conditions
# Monitor the logs to see ACK frequency and adjust if needed
tail -f /tmp/iapproxy.<name of temporary log file>
```

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| "Failed to get token" | Run `gcloud auth application-default login` |
| "Connection denied" | Check IAP permissions and firewall rules |
| "Instance not found" | Verify project ID, zone, and instance name |
| "Slow performance" | Check network connectivity and enable debug logging |

### Debug Commands

```bash
# Test authentication
gcloud auth application-default print-access-token

# Verify instance accessibility
gcloud compute instances list --project=PROJECT --zones=ZONE

# Test with verbose logging
iapproxy -v 3 --project=PROJECT --zone=ZONE INSTANCE 22
```

### Performance Optimization

If you experience slow performance:

1. **Check your network**: High latency networks may need more frequent ACKs

2. **Monitor logs**: Look for reconnections or token refresh issues

3. **Verify instance health**: Ensure the target instance isn't overloaded

4. **Test different regions**: Network path to Google's IAP servers matters

## Development

### Building

```bash
go mod tidy
go build -o iapproxy
```

### Contributing

Contributions welcome! This project implements Google's IAP WebSocket relay protocol v4 based on:

- [Google Cloud SDK Python Implementation](https://github.com/google-cloud-sdk-unofficial/google-cloud-sdk)
- [IAP Desktop C# Implementation](https://github.com/GoogleCloudPlatform/iap-desktop)

## License
Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgments
- Built by analyzing Google Cloud SDK's IAP tunnel implementation
- Protocol reverse-engineered from Google's C# and Python references
- Uses [nhooyr.io/websocket](https://github.com/nhooyr/websocket) for WebSocket support

---

**⚠️ Disclaimer**: This is an unofficial tool not affiliated with Google. While it implements Google's published protocol specifications, use at your own discretion for production workloads. Google can potentially change this protocol in the future, and as it is currently on v4, it is likely that will happen at some point.
