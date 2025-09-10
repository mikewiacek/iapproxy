# IAP Proxy

A high-performance Go implementation of Google Cloud Identity-Aware Proxy (IAP) tunneling for SSH connections to Google Compute Engine instances.

## Why This Tool?

The default Python-based `gcloud compute start-iap-tunnel` command can be slow and choppy, especially for interactive sessions. This Go implementation provides:

- **Better Performance**: Native Go implementation eliminates Python interpreter overhead

- **Smoother SSH Sessions**: Optimized buffering and WebSocket handling for responsive terminal sessions

- **Drop-in Replacement**: Compatible with existing gcloud workflows and SSH configurations

## Installation

### Prerequisites

- Go 1.19 or later

- Google Cloud SDK (`gcloud`) installed and authenticated

- Proper IAP permissions for your GCP project

### Build from Source

```bash

git clone https://github.com/your-username/iap-proxy.git

cd iap-proxy

go mod tidy

go build -o iap-proxy

```

### Install Binary

Copy the binary to a location in your PATH:

```bash

sudo cp iap-proxy /usr/local/bin/

```

## Usage

### Command Line

```bash

# Direct usage (similar to gcloud compute start-iap-tunnel)
iap-proxy --project=my-project --zone=us-central1-a my-instance 22

# For SSH ProxyCommand (stdin mode)
iap-proxy --listen-on-stdin --project=my-project --zone=us-central1-a my-instance 22

```

### SSH Configuration

Add an entry to your `~/.ssh/config` file:

```
Host my-gce-instance
  HostName compute.1234567890  # This can be any value, it's ignored
  User your-username
  IdentityFile ~/.ssh/google_compute_engine
  CheckHostIP no
  IdentitiesOnly yes
  UserKnownHostsFile ~/.ssh/google_compute_known_hosts
  ProxyCommand iap-proxy --listen-on-stdin --project=my-project --zone=us-central1-a my-instance %p
  ProxyUseFdpass no
```

Then connect with:

```bash

ssh my-gce-instance

```

### Command Options

```

--project string Google Cloud project ID (required)

--zone string Zone of the instance (required)

--local-host string Local host to bind to (default "127.0.0.1")

--local-port int Local port to listen on (0 for auto-assign)

--listen-on-stdin Listen on stdin for SSH ProxyCommand mode

--verbosity string Verbosity level: critical, warning, debug (default "warning")

```

## How It Works

This tool implements the same WebSocket-based protocol that `gcloud compute start-iap-tunnel` uses:

1. **Authentication**: Uses your existing gcloud credentials via Google's default credential chain

2. **WebSocket Connection**: Establishes a secure WebSocket connection to Google's IAP tunnel endpoint

3. **Protocol Implementation**: Handles the binary subprotocol for data framing and connection management

4. **Data Relay**: Efficiently relays data between your local connection and the remote instance

## Performance Optimizations

- **Larger Buffer Sizes**: 32KB read/write buffers (vs 4KB default)

- **Message Batching**: Intelligent batching of outgoing messages

- **Optimized Flushing**: Periodic buffer flushing to balance throughput and latency

- **No Compression**: Disabled WebSocket compression for better performance

- **Connection Pooling**: Efficient goroutine management

## Requirements

### IAP Setup

Ensure your GCP project has IAP configured properly:

1. Enable the IAP API

2. Configure IAP TCP forwarding

3. Set up appropriate firewall rules for IAP (source range: `35.235.240.0/20`)

4. Grant your user the `roles/iap.tunnelResourceAccessor` role

### Authentication

The tool uses Google's Application Default Credentials, which means it works if any of these are configured:

- `gcloud auth login` (user credentials)

- `gcloud auth application-default login`

- Service account key file via `GOOGLE_APPLICATION_CREDENTIALS`

- Compute Engine service account (when running on GCE)

## Troubleshooting

### Connection Issues

```bash

# Test with debug logging

iap-proxy --verbosity=debug --project=my-project --zone=us-central1-a my-instance 22

# Verify gcloud authentication

gcloud auth list

gcloud auth application-default print-access-token

```

### Common Problems

- **"Invalid Credentials"**: Run `gcloud auth login` to refresh credentials

- **"Failed to connect to backend"**: Check IAP firewall rules and instance status

- **"Permission denied"**: Ensure you have `roles/iap.tunnelResourceAccessor` role

## Contributing

This project was developed by studying the Google Cloud SDK source code to understand the IAP tunnel protocol. Contributions are welcome!

## License

Apache License - see LICENSE file for details.

## Acknowledgments

- Built with help from Claude AI for protocol analysis

- Based on the Google Cloud SDK IAP tunnel implementation

- Uses the excellent [gorilla/websocket](https://github.com/gorilla/websocket) library

---

**Note**: This is an unofficial tool and is not affiliated with or endorsed by Google. For critical use, consider the official `gcloud` tooling. This is experimental code.
