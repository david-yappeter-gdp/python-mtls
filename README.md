# Python mTLS Implementation

A production-ready mutual TLS (mTLS) implementation with HTTP client, server, and proxy components.

## Quick Start

```bash
# 1. Generate certificates
make certs

# 2. Start mTLS server (terminal 1)
make server

# 3. Start proxy server (terminal 2)
make proxy

# 4. Test endpoints
make test-curl
```

## Environment Variables

Configure via `.env` file:

```bash
# Server certificate paths
MTLS_SERVER_CERT=./certs/server.crt
MTLS_SERVER_KEY=./certs/server.key
MTLS_CA_CERT=./certs/ca.crt

# Proxy server certificate paths
MTLS_PROXY_CERT=./certs/proxy.crt
MTLS_PROXY_KEY=./certs/proxy.key

# Client certificate paths
MTLS_CLIENT_CERT=./certs/client.crt
MTLS_CLIENT_KEY=./certs/client.key

# Optional client certificate (true = no cert required)
MTLS_OPTIONAL_CLIENT_CERT=false
```

### Environment Variable Details

| Variable | Description | Default |
|----------|-------------|---------|
| `MTLS_SERVER_CERT` | Server certificate path | `./certs/server.crt` |
| `MTLS_SERVER_KEY` | Server private key path | `./certs/server.key` |
| `MTLS_CA_CERT` | CA certificate path | `./certs/ca.crt` |
| `MTLS_PROXY_CERT` | Proxy server certificate path | `./certs/proxy.crt` |
| `MTLS_PROXY_KEY` | Proxy server private key path | `./certs/proxy.key` |
| `MTLS_CLIENT_CERT` | Client certificate path | `./certs/client.crt` |
| `MTLS_CLIENT_KEY` | Client private key path | `./certs/client.key` |
| `MTLS_OPTIONAL_CLIENT_CERT` | Make client certs optional | `false` |

**Note**: When `MTLS_OPTIONAL_CLIENT_CERT=true`:
- Server accepts connections without client certificates
- Proxy connects to server without certificates

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make certs` | Generate mTLS certificates |
| `make server` | Run mTLS server (port 8443) |
| `make proxy` | Run proxy server (port 8080) |
| `make test-curl` | Test all endpoints with curl |
| `make test-no-cert` | Test /no-cert endpoint |
| `make clean` | Remove certificates |

## Architecture

```
Client (curl) → Proxy Server (port 8080) → mTLS Server (port 8443)
                 [HTTPS]                     [HTTPS + mTLS]
```

- **mTLS Server**: Requires client certificates (configurable)
- **Proxy Server**: HTTPS with its own certificate, handles mTLS to backend
- **Clients**: Connect to proxy via HTTPS (no client cert required)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Server info and client cert details |
| GET | `/health` | Health check |
| GET | `/secure` | Secure resource (requires valid cert) |
| GET | `/no-cert` | Test endpoint without certificates |

## Example Usage

```bash
# Server info (use --insecure for self-signed certs)
curl --insecure https://localhost:8080/

# Health check
curl --insecure https://localhost:8080/health

# Test without certificates
curl --insecure https://localhost:8080/no-cert

# Or verify with CA certificate
curl --cacert certs/ca.crt https://localhost:8080/health
```

## Next.js Client Application

A sample Next.js application is included to demonstrate server-side HTTPS communication with the proxy server.

```bash
# Navigate to Next.js app
cd nextjs-app

# Install dependencies
npm install

# Run development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to see the application.

See [nextjs-app/README.md](nextjs-app/README.md) for detailed documentation.

## Files

- `mtls_server.py` - mTLS server implementation
- `proxy_server.py` - HTTPS proxy to mTLS backend
- `mtls_http_client.py` - mTLS HTTP client
- `http_client.py` - Base HTTP client
- `generate-mtls-certs.sh` - Certificate generation script (includes proxy certs)
- `nextjs-app/` - Next.js client application example
- `Makefile` - Build and test commands
- `.env` - Environment configuration

## Development

```bash
# Run with custom settings
MTLS_OPTIONAL_CLIENT_CERT=true python mtls_server.py
MTLS_OPTIONAL_CLIENT_CERT=true python proxy_server.py

# Custom ports
python mtls_server.py --port 9443
python proxy_server.py --port 9080 --mtls-port 9443
```
