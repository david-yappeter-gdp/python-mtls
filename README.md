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
# Certificate paths
MTLS_SERVER_CERT=./certs/server.crt
MTLS_SERVER_KEY=./certs/server.key
MTLS_CA_CERT=./certs/ca.crt
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
                 [HTTP]                      [HTTPS + mTLS]
```

- **mTLS Server**: Requires client certificates (configurable)
- **Proxy Server**: Regular HTTP, handles mTLS to backend
- **Clients**: Connect to proxy without certificates

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Server info and client cert details |
| GET | `/health` | Health check |
| GET | `/secure` | Secure resource (requires valid cert) |
| GET | `/no-cert` | Test endpoint without certificates |

## Example Usage

```bash
# Server info
curl http://localhost:8080/

# Health check
curl http://localhost:8080/health

# Test without certificates
curl http://localhost:8080/no-cert
```

## Files

- `mtls_server.py` - mTLS server implementation
- `proxy_server.py` - HTTP proxy to mTLS backend
- `mtls_http_client.py` - mTLS HTTP client
- `http_client.py` - Base HTTP client
- `generate-mtls-certs.sh` - Certificate generation script
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
