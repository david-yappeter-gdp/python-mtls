# Deployment Guide

Quick guide to deploy mTLS server and proxy using Docker.

## Prerequisites

```bash
# Generate certificates first
make certs
```

## Build Docker Images

```bash
# Build mTLS server image
docker build -f Dockerfile.server -t mtls-server .

# Build proxy server image
docker build -f Dockerfile.proxy -t mtls-proxy .
```

## Run Containers

### Option 1: Docker Run

```bash
# 1. Create a network
docker network create mtls-network

# 2. Run mTLS server
docker run -d \
  --name mtls-server \
  --network mtls-network \
  -p 8443:8443 \
  -v $(pwd)/certs:/app/certs \
  mtls-server

# 3. Run proxy server (HTTPS)
docker run -d \
  --name mtls-proxy \
  --network mtls-network \
  -p 8080:8080 \
  -v $(pwd)/certs:/app/certs \
  -e MTLS_SERVER_HOST=mtls-server \
  mtls-proxy
```

### Option 2: Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mtls-server:
    build:
      context: .
      dockerfile: Dockerfile.server
    ports:
      - "8443:8443"
    volumes:
      - ./certs:/app/certs
    networks:
      - mtls-network

  mtls-proxy:
    build:
      context: .
      dockerfile: Dockerfile.proxy
    ports:
      - "8080:8080"  # HTTPS proxy server
    volumes:
      - ./certs:/app/certs
    environment:
      - MTLS_SERVER_HOST=mtls-server
      - MTLS_PROXY_CERT=./certs/proxy.crt
      - MTLS_PROXY_KEY=./certs/proxy.key
    depends_on:
      - mtls-server
    networks:
      - mtls-network

networks:
  mtls-network:
    driver: bridge
```

Run with:

```bash
# Start both services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Test Deployment

```bash
# Test proxy endpoints (HTTPS with self-signed certs)
curl --insecure https://localhost:8080/
curl --insecure https://localhost:8080/health
curl --insecure https://localhost:8080/secure
curl --insecure https://localhost:8080/no-cert

# Or verify with CA certificate
curl --cacert certs/ca.crt https://localhost:8080/health
```

## Environment Variables

Configure via `.env` file (copied into images during build):

```bash
# mTLS Server certificates
MTLS_SERVER_CERT=./certs/server.crt
MTLS_SERVER_KEY=./certs/server.key
MTLS_CA_CERT=./certs/ca.crt

# Proxy Server certificates (HTTPS)
MTLS_PROXY_CERT=./certs/proxy.crt
MTLS_PROXY_KEY=./certs/proxy.key

# Client certificates (for proxy to mTLS server)
MTLS_CLIENT_CERT=./certs/client.crt
MTLS_CLIENT_KEY=./certs/client.key

# Optional: Allow connections without client certs
MTLS_OPTIONAL_CLIENT_CERT=false
```

## Certificate Generation

The `generate-mtls-certs.sh` script now generates:
- CA certificate and key
- Server certificate and key (for mTLS server)
- **Proxy certificate and key (for HTTPS proxy server)**
- Client certificate and key (for proxy → mTLS server communication)

All certificates are signed by the same CA for trust chain validation.
