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
  -v $(pwd)/certs:/app/certs:ro \
  -e MTLS_SERVER_HOST=mtls-server \
  -e MTLS_SERVER_PORT=8443 \
  -e MTLS_PROXY_CERT=./certs/proxy.crt \
  -e MTLS_PROXY_KEY=./certs/proxy.key \
  -e MTLS_CLIENT_CERT=./certs/proxy.crt \
  -e MTLS_CLIENT_KEY=./certs/proxy.key \
  -e MTLS_CA_CERT=./certs/ca.crt \
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
    environment:
      - MTLS_SERVER_CERT=./certs/server.crt
      - MTLS_SERVER_KEY=./certs/server.key
      - MTLS_CA_CERT=./certs/ca.crt
      - MTLS_OPTIONAL_CLIENT_CERT=false
    networks:
      - mtls-network

  mtls-proxy:
    build:
      context: .
      dockerfile: Dockerfile.proxy
    ports:
      - "8080:8080"  # HTTPS proxy server
    volumes:
      - ./certs:/app/certs:ro
    environment:
      - MTLS_SERVER_HOST=mtls-server
      - MTLS_SERVER_PORT=8443
      - MTLS_PROXY_CERT=./certs/proxy.crt
      - MTLS_PROXY_KEY=./certs/proxy.key
      - MTLS_CLIENT_CERT=./certs/proxy.crt
      - MTLS_CLIENT_KEY=./certs/proxy.key
      - MTLS_CA_CERT=./certs/ca.crt
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

### mTLS Server

```bash
# Server certificates
MTLS_SERVER_CERT=./certs/server.crt
MTLS_SERVER_KEY=./certs/server.key
MTLS_CA_CERT=./certs/ca.crt

# Optional: Allow connections without client certs
MTLS_OPTIONAL_CLIENT_CERT=false
```

### Proxy Server

```bash
# Backend mTLS server connection
MTLS_SERVER_HOST=mtls-server  # Hostname of the mTLS backend server
MTLS_SERVER_PORT=8443          # Port of the mTLS backend server

# Proxy server HTTPS certificates
MTLS_PROXY_CERT=./certs/proxy.crt
MTLS_PROXY_KEY=./certs/proxy.key

# Client certificates (for proxy to authenticate with mTLS server)
MTLS_CLIENT_CERT=./certs/proxy.crt  # Using proxy cert as client cert
MTLS_CLIENT_KEY=./certs/proxy.key    # Using proxy key as client key
MTLS_CA_CERT=./certs/ca.crt          # CA cert to verify mTLS server
```

### Next.js Frontend

```bash
# Proxy server connection
PROXY_SERVER_URL=https://mtls-proxy:8080
PROXY_CA_CERT_PATH=/app/certs/ca.crt
SKIP_CERT_VERIFICATION=false
NODE_EXTRA_CA_CERTS=/app/certs/ca.crt

# Next.js HTTPS server certificates
NEXTJS_CERT_PATH=/app/certs/proxy.crt
NEXTJS_KEY_PATH=/app/certs/proxy.key
NEXTJS_CA_CERT_PATH=/app/certs/ca.crt

# Optional: Enable client certificate verification for Next.js server
NEXTJS_REQUEST_CERT=true
NEXTJS_REJECT_UNAUTHORIZED=true

# Server hostname (use 0.0.0.0 in Docker to accept external connections)
HOSTNAME=0.0.0.0
```

## Certificate Generation

The `generate-mtls-certs.sh` script now generates:
- CA certificate and key
- Server certificate and key (for mTLS server)
- **Proxy certificate and key (for HTTPS proxy server)**
- Client certificate and key (for proxy → mTLS server communication)

All certificates are signed by the same CA for trust chain validation.

## Next.js Client Application

A sample Next.js application is included in the `nextjs-app/` directory that demonstrates server-side HTTPS communication with the proxy server.

### Running the Next.js App (Development)

```bash
# Navigate to the Next.js app
cd nextjs-app

# Install dependencies
npm install

# Create environment configuration
cp .env.local.example .env.local

# Edit .env.local and set:
# PROXY_SERVER_URL=https://localhost:8080
# PROXY_CA_CERT_PATH=../certs/ca.crt
# SKIP_CERT_VERIFICATION=false
# NEXTJS_CERT_PATH=../certs/proxy.crt
# NEXTJS_KEY_PATH=../certs/proxy.key
# NEXTJS_CA_CERT_PATH=../certs/ca.crt

# Run in development mode (HTTP)
npm run dev

# Or run with HTTPS
npm run dev:https
```

The application will be available at:
- HTTP: [http://localhost:3000](http://localhost:3000) (using `npm run dev`)
- HTTPS: [https://localhost:3000](https://localhost:3000) (using `npm run dev:https`)

### Building Next.js Docker Image

```bash
# Build the Next.js frontend image
docker build -f Dockerfile.nextjs -t nextjs-mtls-client .
```

### Docker Deployment with Next.js

To include the Next.js application in your Docker deployment, add it to your `docker-compose.yml`:

```yaml
  nextjs-app:
    build:
      context: .
      dockerfile: Dockerfile.nextjs
    ports:
      - "3000:3000"
    volumes:
      - ./certs:/app/certs:ro
    environment:
      - PROXY_SERVER_URL=https://mtls-proxy:8080
      - PROXY_CA_CERT_PATH=/app/certs/ca.crt
      - SKIP_CERT_VERIFICATION=false
      - NODE_EXTRA_CA_CERTS=/app/certs/ca.crt
      - NEXTJS_CERT_PATH=/app/certs/proxy.crt
      - NEXTJS_KEY_PATH=/app/certs/proxy.key
      - NEXTJS_CA_CERT_PATH=/app/certs/ca.crt
      - NEXTJS_REQUEST_CERT=true
      - NEXTJS_REJECT_UNAUTHORIZED=true
      - HOSTNAME=0.0.0.0
    depends_on:
      - mtls-proxy
    networks:
      - mtls-network
```

**Important**: 
- The `NODE_EXTRA_CA_CERTS` environment variable tells Node.js to trust the custom CA certificate for outgoing requests
- The `NEXTJS_*` environment variables configure the Next.js server's HTTPS certificates
- The Next.js server will run with HTTPS on port 3000

### Complete Docker Compose Example

Full `docker-compose.yml` with all three services:

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
      - ./certs:/app/certs:ro
    networks:
      - mtls-network

  mtls-proxy:
    build:
      context: .
      dockerfile: Dockerfile.proxy
    ports:
      - "8080:8080"
    volumes:
      - ./certs:/app/certs:ro
    environment:
      - MTLS_SERVER_HOST=mtls-server
      - MTLS_SERVER_PORT=8443
      - MTLS_PROXY_CERT=./certs/proxy.crt
      - MTLS_PROXY_KEY=./certs/proxy.key
      - MTLS_CLIENT_CERT=./certs/proxy.crt
      - MTLS_CLIENT_KEY=./certs/proxy.key
      - MTLS_CA_CERT=./certs/ca.crt
    depends_on:
      - mtls-server
    networks:
      - mtls-network

  nextjs-app:
    build:
      context: .
      dockerfile: Dockerfile.nextjs
    ports:
      - "3000:3000"
    volumes:
      - ./certs:/app/certs:ro
    environment:
      - PROXY_SERVER_URL=https://mtls-proxy:8080
      - PROXY_CA_CERT_PATH=/app/certs/ca.crt
      - SKIP_CERT_VERIFICATION=false
      - NODE_EXTRA_CA_CERTS=/app/certs/ca.crt
      - NEXTJS_CERT_PATH=/app/certs/proxy.crt
      - NEXTJS_KEY_PATH=/app/certs/proxy.key
      - NEXTJS_CA_CERT_PATH=/app/certs/ca.crt
      - NEXTJS_REQUEST_CERT=true
      - NEXTJS_REJECT_UNAUTHORIZED=true
      - HOSTNAME=0.0.0.0
    depends_on:
      - mtls-proxy
    networks:
      - mtls-network

networks:
  mtls-network:
    driver: bridge
```

Run all services:

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f nextjs-app

# Test the frontend (HTTPS)
curl --insecure https://localhost:3000
# Or with CA certificate
curl --cacert certs/ca.crt https://localhost:3000
```

See [nextjs-app/README.md](nextjs-app/README.md) for detailed documentation.
