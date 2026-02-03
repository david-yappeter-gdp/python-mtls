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

# 3. Run proxy server
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
      - "8080:8080"
    volumes:
      - ./certs:/app/certs
    environment:
      - MTLS_SERVER_HOST=mtls-server
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
# Test proxy endpoints
curl http://localhost:8080/
curl http://localhost:8080/health
curl http://localhost:8080/secure
curl http://localhost:8080/no-cert
```

## Environment Variables

Configure via `.env` file (copied into images during build):

```bash
MTLS_SERVER_CERT=./certs/server.crt
MTLS_SERVER_KEY=./certs/server.key
MTLS_CA_CERT=./certs/ca.crt
MTLS_CLIENT_CERT=./certs/client.crt
MTLS_CLIENT_KEY=./certs/client.key
MTLS_OPTIONAL_CLIENT_CERT=false
```
