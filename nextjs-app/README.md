# Next.js mTLS Proxy Client

A simple Next.js application that demonstrates server-side communication with the HTTPS proxy server.

## Features

- 🔒 **HTTPS Communication**: Connects to the proxy server via HTTPS
- 🔐 **Certificate Verification**: Supports CA certificate validation
- ⚡ **Server-Side Rendering**: Fetches data on the server using Next.js App Router
- 🎨 **Modern UI**: Beautiful interface to display proxy responses
- 🔄 **Multiple Endpoints**: Tests all available proxy endpoints

## Prerequisites

1. **Generate certificates** in the parent directory:
   ```bash
   cd ..
   ./generate-mtls-certs.sh
   ```

2. **Start the mTLS server**:
   ```bash
   cd ..
   python mtls_server.py
   ```

3. **Start the proxy server**:
   ```bash
   cd ..
   python proxy_server.py
   ```

## Installation

```bash
# Install dependencies
npm install
# or
yarn install
# or
pnpm install
```

## Configuration

Edit `.env.local` to configure the proxy connection:

```bash
# Proxy server URL
PROXY_SERVER_URL=https://localhost:8080

# Path to CA certificate (relative to nextjs-app directory)
PROXY_CA_CERT_PATH=../certs/ca.crt

# Skip certificate verification (for development only)
# Set to 'false' for production with proper CA verification
SKIP_CERT_VERIFICATION=false
```

## Running the Application

### Development Mode

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

```bash
npm run build
npm start
# or
yarn build
yarn start
# or
pnpm build
pnpm start
```

## How It Works

1. **Server-Side Rendering**: The Next.js app fetches data from the proxy server during server-side rendering
2. **HTTPS Client**: Uses Node.js `https` module with custom agent for certificate handling
3. **Proxy Communication**: The Next.js server connects to the HTTPS proxy server
4. **mTLS Backend**: The proxy server forwards requests to the mTLS backend server

## Architecture

```
Browser → Next.js App (port 3000) → Proxy Server (port 8080) → mTLS Server (port 8443)
          [HTTP/HTTPS]                [HTTPS]                    [HTTPS + mTLS]
```

## API Routes

The application includes an API route for testing POST requests:

- `POST /api/echo` - Forwards data to the proxy server's `/echo` endpoint

Example:
```bash
curl -X POST http://localhost:3000/api/echo \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from Next.js!"}'
```

## Endpoints Tested

The home page automatically tests these proxy endpoints:

- `GET /` - Server info and client certificate details
- `GET /health` - Health check
- `GET /secure` - Secure resource access
- `GET /no-cert` - Test endpoint without certificates

## Certificate Verification

### Development Mode (Skip Verification)
```bash
SKIP_CERT_VERIFICATION=true
```

This disables certificate verification. Use only for local development.

### Production Mode (With CA Certificate)
```bash
SKIP_CERT_VERIFICATION=false
PROXY_CA_CERT_PATH=../certs/ca.crt
```

This verifies the proxy server's certificate using the CA certificate.

## Troubleshooting

### Certificate Errors

If you see certificate errors:
1. Ensure certificates are generated: `cd .. && ./generate-mtls-certs.sh`
2. Check that `PROXY_CA_CERT_PATH` points to the correct CA certificate
3. For development, set `SKIP_CERT_VERIFICATION=true`

### Connection Refused

If the app can't connect to the proxy:
1. Ensure the proxy server is running: `cd .. && python proxy_server.py`
2. Check that `PROXY_SERVER_URL` matches the proxy server address
3. Verify the proxy server is running on HTTPS (not HTTP)

### Port Already in Use

If port 3000 is already in use:
```bash
npm run dev -- -p 3001
```

## Project Structure

```
nextjs-app/
├── app/
│   ├── api/
│   │   └── echo/
│   │       └── route.ts       # API route for POST requests
│   ├── globals.css            # Global styles
│   ├── layout.tsx             # Root layout
│   ├── page.tsx               # Home page (SSR)
│   └── page.module.css        # Page styles
├── lib/
│   └── proxyClient.ts         # HTTPS client for proxy server
├── .env.local                 # Environment configuration
├── next.config.js             # Next.js configuration
├── package.json               # Dependencies
├── tsconfig.json              # TypeScript configuration
└── README.md                  # This file
```

## Learn More

- [Next.js Documentation](https://nextjs.org/docs)
- [Node.js HTTPS Module](https://nodejs.org/api/https.html)
- [mTLS Overview](https://en.wikipedia.org/wiki/Mutual_authentication)
