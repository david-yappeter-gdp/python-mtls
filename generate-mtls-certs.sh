#!/bin/bash
# Generate test certificates for mTLS testing
#
# This script creates a complete set of certificates for testing mutual TLS:
# - CA certificate and key (Certificate Authority)
# - Server certificate and key (for the mTLS server)
# - Proxy certificate and key (for the proxy server)
# - Client certificate and key (for the mTLS client)
#
# Usage:
#   chmod +x generate-mtls-certs.sh
#   ./generate-mtls-certs.sh

set -e

echo "=========================================="
echo "🔐 Generating mTLS Test Certificates"
echo "=========================================="

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
DAYS_VALID=365

# Create directory for certificates
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo ""
echo "📁 Certificate directory: $CERT_DIR"
echo "⏰ Validity period: $DAYS_VALID days"
echo ""

# 1. Generate CA (Certificate Authority)
echo "Step 1/6: Generating CA private key..."
openssl genrsa -out ca.key 4096 2>/dev/null

echo "Step 2/6: Generating CA certificate..."
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=GLChat Test/OU=Testing/CN=GLChat Test CA" \
    2>/dev/null

# 2. Generate Server Certificate
echo "Step 3/6: Generating server private key..."
openssl genrsa -out server.key 4096 2>/dev/null

echo "Step 4/6: Generating server certificate..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=GLChat Test/OU=Testing/CN=localhost" \
    2>/dev/null

# Create server certificate extensions file
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
DNS.3 = 0.0.0.0
DNS.4 = mtls-proxy
DNS.5 = mtls-server
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days $DAYS_VALID -in server.csr -CA ca.crt -CAkey ca.key \
    -set_serial 01 -out server.crt -extfile server.ext 2>/dev/null

# 3. Generate Proxy Server Certificate
echo "Step 5/8: Generating proxy server private key..."
openssl genrsa -out proxy.key 4096 2>/dev/null

echo "Step 6/8: Generating proxy server certificate..."
openssl req -new -key proxy.key -out proxy.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=GLChat Test/OU=Testing/CN=localhost" \
    2>/dev/null

# Create proxy certificate extensions file
cat > proxy.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
DNS.3 = 0.0.0.0
DNS.4 = mtls-proxy
DNS.5 = mtls-server
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days $DAYS_VALID -in proxy.csr -CA ca.crt -CAkey ca.key \
    -set_serial 03 -out proxy.crt -extfile proxy.ext 2>/dev/null

# 4. Generate Client Certificate
echo "Step 7/8: Generating client private key..."
openssl genrsa -out client.key 4096 2>/dev/null

echo "Step 8/8: Generating client certificate..."
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=GLChat Test/OU=Testing/CN=GLChat Test Client" \
    2>/dev/null

openssl x509 -req -days $DAYS_VALID -in client.csr -CA ca.crt -CAkey ca.key \
    -set_serial 02 -out client.crt 2>/dev/null

# Cleanup CSR files
rm -f server.csr proxy.csr client.csr server.ext proxy.ext

echo ""
echo "=========================================="
echo "✅ Certificate Generation Complete!"
echo "=========================================="
echo ""
echo "Generated files in $CERT_DIR:"
echo "  📄 ca.crt       - CA certificate (for verification)"
echo "  🔑 ca.key       - CA private key"
echo "  📄 server.crt   - Server certificate"
echo "  🔑 server.key   - Server private key"
echo "  📄 proxy.crt    - Proxy server certificate"
echo "  🔑 proxy.key    - Proxy server private key"
echo "  📄 client.crt   - Client certificate"
echo "  🔑 client.key   - Client private key"
echo ""
echo "Certificate details:"
openssl x509 -in ca.crt -noout -subject -dates 2>/dev/null | sed 's/^/  /'
echo ""
echo "Next steps:"
echo "  1. Start the mTLS server:"
echo "     python mtls-server.py"
echo ""
echo "  2. Run the mTLS client tests:"
echo "     python mtls-client.py"
echo ""
echo "⚠️  Note: These certificates are for TESTING ONLY!"
echo "    Do NOT use in production environments."
echo "=========================================="
