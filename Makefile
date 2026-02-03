.PHONY: help server proxy test-curl test-no-cert clean certs

help:
	@echo "Available targets:"
	@echo "  make certs       - Generate mTLS certificates"
	@echo "  make server      - Run mTLS server (port 8443)"
	@echo "  make proxy       - Run proxy server (port 8080)"
	@echo "  make test-curl   - Run example curl commands"
	@echo "  make test-no-cert - Test /no-cert endpoint"
	@echo "  make clean       - Clean up certificates"

# Generate certificates
certs:
	@echo "Generating mTLS certificates..."
	./generate-mtls-certs.sh

# Run mTLS server
server:
	@echo "Starting mTLS server on https://localhost:8443..."
	python mtls_server.py

# Run proxy server
proxy:
	@echo "Starting proxy server on http://localhost:8080..."
	python proxy_server.py

# Test endpoints with curl
test-curl:
	@echo "\n=== Testing Proxy Server Endpoints ==="
	@echo "\n1. Server Info (GET /):"
	curl -s http://localhost:8080/ | python -m json.tool
	@echo "\n\n2. Health Check (GET /health):"
	curl -s http://localhost:8080/health | python -m json.tool
	@echo "\n\n3. Secure Endpoint (GET /secure):"
	curl -s http://localhost:8080/secure | python -m json.tool
	@echo "\n\n4. Echo Endpoint (POST /echo):"
	curl -s -X POST http://localhost:8080/echo \
		-H "Content-Type: application/json" \
		-d '{"message": "Hello from Makefile", "timestamp": "2026-02-03"}' | python -m json.tool
	@echo "\n\n5. Update Resource (PUT /resource/123):"
	curl -s -X PUT http://localhost:8080/resource/123 \
		-H "Content-Type: application/json" \
		-d '{"name": "Updated Resource", "value": 100}' | python -m json.tool
	@echo "\n\n6. Delete Resource (DELETE /resource/456):"
	curl -s -X DELETE http://localhost:8080/resource/456 | python -m json.tool

# Test no-cert endpoint
test-no-cert:
	@echo "\n=== Testing No-Cert Endpoint ==="
	@echo "This endpoint demonstrates what happens without client certificates:"
	curl -s http://localhost:8080/no-cert | python -m json.tool

# Clean up certificates
clean:
	@echo "Cleaning up certificates..."
	rm -rf certs/
	@echo "Certificates removed."
