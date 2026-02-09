"""Proxy server that forwards requests to mTLS server.

This server acts as a gateway/proxy that receives regular HTTP requests
and forwards them to the mTLS-enabled server using client certificate authentication.

This demonstrates a common architecture where:
- External clients connect to this proxy server (no mTLS required)
- This proxy server connects to the backend mTLS server (with mTLS)

Prerequisites:
    1. Generate test certificates: ./generate-mtls-certs.sh
    2. Start the mTLS server: python mtls_server.py
    3. Run this proxy server: python proxy_server.py

Usage:
    python proxy_server.py
    python proxy_server.py --port 8080 --mtls-host localhost --mtls-port 8443
"""

import argparse
import asyncio
import json
import logging
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mtls_http_client import create_http_client_with_optional_mtls

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants
CERT_GENERATION_HELP = "Please run: ./generate-mtls-certs.sh"

# Response models matching the mTLS server
class ServerInfoResponse(BaseModel):
    """Server info response model."""

    message: str
    client_cert: dict[str, Any]
    endpoints: dict[str, str]


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    client_cert: dict[str, Any]


class SecureDataResponse(BaseModel):
    """Secure data response model."""

    message: str
    data: dict[str, Any]
    client_cert: dict[str, Any]


class EchoResponse(BaseModel):
    """Echo response model."""

    message: str
    received_data: dict[str, Any]
    client_cert: dict[str, Any]


class ResourceResponse(BaseModel):
    """Resource operation response model."""

    message: str
    resource_id: str | None = None
    updated_data: dict[str, Any] | None = None
    client_cert: dict[str, Any]


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str
    message: str | None = None
    path: str | None = None


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler that proxies requests to mTLS server."""

    # Class-level attribute to store mTLS client
    mtls_client = None
    # Class-level attribute to store non-mTLS client for testing
    no_cert_client = None

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json") -> None:
        """Set response headers.

        Args:
            status_code (int): HTTP status code. Defaults to 200.
            content_type (str): Content type header. Defaults to "application/json".
        """
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Proxy-Server", "mTLS-Proxy/1.0")
        self.end_headers()

    def _send_json_response(self, data: dict[str, Any] | BaseModel, status_code: int = 200) -> None:
        """Send JSON response.

        Args:
            data (dict[str, Any] | BaseModel): Data to send as JSON.
            status_code (int): HTTP status code. Defaults to 200.
        """
        self._set_headers(status_code)
        if isinstance(data, BaseModel):
            json_data = data.model_dump_json()
        else:
            json_data = json.dumps(data)
        self.wfile.write(json_data.encode())

    def _send_error_response(self, error: str, message: str | None = None, status_code: int = 500) -> None:
        """Send error response.

        Args:
            error (str): Error type.
            message (str | None): Error message. Defaults to None.
            status_code (int): HTTP status code. Defaults to 500.
        """
        error_data = {"error": error, "message": message, "path": self.path}
        self._send_json_response(error_data, status_code)

    async def _proxy_get_request(self) -> None:
        """Proxy GET request to mTLS server."""
        logger.info("📥 [GET] %s - Client: %s:%s", self.path, self.client_address[0], self.client_address[1])
        try:
            if self.path == "/":
                logger.info("🔄 Forwarding GET / to mTLS server...")
                response = await self.mtls_client.get("/", ServerInfoResponse)
            elif self.path == "/health":
                logger.info("🔄 Forwarding GET /health to mTLS server...")
                response = await self.mtls_client.get("/health", HealthResponse)
            elif self.path == "/secure":
                logger.info("🔄 Forwarding GET /secure to mTLS server...")
                response = await self.mtls_client.get("/secure", SecureDataResponse)
            elif self.path == "/no-cert":
                # Test endpoint that hits mTLS server WITHOUT certificates
                # This should fail with SSL/certificate error
                try:
                    response = await self.no_cert_client.get("/health", HealthResponse)
                    if response:
                        self._send_json_response(response)
                    else:
                        self._send_error_response("No Response", "mTLS server returned no data")
                except Exception as cert_error:
                    # Expected to fail - return the error details
                    logger.info("✅ No-cert test failed as expected: %s", type(cert_error).__name__)
                    self._send_json_response(
                        {
                            "endpoint": "/test-no-cert",
                            "expected_behavior": "This endpoint intentionally connects without certificates to demonstrate mTLS requirement",
                            "error_type": type(cert_error).__name__,
                            "error_message": str(cert_error),
                            "result": "Failed as expected - mTLS server requires client certificates",
                        },
                        status_code=200,
                    )
                return
            else:
                logger.warning("❌ Unknown endpoint: %s", self.path)
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)
                return

            if response:
                logger.info("✅ [GET] %s - Success (200)", self.path)
                self._send_json_response(response)
            else:
                logger.warning("⚠️  [GET] %s - No response from mTLS server", self.path)
                self._send_error_response("No Response", "mTLS server returned no data")

        except Exception as e:
            logger.error("❌ [GET] %s - Error: %s", self.path, e)
            self._send_error_response("Proxy Error", str(e))

    async def _proxy_post_request(self) -> None:
        """Proxy POST request to mTLS server."""
        logger.info("📥 [POST] %s - Client: %s:%s", self.path, self.client_address[0], self.client_address[1])
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode()) if body else {}
                logger.info("📦 Request body size: %d bytes", content_length)
            except json.JSONDecodeError:
                logger.error("❌ [POST] %s - Invalid JSON in request body", self.path)
                self._send_error_response("Invalid JSON", "Request body is not valid JSON", status_code=400)
                return

            if self.path == "/echo":
                logger.info("🔄 Forwarding POST /echo to mTLS server...")
                response = await self.mtls_client.post("/echo", EchoResponse, json_data=data)
                if response:
                    logger.info("✅ [POST] %s - Success (200)", self.path)
                    self._send_json_response(response)
                else:
                    logger.warning("⚠️  [POST] %s - No response from mTLS server", self.path)
                    self._send_error_response("No Response", "mTLS server returned no data")
            else:
                logger.warning("❌ Unknown endpoint: %s", self.path)
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)

        except Exception as e:
            logger.error("❌ [POST] %s - Error: %s", self.path, e)
            self._send_error_response("Proxy Error", str(e))

    async def _proxy_put_request(self) -> None:
        """Proxy PUT request to mTLS server."""
        logger.info("📥 [PUT] %s - Client: %s:%s", self.path, self.client_address[0], self.client_address[1])
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode()) if body else {}
                logger.info("📦 Request body size: %d bytes", content_length)
            except json.JSONDecodeError:
                logger.error("❌ [PUT] %s - Invalid JSON in request body", self.path)
                self._send_error_response("Invalid JSON", "Request body is not valid JSON", status_code=400)
                return

            if self.path.startswith("/resource/"):
                logger.info("🔄 Forwarding PUT %s to mTLS server...", self.path)
                response = await self.mtls_client.put(self.path, ResourceResponse, json_data=data)
                if response:
                    logger.info("✅ [PUT] %s - Success (200)", self.path)
                    self._send_json_response(response)
                else:
                    logger.warning("⚠️  [PUT] %s - No response from mTLS server", self.path)
                    self._send_error_response("No Response", "mTLS server returned no data")
            else:
                logger.warning("❌ Unknown endpoint: %s", self.path)
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)

        except Exception as e:
            logger.error("❌ [PUT] %s - Error: %s", self.path, e)
            self._send_error_response("Proxy Error", str(e))

    async def _proxy_delete_request(self) -> None:
        """Proxy DELETE request to mTLS server."""
        logger.info("📥 [DELETE] %s - Client: %s:%s", self.path, self.client_address[0], self.client_address[1])
        try:
            if self.path.startswith("/resource/"):
                logger.info("🔄 Forwarding DELETE %s to mTLS server...", self.path)
                response = await self.mtls_client.delete(self.path, ResourceResponse)
                if response:
                    logger.info("✅ [DELETE] %s - Success (200)", self.path)
                    self._send_json_response(response)
                else:
                    logger.warning("⚠️  [DELETE] %s - No response from mTLS server", self.path)
                    self._send_error_response("No Response", "mTLS server returned no data")
            else:
                logger.warning("❌ Unknown endpoint: %s", self.path)
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)

        except Exception as e:
            logger.error("❌ [DELETE] %s - Error: %s", self.path, e)
            self._send_error_response("Proxy Error", str(e))

    def do_GET(self) -> None:
        """Handle GET requests."""
        asyncio.run(self._proxy_get_request())

    def do_POST(self) -> None:
        """Handle POST requests."""
        asyncio.run(self._proxy_post_request())

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        asyncio.run(self._proxy_put_request())

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        asyncio.run(self._proxy_delete_request())

    def log_message(self, format: str, *args: Any) -> None:
        """Override to customize logging.

        Args:
            format (str): Log message format.
            *args: Format arguments.
        """


def run_proxy_server(  # noqa: PLR0913
    host: str = "localhost",
    port: int = 8080,
    mtls_host: str = "localhost",
    mtls_port: int = 8443,
    proxy_cert: str = "proxy.crt",
    proxy_key: str = "proxy.key",
    client_cert: str = "client.crt",
    client_key: str = "client.key",
    ca_cert: str = "ca.crt",
    use_mtls: bool = True,
) -> None:
    """Run the proxy server.

    Args:
        host (str): Proxy server host. Defaults to "localhost".
        port (int): Proxy server port. Defaults to 8080.
        mtls_host (str): mTLS server host. Defaults to "localhost".
        mtls_port (int): mTLS server port. Defaults to 8443.
        proxy_cert (str): Path to proxy server certificate. Defaults to "proxy.crt".
        proxy_key (str): Path to proxy server key. Defaults to "proxy.key".
        client_cert (str): Path to client certificate. Defaults to "client.crt".
        client_key (str): Path to client key. Defaults to "client.key".
        ca_cert (str): Path to CA certificate. Defaults to "ca.crt".
        use_mtls (bool): Whether to use mTLS for backend connection. Defaults to True.
    """
    try:
        logger.info("="*60)
        logger.info("🚀 Starting HTTPS Proxy Server...")
        logger.info("="*60)
        
        # Verify proxy certificates exist
        logger.info("📋 Checking proxy server certificates...")
        if not os.path.exists(proxy_cert):
            logger.error("❌ Error: Proxy certificate not found: %s", proxy_cert)
            logger.error(CERT_GENERATION_HELP)
            return
        logger.info("✅ Proxy certificate found: %s", proxy_cert)
        
        if not os.path.exists(proxy_key):
            logger.error("❌ Error: Proxy key not found: %s", proxy_key)
            logger.error(CERT_GENERATION_HELP)
            return
        logger.info("✅ Proxy key found: %s", proxy_key)

        # Create client for backend communication
        mtls_base_url = f"https://{mtls_host}:{mtls_port}"
        logger.info("🔧 Configuring backend connection...")
        logger.info("   Backend URL: %s", mtls_base_url)
        
        if use_mtls:
            # Create mTLS client with certificates
            logger.info("🔐 Setting up mTLS client with certificates...")
            logger.info("   Client cert: %s", client_cert)
            logger.info("   Client key: %s", client_key)
            logger.info("   CA cert: %s", ca_cert)
            
            ProxyRequestHandler.mtls_client = create_http_client_with_optional_mtls(
                mtls_enabled=True,
                base_url=mtls_base_url,
                client_cert_path=client_cert,
                client_key_path=client_key,
                ca_cert_path=ca_cert,
                timeout=10.0,
            )
            logger.info("✅ mTLS client configured successfully")
        else:
            # Create regular HTTPS client without certificates
            logger.info("🔓 Setting up regular HTTPS client (no mTLS)...")
            ProxyRequestHandler.mtls_client = create_http_client_with_optional_mtls(
                mtls_enabled=False,
                base_url=mtls_base_url,
                timeout=10.0,
            )
            logger.info("✅ HTTPS client configured successfully")

        # Create non-mTLS client for testing /no-cert endpoint
        # This will fail when connecting to mTLS server, demonstrating the requirement
        logger.info("🧪 Setting up test client (without certificates)...")
        ProxyRequestHandler.no_cert_client = create_http_client_with_optional_mtls(
            mtls_enabled=False,
            base_url=mtls_base_url,
            timeout=10.0,
        )
        logger.info("✅ Test client configured successfully")

        # Create HTTPS server with SSL/TLS
        logger.info("🌐 Creating HTTPS server...")
        server = HTTPServer((host, port), ProxyRequestHandler)

        # Configure SSL context for the proxy server
        logger.info("🔒 Configuring SSL/TLS context...")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.load_cert_chain(certfile=proxy_cert, keyfile=proxy_key)
        logger.info("   Minimum TLS version: TLSv1.2")

        # Wrap the socket with SSL
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info("✅ SSL/TLS configured successfully")

        logger.info("="*60)
        logger.info("🔒 HTTPS Proxy Server started on https://%s:%d", host, port)
        logger.info("📡 Forwarding to mTLS backend: https://%s:%d", mtls_host, mtls_port)
        logger.info("🔐 Using mTLS: %s", use_mtls)
        logger.info("="*60)
        logger.info("✅ Proxy server is ready to accept HTTPS connections...")

        # Start serving
        server.serve_forever()

    except FileNotFoundError as e:
        logger.error("❌ Error: Certificate file not found: %s", e)
        logger.error(CERT_GENERATION_HELP)
    except KeyboardInterrupt:
        logger.info("🛑 Proxy server stopped")
    except Exception as e:
        logger.error("❌ Error starting proxy server: %s", e)


def main() -> None:
    """Main entry point."""
    # Get certificate paths from environment variables or use defaults
    script_dir = Path(__file__).parent
    default_cert_dir = script_dir / "certs"

    default_proxy_cert = str(default_cert_dir / "proxy.crt")
    default_proxy_key = str(default_cert_dir / "proxy.key")
    default_client_cert = str(default_cert_dir / "client.crt")
    default_client_key = str(default_cert_dir / "client.key")
    default_ca_cert = str(default_cert_dir / "ca.crt")

    proxy_cert_path = os.getenv("MTLS_PROXY_CERT", default_proxy_cert)
    proxy_key_path = os.getenv("MTLS_PROXY_KEY", default_proxy_key)
    client_cert_path = os.getenv("MTLS_CLIENT_CERT", default_client_cert)
    client_key_path = os.getenv("MTLS_CLIENT_KEY", default_client_key)
    ca_cert_path = os.getenv("MTLS_CA_CERT", default_ca_cert)

    # Get optional client cert setting from environment variable
    # If the backend server has MTLS_OPTIONAL_CLIENT_CERT=true, we can connect without certs
    optional_mtls = os.getenv("MTLS_OPTIONAL_CLIENT_CERT", "false").lower() in ("true", "1", "yes")

    # Get backend server configuration from environment variables
    mtls_server_host = os.getenv("MTLS_SERVER_HOST", "localhost")
    mtls_server_port = int(os.getenv("MTLS_SERVER_PORT", "8443"))

    parser = argparse.ArgumentParser(description="HTTPS Proxy server for mTLS backend")
    parser.add_argument("--host", default="localhost", help="Proxy server host (default: localhost)")
    parser.add_argument("--port", type=int, default=8080, help="Proxy server port (default: 8080)")
    parser.add_argument("--mtls-host", default=mtls_server_host, help=f"mTLS server host (default: {mtls_server_host})")
    parser.add_argument("--mtls-port", type=int, default=mtls_server_port, help=f"mTLS server port (default: {mtls_server_port})")
    parser.add_argument(
        "--proxy-cert",
        default=proxy_cert_path,
        help=f"Proxy server certificate path (default: {proxy_cert_path})",
    )
    parser.add_argument(
        "--proxy-key",
        default=proxy_key_path,
        help=f"Proxy server key path (default: {proxy_key_path})",
    )
    parser.add_argument(
        "--client-cert",
        default=client_cert_path,
        help=f"Client certificate path (default: {client_cert_path})",
    )
    parser.add_argument(
        "--client-key",
        default=client_key_path,
        help=f"Client key path (default: {client_key_path})",
    )
    parser.add_argument(
        "--ca-cert",
        default=ca_cert_path,
        help=f"CA certificate path (default: {ca_cert_path})",
    )

    args = parser.parse_args()

    run_proxy_server(
        host=args.host,
        port=args.port,
        mtls_host=args.mtls_host,
        mtls_port=args.mtls_port,
        proxy_cert=args.proxy_cert,
        proxy_key=args.proxy_key,
        client_cert=args.client_cert,
        client_key=args.client_key,
        ca_cert=args.ca_cert,
        use_mtls=not optional_mtls,
    )


if __name__ == "__main__":
    main()
