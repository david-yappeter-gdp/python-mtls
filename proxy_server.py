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
        try:
            if self.path == "/":
                response = await self.mtls_client.get("/", ServerInfoResponse)
            elif self.path == "/health":
                response = await self.mtls_client.get("/health", HealthResponse)
            elif self.path == "/secure":
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
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)
                return

            if response:
                self._send_json_response(response)
            else:
                self._send_error_response("No Response", "mTLS server returned no data")

        except Exception as e:
            self._send_error_response("Proxy Error", str(e))

    async def _proxy_post_request(self) -> None:
        """Proxy POST request to mTLS server."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode()) if body else {}
            except json.JSONDecodeError:
                self._send_error_response("Invalid JSON", "Request body is not valid JSON", status_code=400)
                return

            if self.path == "/echo":
                response = await self.mtls_client.post("/echo", EchoResponse, json_data=data)
                if response:
                    self._send_json_response(response)
                else:
                    self._send_error_response("No Response", "mTLS server returned no data")
            else:
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)

        except Exception as e:
            self._send_error_response("Proxy Error", str(e))

    async def _proxy_put_request(self) -> None:
        """Proxy PUT request to mTLS server."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode()) if body else {}
            except json.JSONDecodeError:
                self._send_error_response("Invalid JSON", "Request body is not valid JSON", status_code=400)
                return

            if self.path.startswith("/resource/"):
                response = await self.mtls_client.put(self.path, ResourceResponse, json_data=data)
                if response:
                    self._send_json_response(response)
                else:
                    self._send_error_response("No Response", "mTLS server returned no data")
            else:
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)

        except Exception as e:
            self._send_error_response("Proxy Error", str(e))

    async def _proxy_delete_request(self) -> None:
        """Proxy DELETE request to mTLS server."""
        try:
            if self.path.startswith("/resource/"):
                response = await self.mtls_client.delete(self.path, ResourceResponse)
                if response:
                    self._send_json_response(response)
                else:
                    self._send_error_response("No Response", "mTLS server returned no data")
            else:
                self._send_error_response("Not Found", f"Unknown endpoint: {self.path}", status_code=404)

        except Exception as e:
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
        # Verify proxy certificates exist
        if not os.path.exists(proxy_cert):
            print(f"❌ Error: Proxy certificate not found: {proxy_cert}")
            print(CERT_GENERATION_HELP)
            return
        if not os.path.exists(proxy_key):
            print(f"❌ Error: Proxy key not found: {proxy_key}")
            print(CERT_GENERATION_HELP)
            return

        # Create client for backend communication
        mtls_base_url = f"https://{mtls_host}:{mtls_port}"
        
        if use_mtls:
            # Create mTLS client with certificates
            ProxyRequestHandler.mtls_client = create_http_client_with_optional_mtls(
                mtls_enabled=True,
                base_url=mtls_base_url,
                client_cert_path=client_cert,
                client_key_path=client_key,
                ca_cert_path=ca_cert,
                timeout=10.0,
            )
        else:
            # Create regular HTTPS client without certificates
            ProxyRequestHandler.mtls_client = create_http_client_with_optional_mtls(
                mtls_enabled=False,
                base_url=mtls_base_url,
                timeout=10.0,
            )

        # Create non-mTLS client for testing /no-cert endpoint
        # This will fail when connecting to mTLS server, demonstrating the requirement
        ProxyRequestHandler.no_cert_client = create_http_client_with_optional_mtls(
            mtls_enabled=False,
            base_url=mtls_base_url,
            timeout=10.0,
        )

        # Create HTTPS server with SSL/TLS
        server = HTTPServer((host, port), ProxyRequestHandler)

        # Configure SSL context for the proxy server
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.load_cert_chain(certfile=proxy_cert, keyfile=proxy_key)

        # Wrap the socket with SSL
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

        print(f"\n🔒 HTTPS Proxy Server started on https://{host}:{port}")
        print(f"📡 Forwarding to mTLS backend: https://{mtls_host}:{mtls_port}")
        print(f"🔐 Using mTLS: {use_mtls}")
        print("\nProxy server is ready to accept HTTPS connections...\n")

        # Start serving
        server.serve_forever()

    except FileNotFoundError as e:
        print(f"\n❌ Error: Certificate file not found: {e}")
        print(CERT_GENERATION_HELP)
    except KeyboardInterrupt:
        print("\n\n🛑 Proxy server stopped")
    except Exception as e:
        print(f"\n❌ Error starting proxy server: {e}")


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

    parser = argparse.ArgumentParser(description="HTTPS Proxy server for mTLS backend")
    parser.add_argument("--host", default="localhost", help="Proxy server host (default: localhost)")
    parser.add_argument("--port", type=int, default=8080, help="Proxy server port (default: 8080)")
    parser.add_argument("--mtls-host", default="localhost", help="mTLS server host (default: localhost)")
    parser.add_argument("--mtls-port", type=int, default=8443, help="mTLS server port (default: 8443)")
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
