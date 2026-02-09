"""Sample mTLS server for testing mutual TLS authentication.

This server demonstrates how to set up an HTTPS server that requires
client certificate authentication (mutual TLS). It can be used to test
the MTLSHTTPClient implementation.

Prerequisites:
    Generate test certificates first:
    ```bash
    ./generate-mtls-certs.sh
    ```

    Or manually generate certificates:
    ```bash
    # Generate CA key and certificate
    openssl genrsa -out ca.key 4096
    openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
        -subj "/C=US/ST=CA/L=SF/O=Test/CN=Test CA"

    # Generate server key and certificate
    openssl genrsa -out server.key 4096
    openssl req -new -key server.key -out server.csr \
        -subj "/C=US/ST=CA/L=SF/O=Test/CN=localhost"
    openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
        -set_serial 01 -out server.crt

    # Generate client key and certificate
    openssl genrsa -out client.key 4096
    openssl req -new -key client.key -out client.csr \
        -subj "/C=US/ST=CA/L=SF/O=Test/CN=Test Client"
    openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
        -set_serial 02 -out client.crt
    ```

Usage:
    python mtls-server.py
"""

import argparse
import json
import logging
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


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


class MTLSRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler that validates client certificates."""

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json") -> None:
        """Set response headers.

        Args:
            status_code (int): HTTP status code. Defaults to 200.
            content_type (str): Content type header. Defaults to "application/json".
        """
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def _send_json_response(self, data: dict[str, Any], status_code: int = 200) -> None:
        """Send JSON response.

        Args:
            data (dict[str, Any]): Data to send as JSON.
            status_code (int): HTTP status code. Defaults to 200.
        """
        self._set_headers(status_code)
        self.wfile.write(json.dumps(data).encode())

    def _get_client_cert_info(self) -> dict[str, Any]:
        """Extract client certificate information.

        Returns:
            dict[str, Any]: Client certificate details.
        """
        try:
            # Get client certificate from SSL socket
            cert = self.connection.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "authenticated": True,
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
            return {"authenticated": False, "error": "No client certificate provided"}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    def do_GET(self) -> None:
        """Handle GET requests."""
        cert_info = self._get_client_cert_info()

        if self.path == "/":
            self._send_json_response(
                {
                    "message": "mTLS Server is running",
                    "client_cert": cert_info,
                    "endpoints": {
                        "/": "Server info and client cert details",
                        "/health": "Health check endpoint",
                        "/echo": "Echo endpoint (POST)",
                        "/secure": "Secure data endpoint (requires valid client cert)",
                    },
                }
            )
        elif self.path == "/health":
            self._send_json_response({"status": "healthy", "client_cert": cert_info})
        elif self.path == "/secure":
            if cert_info.get("authenticated"):
                self._send_json_response(
                    {
                        "message": "Access granted to secure resource",
                        "data": {"secret": "This is protected data", "timestamp": "2026-01-08T12:00:00Z"},
                        "client_cert": cert_info,
                    }
                )
            else:
                self._send_json_response(
                    {"error": "Unauthorized", "message": "Valid client certificate required"}, status_code=401
                )
        else:
            self._send_json_response({"error": "Not Found", "path": self.path}, status_code=404)

    def do_POST(self) -> None:
        """Handle POST requests."""
        cert_info = self._get_client_cert_info()

        if self.path == "/echo":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode()) if body else {}
                self._send_json_response({"message": "Echo response", "received_data": data, "client_cert": cert_info})
            except json.JSONDecodeError:
                self._send_json_response({"error": "Invalid JSON", "received_body": body.decode()}, status_code=400)
        else:
            self._send_json_response({"error": "Not Found", "path": self.path}, status_code=404)

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        cert_info = self._get_client_cert_info()

        if self.path.startswith("/resource/"):
            resource_id = self.path.split("/")[-1]
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode()) if body else {}
                self._send_json_response(
                    {
                        "message": "Resource updated",
                        "resource_id": resource_id,
                        "updated_data": data,
                        "client_cert": cert_info,
                    }
                )
            except json.JSONDecodeError:
                self._send_json_response({"error": "Invalid JSON"}, status_code=400)
        else:
            self._send_json_response({"error": "Not Found", "path": self.path}, status_code=404)

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        cert_info = self._get_client_cert_info()

        if self.path.startswith("/resource/"):
            resource_id = self.path.split("/")[-1]
            self._send_json_response(
                {"message": "Resource deleted", "resource_id": resource_id, "client_cert": cert_info}
            )
        else:
            self._send_json_response({"error": "Not Found", "path": self.path}, status_code=404)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to customize logging.

        Args:
            format (str): Log message format.
            *args: Format arguments.
        """
        cert_info = self._get_client_cert_info()
        client_cn = cert_info.get("subject", {}).get("commonName", "Unknown")
        logger.info("%s %s - Client: %s - %s", self.command, self.path, client_cn, format % args)


def create_ssl_context(
    server_cert: str, server_key: str, ca_cert: str, require_client_cert: bool = True
) -> ssl.SSLContext:
    """Create SSL context for mTLS server.

    Args:
        server_cert (str): Path to server certificate file.
        server_key (str): Path to server private key file.
        ca_cert (str): Path to CA certificate for client verification.
        require_client_cert (bool): Whether to require client certificates. Defaults to True.

    Returns:
        ssl.SSLContext: Configured SSL context.

    Raises:
        FileNotFoundError: If certificate files don't exist.
    """
    # Validate certificate files
    logger.info("🔐 Validating SSL/TLS certificates...")
    for cert_path, name in [(server_cert, "Server cert"), (server_key, "Server key"), (ca_cert, "CA cert")]:
        if not Path(cert_path).exists():
            logger.error("❌ Error: %s not found: %s", name, cert_path)
            raise FileNotFoundError(f"{name} not found: {cert_path}")
        logger.info("✅ %s: %s", name, cert_path)

    # Create SSL context
    logger.info("🔧 Configuring SSL context...")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    logger.info("   Minimum TLS version: %s", context.minimum_version.name)

    # Load server certificate and key
    logger.info("📜 Loading server certificate and key...")
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    logger.info("✅ Server certificate loaded successfully")

    # Load CA certificate for client verification
    logger.info("🔑 Loading CA certificate for client verification...")
    context.load_verify_locations(cafile=ca_cert)
    logger.info("✅ CA certificate loaded successfully")

    # Require client certificate
    logger.info("🔒 Configuring client certificate verification...")
    if require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
        logger.info("✅ Client certificate verification: REQUIRED (mTLS enabled)")
    else:
        context.verify_mode = ssl.CERT_NONE
        logger.warning("⚠️  Client certificate verification: OPTIONAL (mTLS disabled)")

    return context


def run_server(  # noqa: PLR0913
    host: str = "localhost",
    port: int = 8443,
    server_cert: str = "server.crt",
    server_key: str = "server.key",
    ca_cert: str = "ca.crt",
    require_client_cert: bool = True,
) -> None:
    """Run the mTLS server.

    Args:
        host (str): Server host. Defaults to "localhost".
        port (int): Server port. Defaults to 8443.
        server_cert (str): Path to server certificate. Defaults to "server.crt".
        server_key (str): Path to server key. Defaults to "server.key".
        ca_cert (str): Path to CA certificate. Defaults to "ca.crt".
        require_client_cert (bool): Whether to require client certificates. Defaults to True.
    """
    try:
        logger.info("="*60)
        logger.info("🚀 Starting mTLS Server")
        logger.info("="*60)
        
        # Create SSL context
        ssl_context = create_ssl_context(server_cert, server_key, ca_cert, require_client_cert)

        # Create HTTP server
        logger.info("🌐 Creating HTTPS server...")
        server = HTTPServer((host, port), MTLSRequestHandler)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info("✅ Server created successfully")

        logger.info("="*60)
        logger.info("✨ mTLS Server is running on https://%s:%d", host, port)
        logger.info("="*60)
        logger.info("Available endpoints:")
        logger.info("  GET  /          - Server info and client cert details")
        logger.info("  GET  /health    - Health check endpoint")
        logger.info("  GET  /secure    - Secure data endpoint")
        logger.info("  POST /echo      - Echo endpoint")
        logger.info("  PUT  /resource/:id - Update resource")
        logger.info("  DELETE /resource/:id - Delete resource")
        logger.info("💡 Press Ctrl+C to stop the server")
        logger.info("="*60)

        # Start serving
        server.serve_forever()

    except FileNotFoundError as e:
        logger.error("❌ Error: %s", e)
        logger.error("Please run: ./generate-mtls-certs.sh")
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
    except Exception as e:
        logger.error("❌ Error starting server: %s", e)

def main() -> None:
    """Main entry point."""
    # Get certificate paths from environment variables or use defaults
    script_dir = Path(__file__).parent
    default_cert_dir = script_dir / "mtls-certs"

    # Get individual certificate paths from environment variables
    default_server_cert = str(default_cert_dir / "server.crt")
    default_server_key = str(default_cert_dir / "server.key")
    default_ca_cert = str(default_cert_dir / "ca.crt")

    server_cert_path = os.getenv("MTLS_SERVER_CERT", default_server_cert)
    server_key_path = os.getenv("MTLS_SERVER_KEY", default_server_key)
    ca_cert_path = os.getenv("MTLS_CA_CERT", default_ca_cert)

    # Get optional client cert setting from environment variable
    # MTLS_OPTIONAL_CLIENT_CERT=true will make client certificates optional
    optional_client_cert_env = os.getenv("MTLS_OPTIONAL_CLIENT_CERT", "false").lower() in ("true", "1", "yes")

    parser = argparse.ArgumentParser(description="mTLS test server")
    parser.add_argument("--host", default="localhost", help="Server host (default: localhost)")
    parser.add_argument("--port", type=int, default=8443, help="Server port (default: 8443)")
    parser.add_argument(
        "--server-cert",
        default=server_cert_path,
        help=f"Server certificate path (default: {server_cert_path})",
    )
    parser.add_argument(
        "--server-key",
        default=server_key_path,
        help=f"Server key path (default: {server_key_path})",
    )
    parser.add_argument(
        "--ca-cert", default=ca_cert_path, help=f"CA certificate path (default: {ca_cert_path})"
    )
    args = parser.parse_args()

    run_server(
        host=args.host,
        port=args.port,
        server_cert=args.server_cert,
        server_key=args.server_key,
        ca_cert=args.ca_cert,
        require_client_cert=not optional_client_cert_env,
    )


if __name__ == "__main__":
    main()
