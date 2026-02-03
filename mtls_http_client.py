"""mTLS-enabled HTTP client for secure third-party API calls.

This module provides HTTP clients with mutual TLS (mTLS) support for secure
communication with third-party APIs that require client certificate authentication.

DESIGN PATTERNS:
- Strategy Pattern: Pluggable response parsers and error handlers
- Builder Pattern: Fluent configuration API
- Template Method Pattern: Standardized request lifecycle

BEST PRACTICES:
✅ Type hints for all parameters and return values
✅ Secure certificate handling with validation
✅ Proper SSL/TLS context configuration
✅ Connection pooling and timeout management
✅ Comprehensive error handling and logging

Authors:
    David Yappeter (david.yappeter@gdplabs.id)

Usage:
    ```python
    from glchat_be.utils.mtls_http_client import MTLSHTTPClient, MTLSConfig

    # Configure mTLS
    mtls_config = MTLSConfig(
        client_cert_path="/path/to/client.crt",
        client_key_path="/path/to/client.key",
        ca_cert_path="/path/to/ca.crt",  # Optional
    )

    # Create client
    client = MTLSHTTPClient(
        base_url="https://api.example.com",
        mtls_config=mtls_config,
        response_parser=simple_json_parser,
    )

    # Make requests
    result = await client.get("/endpoint", ResponseModel)
    ```
"""

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generic, TypeVar

import httpx
from pydantic import BaseModel

from http_client import create_simple_http_client, default_error_handler, simple_json_parser

T = TypeVar("T", bound=BaseModel)

# Type aliases for strategies
ResponseParserFunc = Callable[[httpx.Response, type[T]], T | None]
ErrorHandlerFunc = Callable[[Exception, dict[str, Any]], Exception]


@dataclass
class MTLSConfig:
    """Configuration for mutual TLS authentication.

    Attributes:
        client_cert_path (str): Path to client certificate file (PEM format).
        client_key_path (str): Path to client private key file (PEM format).
        client_key_password (str | None): Password for encrypted private key. Defaults to None.
        ca_cert_path (str | None): Path to CA certificate bundle for server verification. Defaults to None.
        ssl_minimum_version (ssl.TLSVersion): Minimum TLS version. Defaults to TLSv1.2.
    """

    client_cert_path: str
    client_key_path: str
    client_key_password: str | None = None
    ca_cert_path: str | None = None
    ssl_minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    def validate(self) -> None:
        """Validate mTLS configuration.

        Raises:
            FileNotFoundError: If certificate or key files don't exist.
            ValueError: If configuration is invalid.
        """
        # Validate client certificate
        cert_path = Path(self.client_cert_path)
        if not cert_path.exists():
            raise FileNotFoundError(f"Client certificate not found: {self.client_cert_path}")
        if not cert_path.is_file():
            raise ValueError(f"Client certificate path is not a file: {self.client_cert_path}")

        # Validate client key
        key_path = Path(self.client_key_path)
        if not key_path.exists():
            raise FileNotFoundError(f"Client key not found: {self.client_key_path}")
        if not key_path.is_file():
            raise ValueError(f"Client key path is not a file: {self.client_key_path}")

        # Validate CA certificate if provided
        if self.ca_cert_path:
            ca_path = Path(self.ca_cert_path)
            if not ca_path.exists():
                raise FileNotFoundError(f"CA certificate not found: {self.ca_cert_path}")
            if not ca_path.is_file():
                raise ValueError(f"CA certificate path is not a file: {self.ca_cert_path}")


class MTLSHTTPClient(Generic[T]):
    """HTTP client with mutual TLS (mTLS) support.

    This client extends the base HTTP client functionality with mTLS authentication,
    allowing secure communication with APIs that require client certificates.

    Attributes:
        base_url (str): The base URL for all requests.
        mtls_config (MTLSConfig): mTLS configuration with certificate paths.
        default_headers (dict[str, str]): Default headers to include in all requests.
        timeout (float): Default timeout for requests in seconds.
        response_parser (ResponseParserFunc): Function to parse responses.
        error_handler (ErrorHandlerFunc): Function to handle errors.
    """

    def __init__(  # noqa: PLR0913
        self,
        base_url: str,
        mtls_config: MTLSConfig,
        response_parser: ResponseParserFunc,
        error_handler: ErrorHandlerFunc | None = None,
        default_headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize MTLSHTTPClient.

        Args:
            base_url (str): The base URL for all requests.
            mtls_config (MTLSConfig): mTLS configuration with certificate paths.
            response_parser (ResponseParserFunc): Function to parse HTTP responses.
            error_handler (ErrorHandlerFunc | None): Function to handle errors. Defaults to default_error_handler.
            default_headers (dict[str, str] | None): Default headers. Defaults to None.
            timeout (float): Default timeout in seconds. Defaults to 30.0.

        Raises:
            FileNotFoundError: If certificate or key files don't exist.
            ValueError: If mTLS configuration is invalid.
        """
        self.base_url = base_url
        self.mtls_config = mtls_config
        self.default_headers = default_headers or {}
        self.timeout = timeout
        self.response_parser = response_parser
        self.error_handler = error_handler or default_error_handler

        # Validate configuration on initialization
        self.mtls_config.validate()


    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with mTLS configuration.

        Returns:
            ssl.SSLContext: Configured SSL context for mTLS.

        Raises:
            ssl.SSLError: If SSL context creation fails.
        """
        # Create SSL context with secure defaults
        ssl_context = ssl.create_default_context()  # noqa: S323

        # Set minimum TLS version
        ssl_context.minimum_version = self.mtls_config.ssl_minimum_version

        # Load client certificate and key
        try:
            ssl_context.load_cert_chain(
                certfile=self.mtls_config.client_cert_path,
                keyfile=self.mtls_config.client_key_path,
                password=self.mtls_config.client_key_password,
            )
        except ssl.SSLError as e:
            raise

        # Load CA certificate if provided
        if self.mtls_config.ca_cert_path:
            try:
                ssl_context.load_verify_locations(cafile=self.mtls_config.ca_cert_path)
            except ssl.SSLError as e:
                raise

        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        return ssl_context

    def _get_client_config(self) -> dict[str, Any]:
        """Get the HTTP client configuration with mTLS.

        Returns:
            dict[str, Any]: Configuration dictionary for httpx.AsyncClient.
        """
        ssl_context = self._create_ssl_context()

        return {
            "base_url": self.base_url,
            "headers": self.default_headers,
            "timeout": self.timeout,
            "verify": ssl_context,  # Use custom SSL context
            "follow_redirects": True,
        }

    async def _make_request(  # noqa: PLR0913
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with mTLS.

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.).
            endpoint (str): API endpoint path.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            params (dict[str, Any] | None): Query parameters. Defaults to None.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            httpx.Response: The HTTP response.

        Raises:
            Exception: Based on error handler strategy.
        """
        client_config = self._get_client_config()

        # Merge additional headers
        request_headers = {**self.default_headers}
        if headers:
            request_headers.update(headers)

        try:
            async with httpx.AsyncClient(**client_config) as client:
                response = await client.request(
                    method=method,
                    url=endpoint,
                    json=json_data,
                    params=params,
                    headers=request_headers,
                )
            return response
        except Exception as e:
            context = {
                "method": method,
                "endpoint": endpoint,
                "base_url": self.base_url,
                "mtls_enabled": True,
            }
            raise self.error_handler(e, context) from e

    async def request(  # noqa: PLR0913
        self,
        method: str,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> T | None:
        """Template method for making HTTP requests with mTLS.

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.).
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            params (dict[str, Any] | None): Query parameters. Defaults to None.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.

        Raises:
            Exception: Based on error handler strategy.
        """
        try:
            # Make HTTP request with mTLS
            response = await self._make_request(method, endpoint, json_data, params, headers)

            # Parse using strategy function
            parsed_data = self.response_parser(response, response_model)

            return parsed_data
        except Exception as e:
            context = {
                "method": method,
                "endpoint": endpoint,
                "response_model": response_model.__name__,
                "mtls_enabled": True,
            }
            raise self.error_handler(e, context) from e

    # Convenience methods
    async def get(
        self,
        endpoint: str,
        response_model: type[T],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> T | None:
        """Make a GET request with mTLS.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            params (dict[str, Any] | None): Query parameters. Defaults to None.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("GET", endpoint, response_model, params=params, headers=headers)

    async def post(
        self,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> T | None:
        """Make a POST request with mTLS.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("POST", endpoint, response_model, json_data=json_data, headers=headers)

    async def put(
        self,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> T | None:
        """Make a PUT request with mTLS.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("PUT", endpoint, response_model, json_data=json_data, headers=headers)

    async def patch(
        self,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> T | None:
        """Make a PATCH request with mTLS.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("PATCH", endpoint, response_model, json_data=json_data, headers=headers)

    async def delete(
        self,
        endpoint: str,
        response_model: type[T],
        headers: dict[str, str] | None = None,
    ) -> T | None:
        """Make a DELETE request with mTLS.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            headers (dict[str, str] | None): Additional headers. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("DELETE", endpoint, response_model, headers=headers)


# ============================================================================
# CONVENIENCE FACTORY FUNCTIONS
# ============================================================================


def create_mtls_http_client(  # noqa: PLR0913
    base_url: str,
    client_cert_path: str,
    client_key_path: str,
    client_key_password: str | None = None,
    ca_cert_path: str | None = None,
    auth_token: str | None = None,
    timeout: float = 30.0,
) -> MTLSHTTPClient:
    """Create an mTLS-enabled HTTP client with simple JSON responses.

    Args:
        base_url (str): The service base URL.
        client_cert_path (str): Path to client certificate file.
        client_key_path (str): Path to client private key file.
        client_key_password (str | None): Password for encrypted private key. Defaults to None.
        ca_cert_path (str | None): Path to CA certificate bundle. Defaults to None.
        auth_token (str | None): Optional authentication token. Defaults to None.
        timeout (float): Default timeout in seconds. Defaults to 30.0.

    Returns:
        MTLSHTTPClient: Configured mTLS HTTP client.

    Raises:
        FileNotFoundError: If certificate or key files don't exist.
        ValueError: If configuration is invalid.
    """
    # Create mTLS configuration
    mtls_config = MTLSConfig(
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
        client_key_password=client_key_password,
        ca_cert_path=ca_cert_path,
    )

    # Prepare headers
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    return MTLSHTTPClient(
        base_url=base_url,
        mtls_config=mtls_config,
        response_parser=simple_json_parser,
        error_handler=default_error_handler,
        default_headers=headers,
        timeout=timeout,
    )


def create_http_client_with_optional_mtls(  # noqa: PLR0913
    base_url: str,
    mtls_enabled: bool = False,
    client_cert_path: str | None = None,
    client_key_path: str | None = None,
    client_key_password: str | None = None,
    ca_cert_path: str | None = None,
    auth_token: str | None = None,
    timeout: float = 30.0,
):
    """Create HTTP client with optional mTLS based on configuration.

    This function respects the mtls_enabled flag and falls back to regular
    HTTP client when mTLS is disabled.

    Args:
        base_url (str): The service base URL.
        mtls_enabled (bool): Whether to enable mTLS. Defaults to False.
        client_cert_path (str | None): Path to client certificate file. Required if mtls_enabled=True.
        client_key_path (str | None): Path to client private key file. Required if mtls_enabled=True.
        client_key_password (str | None): Password for encrypted private key. Defaults to None.
        ca_cert_path (str | None): Path to CA certificate bundle. Defaults to None.
        auth_token (str | None): Optional authentication token. Defaults to None.
        timeout (float): Default timeout in seconds. Defaults to 30.0.

    Returns:
        MTLSHTTPClient | BaseHTTPClient: Configured HTTP client (with or without mTLS).

    Raises:
        ValueError: If mTLS is enabled but certificate paths are not provided.

    Example:
        ```python
        from glchat_be.config import settings

        # Automatically uses mTLS if enabled in settings
        client = create_http_client_with_optional_mtls(
            base_url="https://api.example.com",
            mtls_enabled=settings.MTLS_ENABLED,
            client_cert_path=settings.MTLS_CLIENT_CERT_PATH,
            client_key_path=settings.MTLS_CLIENT_KEY_PATH,
            ca_cert_path=settings.MTLS_CA_CERT_PATH,
            auth_token="bearer_token",
        )
        ```
    """
    if mtls_enabled:
        # Validate required parameters for mTLS
        if not client_cert_path or not client_key_path:
            raise ValueError("client_cert_path and client_key_path are required when mtls_enabled=True")

        return create_mtls_http_client(
            base_url=base_url,
            client_cert_path=client_cert_path,
            client_key_path=client_key_path,
            client_key_password=client_key_password,
            ca_cert_path=ca_cert_path,
            auth_token=auth_token,
            timeout=timeout,
        )
    else:
        # Fall back to regular HTTP client

        return create_simple_http_client(
            base_url=base_url,
            auth_token=auth_token,
            timeout=timeout,
        )
