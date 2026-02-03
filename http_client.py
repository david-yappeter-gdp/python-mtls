"""HTTP client with functional Strategy Pattern (Most Pythonic).

This version uses callable strategies instead of abstract classes, which is more
Pythonic and flexible while maintaining the same benefits.

DESIGN PATTERNS:
- Strategy Pattern (functional): Callable response parsers and error handlers
- Template Method Pattern: Standardized request lifecycle
- Dependency Injection: Strategies injected via constructor

BEST PRACTICES:
✅ Type hints for all parameters and return values
✅ Generic typing for flexibility
✅ Separation of concerns (parsing, error handling, HTTP)
✅ Easy to test (mock strategies)
✅ Easy to extend (add new strategies)
✅ Minimal boilerplate (no abstract classes needed)
"""

from http import HTTPStatus
from typing import Any, Callable, Generic, TypeVar

import httpx
from pydantic import BaseModel


T = TypeVar("T", bound=BaseModel)

# ============================================================================
# TYPE ALIASES FOR STRATEGIES
# ============================================================================

# Type for response parser functions
ResponseParserFunc = Callable[[httpx.Response, type[T]], T | None]

# Type for error handler functions
ErrorHandlerFunc = Callable[[Exception, dict[str, Any]], Exception]


# ============================================================================
# GENERIC HTTP CLIENT WITH FUNCTIONAL STRATEGIES
# ============================================================================


class BaseHTTPClient(Generic[T]):
    """Generic HTTP client with pluggable response parsing and error handling.

    This client uses functional strategies (callables) instead of abstract classes,
    making it more Pythonic and easier to use.

    Attributes:
        base_url (str): The base URL for all requests.
        default_headers (dict[str, str]): Default headers to include in all requests.
        timeout (float): Default timeout for requests in seconds.
        response_parser (ResponseParserFunc): Function to parse responses.
        error_handler (ErrorHandlerFunc): Function to handle errors.
    """

    def __init__(
        self,
        base_url: str,
        response_parser: ResponseParserFunc,
        error_handler: ErrorHandlerFunc | None = None,
        default_headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize BaseHTTPClient with functional strategies.

        Args:
            base_url (str): The base URL for all requests.
            response_parser (ResponseParserFunc): Function to parse HTTP responses.
            error_handler (ErrorHandlerFunc | None): Function to handle errors. Defaults to default_error_handler.
            default_headers (dict[str, str] | None): Default headers. Defaults to None.
            timeout (float): Default timeout in seconds. Defaults to 30.0.
        """
        self.base_url = base_url
        self.default_headers = default_headers or {}
        self.timeout = timeout
        self.response_parser = response_parser
        self.error_handler = error_handler or default_error_handler

    def _get_client_config(self) -> dict[str, Any]:
        """Get the HTTP client configuration.

        Returns:
            dict[str, Any]: Configuration dictionary for httpx.AsyncClient.
        """
        return {
            "base_url": self.base_url,
            "headers": self.default_headers,
            "timeout": self.timeout,
            "follow_redirects": True,
        }

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request.

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.).
            endpoint (str): API endpoint path.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            params (dict[str, Any] | None): Query parameters. Defaults to None.

        Returns:
            httpx.Response: The HTTP response.

        Raises:
            Exception: Based on error handler strategy.
        """
        client_config = self._get_client_config()

        try:
            async with httpx.AsyncClient(**client_config) as client:
                response = await client.request(
                    method=method,
                    url=endpoint,
                    json=json_data,
                    params=params,
                )
            return response
        except Exception as e:
            context = {
                "method": method,
                "endpoint": endpoint,
                "base_url": self.base_url,
            }
            raise self.error_handler(e, context) from e

    async def request(
        self,
        method: str,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> T | None:
        """Template method for making HTTP requests.

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.).
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.
            params (dict[str, Any] | None): Query parameters. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.

        Raises:
            Exception: Based on error handler strategy.
        """
        try:
            # Make HTTP request
            response = await self._make_request(method, endpoint, json_data, params)

            # Parse using strategy function
            parsed_data = self.response_parser(response, response_model)

            return parsed_data
        except Exception as e:
            context = {
                "method": method,
                "endpoint": endpoint,
                "response_model": response_model.__name__,
            }
            raise self.error_handler(e, context) from e

    # Convenience methods
    async def get(
        self,
        endpoint: str,
        response_model: type[T],
        params: dict[str, Any] | None = None,
    ) -> T | None:
        """Make a GET request.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            params (dict[str, Any] | None): Query parameters. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("GET", endpoint, response_model, params=params)

    async def post(
        self,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
    ) -> T | None:
        """Make a POST request.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("POST", endpoint, response_model, json_data=json_data)

    async def put(
        self,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
    ) -> T | None:
        """Make a PUT request.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("PUT", endpoint, response_model, json_data=json_data)

    async def patch(
        self,
        endpoint: str,
        response_model: type[T],
        json_data: dict[str, Any] | None = None,
    ) -> T | None:
        """Make a PATCH request.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.
            json_data (dict[str, Any] | None): JSON data for request body. Defaults to None.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("PATCH", endpoint, response_model, json_data=json_data)

    async def delete(
        self,
        endpoint: str,
        response_model: type[T],
    ) -> T | None:
        """Make a DELETE request.

        Args:
            endpoint (str): API endpoint path.
            response_model (type[T]): Pydantic model for response validation.

        Returns:
            T | None: Validated response data, or None if applicable.
        """
        return await self.request("DELETE", endpoint, response_model)


# ============================================================================
# STRATEGY FUNCTIONS FOR OTHER SERVICES
# ============================================================================


def simple_json_parser(response: httpx.Response, response_model: type[T]) -> T | None:
    """Parse simple JSON response without wrapper.

    Use this for services that return plain JSON responses (not wrapped).

    Args:
        response (httpx.Response): The HTTP response.
        response_model (type[T]): The expected response model.

    Returns:
        T | None: Parsed data or None if 404.

    Raises:
        httpx.HTTPStatusError: If response status indicates error.
        ValueError: If response is not valid JSON.
    """
    if response.status_code == HTTPStatus.NOT_FOUND:
        return None

    response.raise_for_status()
    response_data = response.json()
    return response_model.model_validate(response_data)


def default_error_handler(error: Exception, context: dict[str, Any]) -> Exception:
    """Default error handler that logs and re-raises.

    Args:
        error (Exception): The original error.
        context (dict[str, Any]): Request context.

    Returns:
        Exception: The original error.
    """
    context.get("endpoint", "unknown")
    return error


# ============================================================================
# CONVENIENCE FACTORY FUNCTIONS
# ============================================================================


def create_simple_http_client(
    base_url: str,
    auth_token: str | None = None,
    timeout: float = 30.0,
) -> BaseHTTPClient:
    """Create an HTTP client for services with simple JSON responses.

    Args:
        base_url (str): The service base URL.
        auth_token (str | None): Optional authentication token. Defaults to None.
        timeout (float): Default timeout in seconds. Defaults to 30.0.

    Returns:
        BaseHTTPClient: Configured HTTP client.
    """
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    return BaseHTTPClient(
        base_url=base_url,
        response_parser=simple_json_parser,
        error_handler=default_error_handler,
        default_headers=headers,
        timeout=timeout,
    )


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

"""
Example 1: Using AIPHTTPClient (pre-configured)
------------------------------------------------
from glchat_be.utils.http_client_v3 import AIPHTTPClient

client = AIPHTTPClient(base_url=AIP_BASE_URL, api_key=AIP_API_KEY)
agent = await client.get("/agents/123", AIPAgentResponse)


Example 2: Using BaseHTTPClient with custom strategies
-------------------------------------------------------
from glchat_be.utils.http_client_v3 import BaseHTTPClient, simple_json_parser

# Custom error handler
def my_error_handler(error: Exception, context: dict) -> Exception:
    # Your custom logic
    return error

client = BaseHTTPClient(
    base_url="https://api.example.com",
    response_parser=simple_json_parser,
    error_handler=my_error_handler,
    default_headers={"Authorization": "Bearer token"},
)

result = await client.get("/users/123", UserModel)


Example 3: Using factory functions
-----------------------------------
from glchat_be.utils.http_client_v3 import create_simple_http_client

client = create_simple_http_client(
    base_url="https://api.example.com",
    auth_token="your-token",
)

result = await client.get("/data", DataModel)


Example 4: Custom inline strategies (most flexible)
----------------------------------------------------
from glchat_be.utils.http_client_v3 import BaseHTTPClient

# Define custom parser inline
def custom_parser(response, model):
    data = response.json()
    # Custom transformation
    transformed = {"id": data["userId"], "name": data["fullName"]}
    return model.model_validate(transformed)

client = BaseHTTPClient(
    base_url="https://api.example.com",
    response_parser=custom_parser,
)

result = await client.get("/users/123", MyUserModel)
"""
