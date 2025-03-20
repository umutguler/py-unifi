"""
Low-level UniFi client that exposes raw HTTP methods and ensures authentication.
"""

from requests import exceptions as request_exceptions

from .auth import UnifiAuth


def requires_auth(func):
    """Decorator to ensure authentication before executing a method."""

    def wrapper(self, *args, **kwargs):
        self.ensure_logged_in()
        return func(self, *args, **kwargs)
    return wrapper


class UnifiClient:
    """
    Low-level UniFi client that exposes raw HTTP methods.
    """

    def __init__(self, base_url, username, password, verify_ssl=False,
                 service_name="UnifiApiClientToken"):
        self.auth = UnifiAuth(base_url, username, password,
                              verify_ssl, service_name)
        self.base_url = self.auth.base_url
        self.session = self.auth.session
        self._retries = 0
        self._max_retries = 1

    def ensure_logged_in(self):
        """
        Ensure we have a valid UniFi token. If not, attempt a login.
        """
        if not self.auth.is_logged_in:
            self.auth.login()

    @requires_auth
    def request(self, method, path, json_data=None):
        """HTTP request method that ensures authentication."""
        url = self.base_url + path
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Use the token manager inside auth to grab the CSRF token if present
        csrf_token = self.auth.token_manager.get_csrf_token()
        if csrf_token:
            headers["x-csrf-token"] = csrf_token

        response = self.session.request(
            method.upper(), url, headers=headers, json=json_data
        )

        if response.status_code == 401 and self._retries < self._max_retries:
            self._retries += 1
            self.auth.token_manager.clear_token()
            self.auth.login()
            return self.request(method, path, json_data)

        if response.status_code == 429:
            raise request_exceptions.HTTPError(
                "Rate limit hit (429). Wait before retrying."
            )

        self._retries = 0
        if not response.ok:
            raise request_exceptions.HTTPError(
                f"Request {method} {url} failed: {response.status_code}, {response.text}"
            )

        return response.json() if response.text else {}

    @requires_auth
    def get(self, path, json_data=None):
        """Generic GET method."""
        return self.request("GET", path, json_data)

    @requires_auth
    def post(self, path, json_data=None):
        """Generic POST method."""
        return self.request("POST", path, json_data)

    @requires_auth
    def put(self, path, json_data=None):
        """Generic PUT method."""
        return self.request("PUT", path, json_data)

    @requires_auth
    def delete(self, path, json_data=None):
        """Generic DELETE method."""
        return self.request("DELETE", path, json_data)
