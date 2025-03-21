"""
Low-level UniFi client that exposes raw HTTP methods and ensures authentication.
"""

import py_logging
from py_abstractions.rest import Delete, Get, Post, Put
from requests import exceptions as request_exceptions

from .auth import UnifiAuth

logging = py_logging.get_logger(__name__)


def requires_auth(func):
    """Decorator to ensure authentication before executing a method."""

    def wrapper(self, *args, **kwargs):
        self.ensure_logged_in()
        return func(self, *args, **kwargs)
    return wrapper


class UnifiClient(Get, Post, Put, Delete):
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
            logging.debug("Not logged in. Attempting login.")
            self.auth.login()

    @requires_auth
    def __request(self, method, path, data=None):
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
            method.upper(), url, headers=headers, json=data
        )

        if response.status_code == 401 and self._retries < self._max_retries:
            self._retries += 1
            self.auth.token_manager.clear_token()
            self.auth.login()
            return self.__request(method, path, data)

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
    def get(self, resource, data=None):
        """Generic GET method."""
        logging.debug("GET %s", resource)
        return self.__request("GET", resource, data)

    @requires_auth
    def post(self, resource, data=None):
        """Generic POST method."""
        logging.debug("POST %s", resource)
        return self.__request("POST", resource, data)

    @requires_auth
    def put(self, resource, data=None):
        """Generic PUT method."""
        logging.debug("PUT %s", resource)
        return self.__request("PUT", resource, data)

    @requires_auth
    def delete(self, resource, data=None):
        """Generic DELETE method."""
        logging.debug("DELETE %s", resource)
        return self.__request("DELETE", resource, data)
