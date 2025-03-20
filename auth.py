"""
UniFi authentication class.
Authenticates with the UniFi Firewall API and stores the token in the OS's Keyring Store securely.
"""
import requests
from requests import exceptions as request_exceptions

from ..py_tokens.jwt_manager import JwtManager
from ..py_unifi.constants import UNIFI_ENDPOINTS, UnifiConstants


class UnifiAuth:
    """
    UniFi authentication class.
    Provides login() and logout() functionality.
    Uses JwtManager for secure token storage and parsing.
    """

    def __init__(self, base_url, username, password, verify_ssl,
                 service_name="UnifiApiClientToken"):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token_manager = JwtManager(self.session, service_name)

    @property
    def is_logged_in(self) -> bool:
        """Determine if we are 'logged in' by checking if our token is valid."""
        return self.token_manager.is_token_valid()

    def login(self) -> bool:
        """
        Logs into the UniFi Firewall API if our token is missing or invalid.
        Returns True if already logged in or if we just successfully logged in.
        Raises HTTPError if login fails.
        """
        if self.is_logged_in:
            return True

        response = self.session.get(f"{self.base_url}/")
        if response.status_code not in [200, 401]:
            raise request_exceptions.HTTPError(
                f"Unexpected GET status code during init: {response.status_code}"
            )

        login_url = f"{self.base_url}{UNIFI_ENDPOINTS['LOGIN']}"
        headers = UnifiConstants.get_headers(self.base_url)
        headers["Referer"] = f"{self.base_url}/login"

        payload = {"username": self.username, "password": self.password}
        response = self.session.post(login_url, json=payload, headers=headers)

        if response.status_code == 200:
            # We have a 200, meaning our credentials were accepted
            for cookie in self.session.cookies:
                if cookie.name.upper() == "TOKEN":
                    self.token_manager.save_token(cookie.value)
                    break
            if self.is_logged_in:
                return True

            # If token was invalid after all, throw an error
            raise request_exceptions.HTTPError(
                "Token invalid after login.")
        if response.status_code == 429:
            raise request_exceptions.HTTPError(
                "Rate limit hit (429). Wait before retrying.")

        # For other status codes, raise an error
        raise request_exceptions.HTTPError(
            f"Login failed with status {response.status_code}: {response.text}"
        )

    def logout(self) -> bool:
        """
        Logout from the UniFi Firewall API.
        If the token is invalid or missing, no request is sent. 
        Otherwise, we call the logout endpoint and clear the token if successful.

        Returns True if we are now 'logged out' (meaning token is invalid/cleared),
        or if no valid token was present in the first place.
        """
        if not self.is_logged_in:
            self.token_manager.clear_token()
            return True

        logout_url = f"{self.base_url}{UNIFI_ENDPOINTS['LOGOUT']}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.base_url}/logout",
            "Origin": self.base_url,
            "x-csrf-token": self.token_manager.get_csrf_token()
        }

        payload = {"TOKEN": self.token_manager.token_info["token"]}
        response = self.session.post(logout_url, json=payload, headers=headers)

        if response.ok:
            self.token_manager.clear_token()
            return True

        # If logout fails, but the token is now effectively invalid on the server side,
        # you can choose to still clear or to keep it. This example keeps the token
        # until we know for sure it's invalid. Return False to signal that we might still be logged in.
        return False
