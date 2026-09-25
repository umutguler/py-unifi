"""
Constants for UniFi API endpoints, paths, and any other shared constants.
"""

# Seconds; without it a hung gateway blocks the caller forever.
REQUEST_TIMEOUT = 30

UNIFI_ENDPOINTS = {
    "LOGIN": "/api/auth/login",
    "LOGOUT": "/api/auth/logout",

    # Formatted Endpoints
    "FIREWALLGROUP": "/proxy/network/api/s/{site}/rest/firewallgroup/{firewallgroup_id}"
}

# pylint: disable=too-few-public-methods


class UnifiConstants:
    """Class to handle UniFi API constants."""

    @staticmethod
    def get_headers(base_url):
        """Get basic default headers with the Origin for templating. Can add extra later"""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": base_url
        }

    @staticmethod
    def get_firewallgroup_path(site, firewallgroup_id=""):
        """Formatted URL path UniFI firewall group, or of all groups if no ID is given."""
        return f"/proxy/network/api/s/{site}/rest/firewallgroup/{firewallgroup_id}".rstrip("/")
