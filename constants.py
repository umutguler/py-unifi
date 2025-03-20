"""
Constants for UniFi API endpoints, paths, and any other shared constants.
"""

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
    def get_firewallgroup_path(site, firewallgroup_id):
        """Formatted URL path UniFI firewall group."""
        return f"/proxy/network/api/s/{site}/rest/firewallgroup/{firewallgroup_id}"
