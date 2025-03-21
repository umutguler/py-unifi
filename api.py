"""
High-level UniFi API that exposes domain-specific operations.
"""
import py_logging
from py_abstractions.rest import Delete, Get, Post, Put
from py_dns import DDNS
from py_unifi.client import UnifiClient
from py_unifi.constants import UnifiConstants

logging = py_logging.get_logger(__name__)


class UnifiApi:
    """
    High-level UniFi API that provides domain-specific operations.
    For CRUD-like operations, we map get/post/put/delete to the underlying UnifiClient.
    """

    def __init__(self, base_url, username=None, password=None, site="default",
                 verify_ssl=False, service_name="UnifiApiClientToken"):
        self.site = site
        self.client = UnifiClient(
            base_url,
            username or "",
            password or "",
            verify_ssl,
            service_name
        )

    def logout(self):
        """
        Log out of the UniFi Firewall API.
        """
        logging.info("Logging out of the UniFi Firewall API")
        return self.client.auth.logout()

    def update_firewall_group(self, data):
        """Convenience method to update a firewall group."""
        path = UnifiConstants.get_firewallgroup_path(
            self.site, data["firewallgroup"])

        print(data["title"])
        print(data["firewallgroup"])
        payload = {
            "name": data["title"],
            "group_type": "address-group",
            "group_members": DDNS.bulk_get_ipv4(data["hosts"]),
            "site_id": "660ab0a2f11c12313f8c6f56",
            "_id": data["firewallgroup"]
        }

        logging.info("Updating firewall group.")
        logging.info("Firewall Rule: %s", payload['name'])
        logging.info("IP Addresses: %s", payload['group_members'])
        return self.client.put(path, payload)
