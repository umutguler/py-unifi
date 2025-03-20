"""
High-level UniFi API that exposes domain-specific operations.
"""
from py_abstractions.rest import Delete, Get, Post, Put
from py_dns import DDNS
from py_unifi.client import UnifiClient
from py_unifi.constants import UnifiConstants


class UnifiApi(Get, Post, Put, Delete):
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
        return self.client.auth.logout()

    def get(self, resource, data=None):
        """
        Perform a GET request to the specified resource with optional data (query params).
        """
        return self.client.get(resource, data)

    def post(self, resource, data=None):
        """
        Perform a POST request to the specified resource with optional data.
        """
        return self.client.post(resource, data)

    def put(self, resource, data=None):
        """
        Perform a PUT request to the specified resource with optional data.
        """
        return self.client.put(resource, data)

    def delete(self, resource, data=None):
        """
        Perform a DELETE request to the specified resource with optional data.
        """
        return self.client.delete(resource, data)

    # Domain-specific example:
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

        return self.put(path, payload)
