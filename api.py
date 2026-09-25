"""
High-level UniFi API that exposes domain-specific operations.
"""
import py_logging
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
                 verify_ssl=True, service_name="UnifiApiClientToken", api_key=None):
        self.site = site
        self.client = UnifiClient(
            base_url,
            username or "",
            password or "",
            verify_ssl,
            service_name,
            api_key
        )

    def logout(self):
        """
        Log out of the UniFi Firewall API.
        """
        logging.info("Logging out of the UniFi Firewall API")
        return self.client.auth.logout()

    def update_firewall_group(self, data):
        """Set the members of the one address group named or ID'd by data["firewallgroup"]
        to the IPv4 addresses that data["hosts"] (hostnames, URLs or IPs) resolve to.
        Idempotent: only PUTs when the members changed. Returns the PUT response, or None if unchanged.
        Only ever writes that group's members; raises LookupError or ValueError, writing nothing,
        if the group is missing, ambiguous or not an address group, or any host fails to resolve."""
        hosts = data["hosts"]
        if not hosts:
            raise ValueError("No hosts given; refusing to empty the firewall group.")
        resolved = DDNS.bulk_get_ipv4(hosts)
        unresolved = [host for host, ip in zip(hosts, resolved) if ip is None]
        if unresolved:
            # Never push a partial list: an allow list would silently lose hosts.
            raise LookupError(f"Could not resolve {unresolved}; firewall group left unchanged.")
        members = sorted(set(resolved))

        wanted = data["firewallgroup"]
        groups = self.client.get(UnifiConstants.get_firewallgroup_path(self.site))["data"]
        matches = [g for g in groups if wanted in (g["_id"], g["name"])]
        if len(matches) != 1:
            raise LookupError(f"Expected exactly one firewall group named or with ID '{wanted}', "
                              f"found {len(matches)}.")
        group = matches[0]
        if group["group_type"] != "address-group":
            raise ValueError(f"Firewall group '{group['name']}' is a {group['group_type']}, "
                             "not an IPv4 address group.")

        if sorted(group["group_members"]) == members:
            logging.debug("Firewall group '%s' already up to date: %s", group["name"], members)
            return None

        logging.info("Updating firewall group '%s': %s -> %s",
                     group["name"], group["group_members"], members)
        return self.client.put(UnifiConstants.get_firewallgroup_path(self.site, group["_id"]),
                               {**group, "group_members": members})
