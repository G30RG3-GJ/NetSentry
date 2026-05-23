import routeros_api
import os
import logging
import socket
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Socket errors that indicate a dead connection and require reconnect
_DEAD_SOCKET_ERRORS = ("WinError 10038", "WinError 10054", "WinError 10053", 
                       "Broken pipe", "Connection reset", "EOF occurred",
                       "ConnectionResetError", "timed out")

class MikroTikClient:
    def __init__(self):
        self.host = os.getenv('MIKROTIK_HOST', '192.168.88.1')
        self.username = os.getenv('MIKROTIK_USER', 'admin')
        self.password = os.getenv('MIKROTIK_PASSWORD', '')
        self.port = int(os.getenv('MIKROTIK_PORT', 8728))
        self.use_ssl = os.getenv('MIKROTIK_USE_SSL', 'False').lower() in ('true', '1', 't')
        self.connection = None
        self.api = None

    def connect(self) -> bool:
        try:
            self.disconnect()
            self.connection = routeros_api.RouterOsApiPool(
                self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                use_ssl=self.use_ssl,
                plaintext_login=True
            )
            self.api = self.connection.get_api()
            logger.info(f"Connected to MikroTik at {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self.api = None
            self.connection = None
            return False

    def disconnect(self):
        try:
            if self.connection:
                self.connection.disconnect()
        except Exception:
            pass
        finally:
            self.api = None
            self.connection = None

    def _is_dead_socket(self, e: Exception) -> bool:
        """Check if the exception is due to a dead/closed socket."""
        err_str = str(e)
        return any(err in err_str for err in _DEAD_SOCKET_ERRORS)

    def _safe_get(self, resource_path: str, default=None, label: str = ""):
        """Safely get a resource, auto-reconnecting on socket death."""
        if default is None:
            default = []
        if not self.api:
            if not self.connect():
                return default
        try:
            return self.api.get_resource(resource_path).get()
        except Exception as e:
            if self._is_dead_socket(e):
                logger.warning(f"Dead socket detected for {label}, reconnecting...")
                self.disconnect()
            elif "no such item" not in str(e):
                logger.error(f"Error fetching {label}: {e}")
            return default

    # ── Core System ──────────────────────────────────────────────────────────

    def get_identity(self) -> str:
        data = self._safe_get('/system/identity', default=[{}], label="identity")
        return data[0].get('name', 'Unknown') if data else 'Unknown'

    def get_resources(self) -> Dict[str, Any]:
        data = self._safe_get('/system/resource', default=[{}], label="resources")
        return data[0] if data else {}

    def get_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        data = self._safe_get('/log', label="logs")
        return data[-limit:]

    def get_packages(self) -> List[Dict[str, Any]]:
        return self._safe_get('/system/package', label="packages")

    def get_scripts(self) -> List[Dict[str, Any]]:
        return self._safe_get('/system/script', label="scripts")

    def get_schedulers(self) -> List[Dict[str, Any]]:
        return self._safe_get('/system/scheduler', label="schedulers")

    def get_system_health(self) -> Dict[str, Any]:
        """Fetch hardware health (voltage, temperature) if available."""
        data = self._safe_get('/system/health', default=[{}], label="health")
        return data[0] if data else {}

    def reboot(self) -> bool:
        if not self.api:
            if not self.connect():
                return False
        try:
            self.api.get_resource('/system').call('reboot')
            self.disconnect()
            return True
        except Exception as e:
            logger.info(f"Reboot sent (connection drop expected): {e}")
            self.disconnect()
            return True

    def export_config(self) -> str:
        if not self.api:
            if not self.connect():
                return ""
        try:
            res = self.api.get_resource('/').call('export')
            config = ""
            for item in res:
                for key, val in item.items():
                    if val and isinstance(val, str):
                        config += val + "\n"
            return config
        except Exception as e:
            logger.error(f"Error exporting config: {e}")
            return ""

    # ── Interfaces & Traffic ─────────────────────────────────────────────────

    def get_interfaces(self) -> List[Dict[str, Any]]:
        return self._safe_get('/interface', label="interfaces")

    def get_interface_wireless(self) -> List[Dict[str, Any]]:
        return self._safe_get('/interface/wireless', label="wireless interfaces")

    def get_wireless_clients(self) -> List[Dict[str, Any]]:
        """Get connected wireless clients (station registrations)."""
        return self._safe_get('/interface/wireless/registration-table', label="wireless clients")

    def get_bridge_hosts(self) -> List[Dict[str, Any]]:
        """Get bridge host (MAC) table."""
        return self._safe_get('/interface/bridge/host', label="bridge hosts")

    # ── IP / Routing ─────────────────────────────────────────────────────────

    def get_arp_table(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/arp', label="ARP")

    def get_routes(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/route', label="Routes")

    def get_neighbors(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/neighbor', label="Neighbors")

    def get_dhcp_leases(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/dhcp-server/lease', label="DHCP leases")

    def get_dhcp_server(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/dhcp-server', label="DHCP server")

    def get_ip_addresses(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/address', label="IP addresses")

    def get_ip_pools(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/pool', label="IP pools")

    def get_dns_cache(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/dns/cache', label="DNS cache")

    def get_ip_services(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/service', label="IP services")

    def get_ping_latency(self, target: str = "8.8.8.8") -> str:
        if not self.api:
            if not self.connect():
                return "0"
        try:
            base_res = self.api.get_resource('/')
            result = base_res.call('ping', {'address': target, 'count': '1'})
            if result and len(result) > 0:
                return result[0].get('time', '0ms').replace('ms', '')
            return "0"
        except Exception as e:
            if self._is_dead_socket(e):
                self.disconnect()
            return "0"

    # ── Firewall ─────────────────────────────────────────────────────────────

    def get_firewall_connections(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not self.api:
            if not self.connect():
                return []
        try:
            conns = self.api.get_resource('/ip/firewall/connection').get()
            return conns[:limit]
        except Exception as e:
            if self._is_dead_socket(e):
                self.disconnect()
            elif "no such item" not in str(e):
                logger.error(f"Error fetching connections: {e}")
            return []

    def get_firewall_filters(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/firewall/filter', label="firewall filters")

    def get_nat_rules(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/firewall/nat', label="NAT rules")

    def get_mangle_rules(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/firewall/mangle', label="mangle rules")

    def get_address_lists(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/firewall/address-list', label="address lists")

    def block_ip(self, ip_address: str, comment: str = "Blocked by NetSentry") -> bool:
        if not self.api:
            if not self.connect():
                return False
        try:
            address_list = self.api.get_resource('/ip/firewall/address-list')
            address_list.add(list="NetSentry_Blocklist", address=ip_address, comment=comment)
            logger.info(f"Blocked IP: {ip_address}")
            return True
        except Exception as e:
            if self._is_dead_socket(e):
                self.disconnect()
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False

    # ── VPN / PPP ─────────────────────────────────────────────────────────────

    def get_active_vpns(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ppp/active', label="active VPNs")

    def get_ppp_secrets(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ppp/secret', label="PPP secrets")

    # ── Hotspot ───────────────────────────────────────────────────────────────

    def get_hotspot_active(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/hotspot/active', label="hotspot active")

    def get_hotspot_users(self) -> List[Dict[str, Any]]:
        return self._safe_get('/ip/hotspot/user', label="hotspot users")

    # ── Queues / QoS ─────────────────────────────────────────────────────────

    def get_simple_queues(self) -> List[Dict[str, Any]]:
        return self._safe_get('/queue/simple', label="simple queues")

    def get_queue_tree(self) -> List[Dict[str, Any]]:
        return self._safe_get('/queue/tree', label="queue tree")

    # ── System Users ──────────────────────────────────────────────────────────

    def get_system_users(self) -> List[Dict[str, Any]]:
        return self._safe_get('/user', label="users")

    def get_active_users(self) -> List[Dict[str, Any]]:
        """Get users currently logged into the router."""
        return self._safe_get('/user/active', label="active users")
