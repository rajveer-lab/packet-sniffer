"""The devices on the local network, as seen in their own traffic.

Every frame carries its sender's MAC address. For each MAC this keeps:

    addresses   the IPs it uses on this network (from ARP and its own packets)
    name        the name it gives itself when it asks DHCP for an address
    maker       the company the first half of the MAC is registered to
                (Scapy's copy of the IEEE list), e.g. Apple, Samsung, TP-Link
    traffic     packets and bytes it sent, first and last time seen

Phones and laptops often use a made-up ("randomised") MAC for privacy; those
have no maker and are labelled as such. This computer and the router are
marked. Only devices on the same network segment can be seen this way: traffic
from the internet arrives with the router's MAC.
"""

import ipaddress
import threading

# Address ranges that only exist inside a local network (RFC 1918, link-local, IPv6 unique-local)
LAN_RANGES = [ipaddress.ip_network(n) for n in
              ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def is_lan_address(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in LAN_RANGES)


def normalize_mac(mac):
    return str(mac).lower().replace("-", ":")


def is_unicast(mac):
    try:
        return not int(mac[:2], 16) & 1
    except (TypeError, ValueError):
        return False


def is_randomised(mac):
    """Locally administered MACs (second hex digit 2, 6, A or E) are made up by the device."""
    return mac[1:2].lower() in ("2", "6", "a", "e")


def maker(mac):
    if is_randomised(mac):
        return "Private (randomised) address"
    try:
        from scapy.config import conf

        name = conf.manufdb._get_manuf(mac)
    except Exception:
        return None
    return None if not name or name.lower() == mac.lower() else name


class DeviceTable:
    def __init__(self, own_macs=(), router_ip=None, max_devices=500):
        self.own_macs = {normalize_mac(m) for m in own_macs if m}
        self.router_ip = router_ip
        self.max_devices = max_devices
        self._devices = {}
        self._lock = threading.Lock()

    def update(self, record):
        mac = record.get("src_mac")
        if mac and is_unicast(mac):
            mac = normalize_mac(mac)
            with self._lock:
                device = self._device(mac, record["time"])
                if device is None:
                    return
                device["packets"] += 1
                device["bytes"] += record["length"]
                device["last_seen"] = record["time"]
                ip = record.get("src")
                if ip and ip != "0.0.0.0" and is_lan_address(ip):
                    device["addresses"].add(ip)
                if record.get("dhcp_hostname") and record.get("dhcp_type") in ("discover", "request", "inform"):
                    device["name"] = record["dhcp_hostname"]
        # A DHCP answer tells which address the asking device was given
        client = record.get("dhcp_client_mac")
        if client and record.get("dhcp_type") == "ack" and record.get("dhcp_offer"):
            with self._lock:
                device = self._device(normalize_mac(client), record["time"])
                if device is not None:
                    device["addresses"].add(record["dhcp_offer"])

    def devices(self):
        with self._lock:
            found = [dict(d, addresses=sorted(d["addresses"])) for d in self._devices.values()]
        for d in found:
            d["is_router"] = bool(self.router_ip and self.router_ip in d["addresses"])
        return sorted(found, key=lambda d: d["last_seen"], reverse=True)

    def _device(self, mac, now):
        device = self._devices.get(mac)
        if device is None:
            if len(self._devices) >= self.max_devices:
                return None
            device = self._devices[mac] = {
                "mac": mac, "maker": maker(mac), "name": None, "addresses": set(), "packets": 0, "bytes": 0,
                "first_seen": now, "last_seen": now, "is_this_computer": mac in self.own_macs,
            }
        return device


def own_macs():
    """MAC addresses of this computer's network adapters."""
    try:
        import psutil

        return [a.address for addrs in psutil.net_if_addrs().values() for a in addrs
                if a.family == psutil.AF_LINK and a.address]
    except Exception:
        return []
