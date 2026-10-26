"""Put names on IP addresses by watching DNS answers (passive DNS).

Before a program connects to www.example.com it asks DNS for the address, and
the answer crosses the network like any other packet:

    DNS answer  www.example.com = 93.184.215.14

The sniffer remembers that pairing, so later packets to 93.184.215.14 can be
shown as www.example.com. Nothing extra is sent on the network; the name is the
one the program itself asked for (not a reverse lookup). The newest
``max_names`` pairings are kept.
"""

import threading
from collections import OrderedDict

from scapy.layers.dns import DNS

ADDRESS_TYPES = (1, 28)   # A (IPv4) and AAAA (IPv6) records


def records(field):
    """DNS questions or answers as a list, whichever way this Scapy version stores them."""
    if not field:
        return []
    if isinstance(field, list):
        return list(field)
    found, layer = [], field          # older Scapy: records chained one after another
    while layer is not None and (hasattr(layer, "rrname") or hasattr(layer, "qname")):
        found.append(layer)
        layer = layer.payload if layer.payload else None
    return found


def label(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw).rstrip(".")


class NameCache:
    def __init__(self, max_names=5000):
        self.max_names = max_names
        self._names = OrderedDict()   # ip -> name, oldest first
        self._lock = threading.Lock()

    def learn(self, pkt):
        """Remember the addresses in a DNS answer, under the name that was asked for."""
        if DNS not in pkt or not pkt[DNS].qr:
            return
        dns = pkt[DNS]
        questions = records(dns.qd)
        asked = label(questions[0].qname) if questions else None
        for answer in records(dns.an):
            if getattr(answer, "type", None) in ADDRESS_TYPES:
                self._remember(str(answer.rdata), asked or label(answer.rrname))

    def remember(self, ip, name):
        """Name an address learned some other way, e.g. from the site name of an HTTPS connection."""
        if ip and name:
            self._remember(ip, name)

    def name(self, ip):
        if ip is None:
            return None
        with self._lock:
            return self._names.get(ip)

    def __len__(self):
        return len(self._names)

    def _remember(self, ip, name):
        with self._lock:
            self._names[ip] = name
            self._names.move_to_end(ip)
            while len(self._names) > self.max_names:
                self._names.popitem(last=False)
