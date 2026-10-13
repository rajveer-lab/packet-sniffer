"""Security checks run on every decoded packet.

Each rule watches a short sliding window of traffic and raises an alert when
a pattern typical of an attack, or of an unsafe setup, shows up:

    Port scan       one source probes many ports on one host
                    (TCP SYN, FIN, NULL and Xmas probes, or UDP)
    Host sweep      one source pings or ARP-probes many addresses
    SYN flood       a burst of connection requests at one server port
    ARP spoofing    an IP address starts answering from a different MAC,
                    the first step of a man-in-the-middle attack
    Cleartext       Telnet, FTP, POP3, IMAP or HTTP, which carry passwords
                    and data unencrypted

The same rule firing again for the same source updates the open alert (its
count and detail) instead of adding a new one, until it has been quiet for
``cooldown`` seconds. Windows use the packets' own timestamps, so a replayed
capture gives the same alerts as the live traffic did.
"""

import threading
from collections import Counter, OrderedDict, deque
from itertools import islice

# Server ports of protocols that send logins and data in clear text
CLEARTEXT = {
    21: ("FTP", "medium"),
    23: ("Telnet", "medium"),
    80: ("HTTP", "low"),
    110: ("POP3", "medium"),
    143: ("IMAP", "medium"),
}

SEVERITIES = ("high", "medium", "low")


def is_tcp_probe(record):
    """A TCP packet that opens or probes a port: no ACK (and not a reset).

    Covers SYN (normal connect or half-open scan) and the FIN, NULL and Xmas
    stealth scans. Every packet of an established connection carries ACK.
    """
    flags = record["flags"]
    return record["proto"] == "TCP" and "ACK" not in flags and "RST" not in flags


def is_udp_probe(record):
    # Replies come *from* a well-known port (DNS answers from 53, QUIC from 443),
    # so only traffic from a high client port counts as probing.
    return record["proto"] == "UDP" and record["sport"] is not None and record["sport"] >= 1024


class SecurityMonitor:
    def __init__(self, scan_ports=15, sweep_hosts=10, window=10,
                 flood_syns=100, flood_window=5, cooldown=60, max_alerts=200):
        self.scan_ports = scan_ports
        self.sweep_hosts = sweep_hosts
        self.window = window
        self.flood_syns = flood_syns
        self.flood_window = flood_window
        self.cooldown = cooldown

        self._lock = threading.Lock()
        self._alerts = deque(maxlen=max_alerts)
        self._open = {}                 # (rule, key) -> alert still within its cooldown
        self._last_id = 0
        self._ports = {}                # (src, dst) -> OrderedDict port -> last seen
        self._targets = {}              # src -> OrderedDict address -> last seen
        self._syns = {}                 # (dst, port) -> deque of SYN times
        self._arp = {}                  # IP -> MAC it last claimed
        self._next_cleanup = None
        self.checked = 0

        self.rules = [
            {"rule": "port_scan", "name": "Port scan", "severity": "high",
             "description": f"one source probes {scan_ports}+ ports on a host within {window} s"},
            {"rule": "host_sweep", "name": "Host sweep", "severity": "medium",
             "description": f"one source pings or ARP-probes {sweep_hosts}+ addresses within {window} s"},
            {"rule": "syn_flood", "name": "SYN flood", "severity": "high",
             "description": f"{flood_syns}+ connection requests to one port within {flood_window} s"},
            {"rule": "arp_spoof", "name": "ARP spoofing", "severity": "high",
             "description": "an IP address starts answering from a different MAC address"},
            {"rule": "cleartext", "name": "Cleartext protocols", "severity": "medium",
             "description": "Telnet, FTP, POP3, IMAP or HTTP send passwords and data unencrypted"},
        ]

    def inspect(self, record):
        """Run every rule on one packet record."""
        with self._lock:
            self.checked += 1
            now = record["time"]
            self._check_port_scan(record, now)
            self._check_host_sweep(record, now)
            self._check_syn_flood(record, now)
            self._check_arp_spoof(record, now)
            self._check_cleartext(record, now)
            if self._next_cleanup is None or now >= self._next_cleanup:
                self._cleanup(now)
                self._next_cleanup = now + self.window

    def summary(self, limit=50):
        """Newest alerts first, alert counts by severity and by rule."""
        with self._lock:
            alerts = [dict(a) for a in islice(reversed(self._alerts), limit)]
            by_severity = Counter(a["severity"] for a in self._alerts)
            by_rule = Counter(a["rule"] for a in self._alerts)
            return {
                "alerts": alerts,
                "counts": {s: by_severity[s] for s in SEVERITIES},
                "rules": [dict(r, alerts=by_rule[r["rule"]]) for r in self.rules],
                "checked": self.checked,
            }

    # ---- rules -------------------------------------------------------------

    def _check_port_scan(self, r, now):
        if r["dst"] is None or r["dport"] is None or not (is_tcp_probe(r) or is_udp_probe(r)):
            return
        ports = self._remember(self._ports, (r["src"], r["dst"]), r["dport"], now, self.window)
        if ports >= self.scan_ports:
            kind = "UDP" if r["proto"] == "UDP" else "TCP"
            self._alert("port_scan", "high", (r["src"], r["dst"]), now,
                        title=f"Port scan from {r['src']}",
                        detail=f"{ports} {kind} ports probed on {r['dst']} within {self.window} s",
                        src=r["src"], dst=r["dst"], focus=r["src"])

    def _check_host_sweep(self, r, now):
        ping = r["proto"] == "ICMP" and r.get("icmp_type") == 8
        arp_probe = r["proto"] == "ARP" and r.get("arp_op") == 1 and r["src"] != "0.0.0.0"
        if not (ping or arp_probe) or r["dst"] is None:
            return
        targets = self._remember(self._targets, r["src"], r["dst"], now, self.window)
        if targets >= self.sweep_hosts:
            how = "pinged" if ping else "ARP-probed"
            self._alert("host_sweep", "medium", r["src"], now,
                        title=f"Host sweep from {r['src']}",
                        detail=f"{targets} addresses {how} within {self.window} s",
                        src=r["src"], dst=None, focus=r["src"])

    def _check_syn_flood(self, r, now):
        if r["proto"] != "TCP" or r["flags"] != ["SYN"] or r["dst"] is None:
            return
        key = (r["dst"], r["dport"])
        times = self._syns.setdefault(key, deque())
        times.append(now)
        while times[0] < now - self.flood_window:
            times.popleft()
        if len(times) >= self.flood_syns:
            self._alert("syn_flood", "high", key, now,
                        title=f"SYN flood at {r['dst']}:{r['dport']}",
                        detail=f"{len(times)} connection requests within {self.flood_window} s",
                        src=None, dst=r["dst"], focus=r["dst"])

    def _check_arp_spoof(self, r, now):
        if r["proto"] != "ARP" or not r.get("arp_mac") or r["src"] in (None, "0.0.0.0"):
            return
        ip, mac = r["src"], r["arp_mac"].lower()
        known = self._arp.get(ip)
        self._arp[ip] = mac
        if known and known != mac:
            self._alert("arp_spoof", "high", ip, now,
                        title=f"ARP spoofing of {ip}",
                        detail=f"{ip} moved from {known} to {mac}; traffic for it may be intercepted",
                        src=mac, dst=ip, focus=mac)

    def _check_cleartext(self, r, now):
        # PSH means the client actually sent data; a scan's bare SYN to port 23 does not count.
        if r["proto"] != "TCP" or r["dport"] not in CLEARTEXT or "PSH" not in r["flags"]:
            return
        name, severity = CLEARTEXT[r["dport"]]
        self._alert("cleartext", severity, (name, r["src"]), now,
                    title=f"Unencrypted {name} from {r['src']}",
                    detail=f"{name} to {r['dst']}:{r['dport']} sends logins and data in clear text",
                    src=r["src"], dst=r["dst"], focus=r["src"])

    # ---- helpers -----------------------------------------------------------

    @staticmethod
    def _remember(table, key, item, now, window):
        """Record ``item`` under ``key``; return how many distinct items were seen in the window."""
        seen = table.setdefault(key, OrderedDict())
        seen[item] = now
        seen.move_to_end(item)
        while next(iter(seen.values())) < now - window:
            seen.popitem(last=False)
        return len(seen)

    def _alert(self, rule, severity, key, now, title, detail, src, dst, focus):
        alert = self._open.get((rule, key))
        if alert and now - alert["last_seen"] < self.cooldown:
            alert.update(last_seen=now, count=alert["count"] + 1, detail=detail)
            return
        self._last_id += 1
        alert = {"id": self._last_id, "rule": rule, "severity": severity, "title": title,
                 "detail": detail, "src": src, "dst": dst, "focus": focus,
                 "time": now, "last_seen": now, "count": 1}
        self._alerts.append(alert)
        self._open[(rule, key)] = alert

    def _cleanup(self, now):
        """Drop tracking state that has gone quiet, so memory stays bounded."""
        for table in (self._ports, self._targets):
            for key in [k for k, seen in table.items() if next(reversed(seen.values())) < now - self.window]:
                del table[key]
        for key in [k for k, times in self._syns.items() if times[-1] < now - self.flood_window]:
            del self._syns[key]
        for key in [k for k, a in self._open.items() if now - a["last_seen"] >= self.cooldown]:
            del self._open[key]
