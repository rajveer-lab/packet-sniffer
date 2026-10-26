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
    Brute force     one source keeps opening connections to a login service
                    (SSH, RDP, FTP, Telnet, SMB, VNC, databases), guessing passwords
    Passwords       a password actually crosses the network in clear text
                    (FTP/POP3 PASS, IMAP LOGIN, HTTP Basic auth or a login form,
                    a Telnet password prompt); the alert never shows the password
    Bad domain      a program looks up a domain on the blocklist
    DNS tunneling   data hidden in DNS names: very long labels, or many random
                    subdomains of one domain in a minute
    Unusual upload  this computer sends a large amount to one outside address
    Rogue DHCP      a second DHCP server answers; it could make itself your
                    router or DNS server
    ICMP redirect   a device tells this computer to send traffic another way

Every alert also says which fix applies, if the computer can protect itself
(see core/defense.py): blocking the attacker's IP, pinning the real MAC of a
spoofed address, or blocking a cleartext protocol.

The same rule firing again for the same source updates the open alert (its
count and detail) instead of adding a new one, until it has been quiet for
``cooldown`` seconds. Windows use the packets' own timestamps, so a replayed
capture gives the same alerts as the live traffic did.
"""

import base64
import ipaddress
import os
import re
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

# Login services that attackers try passwords against, by server port
LOGIN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
}

# Cleartext protocols whose payload is searched for passwords, by server port
CREDENTIAL_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 8080: "HTTP"}

PASS_COMMAND = re.compile(rb"^PASS (.+?)\r?$", re.I | re.M)                  # FTP, POP3
USER_COMMAND = re.compile(rb"^USER (.+?)\r?$", re.I | re.M)
IMAP_LOGIN = re.compile(rb'^\S+ LOGIN "?([^\s"]+)"? "?([^\s"]+)"?', re.I | re.M)
BASIC_AUTH = re.compile(rb"^Authorization: Basic ([A-Za-z0-9+/=]+)", re.I | re.M)
FORM_PASSWORD = re.compile(rb"(?:^|&)(?:password|passwd|pass|pwd)=([^&\s]+)", re.I | re.M)
FORM_USER = re.compile(rb"(?:^|&)(?:username|user|login|email)=([^&\s]+)", re.I | re.M)

SEVERITIES = ("high", "medium", "low")

BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt")


def load_blocklist(path=BLOCKLIST_FILE):
    """Domains from a file: one per line, or hosts-file lines like '0.0.0.0 bad.example'."""
    domains = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                domains.append(line.split()[-1])
    return domains


LONG_LABEL = 50          # a DNS label this long hides data; real names almost never need it
RANDOM_LABEL = 20        # labels at least this long count towards the many-subdomains check


def is_local_address(ip):
    """A private, link-local or loopback address: this computer or its own network."""
    try:
        address = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return address.is_private or address.is_link_local or address.is_loopback


def is_outside_address(ip):
    try:
        address = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return address.is_global and not address.is_multicast


def is_tcp_probe(record):
    """A TCP packet that opens or probes a port: no ACK (and not a reset).

    Covers SYN (normal connect or half-open scan) and the FIN, NULL and Xmas
    stealth scans. Every packet of an established connection carries ACK.
    """
    flags = record["flags"]
    return record["proto"] == "TCP" and "ACK" not in flags and "RST" not in flags


def block_port_fix(service, port):
    """Block a cleartext protocol going out. Not offered for HTTP: half the web still uses it."""
    if service == "HTTP":
        return None
    return {"action": "block_port", "port": port, "protocol": "TCP", "service": service}


def describe_secret(secret):
    """Say how long a captured password is, never what it is."""
    n = len(secret)
    article = "an" if str(n).startswith("8") or n in (11, 18) else "a"
    return f"{article} {n}-character password"


def text(raw):
    return raw.decode("utf-8", "replace").strip()


def is_udp_probe(record):
    # Replies come *from* a well-known port (DNS answers from 53, QUIC from 443),
    # so only traffic from a high client port counts as probing.
    return record["proto"] == "UDP" and record["sport"] is not None and record["sport"] >= 1024


class SecurityMonitor:
    def __init__(self, scan_ports=15, sweep_hosts=10, window=10,
                 flood_syns=100, flood_window=5, brute_attempts=20, brute_window=60,
                 cooldown=60, max_alerts=200, blocklist=None, upload_mb=50, upload_window=60,
                 tunnel_subdomains=25, tunnel_window=60):
        self.scan_ports = scan_ports
        self.sweep_hosts = sweep_hosts
        self.window = window
        self.flood_syns = flood_syns
        self.flood_window = flood_window
        self.brute_attempts = brute_attempts
        self.brute_window = brute_window
        self.cooldown = cooldown
        if blocklist is None:
            blocklist = load_blocklist()
        self.blocklist = {d.strip().lower().rstrip(".") for d in blocklist if d.strip()}
        self.upload_bytes = int(upload_mb * 1024 * 1024)
        self.upload_window = upload_window
        self.tunnel_subdomains = tunnel_subdomains
        self.tunnel_window = tunnel_window

        self._lock = threading.Lock()
        self._alerts = deque(maxlen=max_alerts)
        self._open = {}                 # (rule, key) -> alert still within its cooldown
        self._last_id = 0
        self._ports = {}                # (src, dst) -> OrderedDict port -> last seen
        self._targets = {}              # src -> OrderedDict address -> last seen
        self._syns = {}                 # (dst, port) -> deque of SYN times
        self._arp = {}                  # IP -> MAC it last claimed
        self._logins = {}               # (src, dst, port) -> deque of connection attempt times
        self._users = {}                # connection -> (user name, last seen) from USER commands
        self._prompted = {}             # Telnet connection -> (typed bytes, last seen) after "Password:"
        self._uploads = {}              # (src, dst) -> [deque of (time, bytes), running total]
        self._subdomains = {}           # (src, domain) -> OrderedDict long label -> last seen
        self._dhcp_server = None        # the first DHCP server seen answering
        self._next_cleanup = None
        self.checked = 0
        self.on_alert = None            # optional callback for every new alert, e.g. auto-block

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
            {"rule": "brute_force", "name": "Brute-force login", "severity": "high",
             "description": f"one source opens {brute_attempts}+ connections to SSH, RDP, FTP or another "
                            f"login service within {brute_window} s"},
            {"rule": "credentials", "name": "Password in clear text", "severity": "high",
             "description": "a password is sent unencrypted over FTP, POP3, IMAP, Telnet or HTTP"},
            {"rule": "bad_domain", "name": "Blocklisted domain", "severity": "high",
             "description": f"a program looks up one of {len(self.blocklist)} domains on the blocklist"},
            {"rule": "dns_tunnel", "name": "DNS tunneling", "severity": "medium",
             "description": f"DNS names hide data: labels of {LONG_LABEL}+ characters, or {tunnel_subdomains}+ "
                            f"random subdomains of one domain within {tunnel_window} s"},
            {"rule": "large_upload", "name": "Unusual upload", "severity": "medium",
             "description": f"this computer sends {upload_mb:g}+ MB to one outside address within {upload_window} s"},
            {"rule": "rogue_dhcp", "name": "Rogue DHCP server", "severity": "high",
             "description": "a second DHCP server answers; it could make itself your router or DNS server"},
            {"rule": "icmp_redirect", "name": "ICMP redirect", "severity": "medium",
             "description": "a device tells this computer to send traffic through a different router"},
        ]

    @staticmethod
    def wants_payload(record):
        """Whether ``inspect`` needs this packet's TCP payload (to look for passwords)."""
        return record["proto"] == "TCP" and (record["dport"] in CREDENTIAL_PORTS or
                                             record["sport"] in CREDENTIAL_PORTS)

    def inspect(self, record, payload=b""):
        """Run every rule on one packet record (and its TCP payload, if given)."""
        with self._lock:
            self.checked += 1
            now = record["time"]
            self._check_port_scan(record, now)
            self._check_host_sweep(record, now)
            self._check_syn_flood(record, now)
            self._check_arp_spoof(record, now)
            self._check_cleartext(record, now)
            self._check_brute_force(record, now)
            self._check_dns(record, now)
            self._check_upload(record, now)
            self._check_dhcp(record, now)
            self._check_redirect(record, now)
            if payload:
                self._check_credentials(record, payload, now)
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

    def get(self, alert_id):
        """One alert by id (a copy), or None if it is unknown or too old."""
        with self._lock:
            for alert in self._alerts:
                if alert["id"] == alert_id:
                    return dict(alert)
        return None

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
                        src=r["src"], dst=r["dst"], focus=r["src"],
                        fix={"action": "block_ip", "ip": r["src"]})

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
                        src=r["src"], dst=None, focus=r["src"],
                        fix={"action": "block_ip", "ip": r["src"]})

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
                        src=mac, dst=ip, focus=mac,
                        fix={"action": "pin_arp", "ip": ip, "mac": known})

    def _check_cleartext(self, r, now):
        # PSH means the client actually sent data; a scan's bare SYN to port 23 does not count.
        if r["proto"] != "TCP" or r["dport"] not in CLEARTEXT or "PSH" not in r["flags"]:
            return
        name, severity = CLEARTEXT[r["dport"]]
        used_by = f", used by {r['app']}" if r.get("app") else ""
        self._alert("cleartext", severity, (name, r["src"]), now,
                    title=f"Unencrypted {name} from {r['src']}",
                    detail=f"{name} to {r['dst']}:{r['dport']} sends logins and data in clear text{used_by}",
                    src=r["src"], dst=r["dst"], focus=r["src"],
                    fix=block_port_fix(name, r["dport"]))

    def _check_dns(self, r, now):
        name = r.get("dns_query")
        if not name or r["dport"] != 53:     # queries only, so each lookup counts once
            return
        name = name.lower().rstrip(".")
        labels = name.split(".")
        by = f" ({r['app']})" if r.get("app") else ""
        for i in range(len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in self.blocklist:
                self._alert("bad_domain", "high", (r["src"], parent), now,
                            title=f"Blocklisted domain {parent}",
                            detail=f"{r['src']}{by} looked up {name}, which is on the blocklist",
                            src=r["src"], dst=r["dst"], focus=r["src"])
                break
        domain = ".".join(labels[-2:])
        longest = max(labels, key=len)
        if len(longest) >= LONG_LABEL:
            self._alert("dns_tunnel", "medium", (r["src"], domain), now,
                        title=f"Possible DNS tunneling to {domain}",
                        detail=f"{r['src']}{by} looked up a name with a {len(longest)}-character label; "
                               f"data can be hidden in names like that",
                        src=r["src"], dst=r["dst"], focus=r["src"])
        elif len(labels) >= 3 and len(labels[0]) >= RANDOM_LABEL:
            count = self._remember(self._subdomains, (r["src"], domain), labels[0], now, self.tunnel_window)
            if count >= self.tunnel_subdomains:
                self._alert("dns_tunnel", "medium", (r["src"], domain), now,
                            title=f"Possible DNS tunneling to {domain}",
                            detail=f"{r['src']}{by} looked up {count} different random-looking names under "
                                   f"{domain} within {self.tunnel_window} s",
                            src=r["src"], dst=r["dst"], focus=r["src"])

    def _check_upload(self, r, now):
        if not (is_local_address(r["src"]) and is_outside_address(r["dst"])):
            return
        entry = self._uploads.setdefault((r["src"], r["dst"]), [deque(), 0])
        size = r.get("length", 0)
        sent, entry[1] = entry[0], entry[1] + size
        sent.append((now, size))
        while sent[0][0] < now - self.upload_window:
            entry[1] -= sent.popleft()[1]
        if entry[1] >= self.upload_bytes:
            name = r.get("dst_name")
            to = f"{r['dst']} ({name})" if name else r["dst"]
            by = f" by {r['app']}" if r.get("app") else ""
            self._alert("large_upload", "medium", (r["src"], r["dst"]), now,
                        title=f"Unusual upload to {to}",
                        detail=f"{entry[1] / 1024 / 1024:.0f} MB sent within {self.upload_window} s{by}",
                        src=r["src"], dst=r["dst"], focus=r["dst"],
                        fix={"action": "block_ip", "ip": r["dst"]})

    def _check_dhcp(self, r, now):
        if r.get("dhcp_type") not in ("offer", "ack"):
            return
        server = r.get("dhcp_server") or r["src"]
        if self._dhcp_server is None:
            self._dhcp_server = server
        elif server != self._dhcp_server:
            self._alert("rogue_dhcp", "high", server, now,
                        title=f"Rogue DHCP server {server}",
                        detail=f"{server} hands out network settings as well as {self._dhcp_server}; a fake DHCP "
                               f"server can make itself your router or DNS server",
                        src=server, dst=r["dst"], focus=server,
                        fix={"action": "block_ip", "ip": server})

    def _check_redirect(self, r, now):
        if r["proto"] != "ICMP" or r.get("icmp_type") != 5:
            return
        self._alert("icmp_redirect", "medium", r["src"], now,
                    title=f"ICMP redirect from {r['src']}",
                    detail=f"{r['src']} told {r['dst']} to send traffic through a different router",
                    src=r["src"], dst=r["dst"], focus=r["src"],
                    fix={"action": "disable_redirects"})

    def _check_brute_force(self, r, now):
        if r["proto"] != "TCP" or r["flags"] != ["SYN"] or r["dport"] not in LOGIN_SERVICES:
            return
        key = (r["src"], r["dst"], r["dport"])
        times = self._logins.setdefault(key, deque())
        times.append(now)
        while times[0] < now - self.brute_window:
            times.popleft()
        if len(times) >= self.brute_attempts:
            service = LOGIN_SERVICES[r["dport"]]
            self._alert("brute_force", "high", key, now,
                        title=f"{service} brute force from {r['src']}",
                        detail=f"{len(times)} login connections to {r['dst']}:{r['dport']} "
                               f"within {self.brute_window} s",
                        src=r["src"], dst=r["dst"], focus=r["src"],
                        fix={"action": "block_ip", "ip": r["src"]})

    def _check_credentials(self, r, payload, now):
        to_server = r["dport"] in CREDENTIAL_PORTS
        port = r["dport"] if to_server else r["sport"]
        service = CREDENTIAL_PORTS[port]
        if to_server:
            conn = (r["src"], r["sport"], r["dst"], r["dport"])
        else:
            conn = (r["dst"], r["dport"], r["src"], r["sport"])

        if service == "Telnet":
            self._telnet(r, conn, to_server, payload, now)
            return
        if not to_server:
            return

        user = secret = None
        if service in ("FTP", "POP3"):
            if m := USER_COMMAND.search(payload):
                self._users[conn] = (text(m.group(1)), now)
            if m := PASS_COMMAND.search(payload):
                secret = text(m.group(1))
                user = self._users.pop(conn, (None, 0))[0]
        elif service == "IMAP":
            if m := IMAP_LOGIN.search(payload):
                user, secret = text(m.group(1)), text(m.group(2))
        else:   # HTTP
            if m := BASIC_AUTH.search(payload):
                try:
                    decoded = base64.b64decode(m.group(1), validate=True)
                except ValueError:
                    return
                user, _, secret = decoded.decode("utf-8", "replace").partition(":")
            elif m := FORM_PASSWORD.search(payload):
                secret = text(m.group(1))
                user_match = FORM_USER.search(payload)
                user = text(user_match.group(1)) if user_match else None
        if secret:
            self._password_alert(r, service, user, secret, now)

    def _telnet(self, r, conn, to_server, payload, now):
        """After the server prompts "Password:", collect what the client types up to Enter."""
        if not to_server:
            if b"password:" in payload.lower():
                self._prompted[conn] = (b"", now)
            return
        if conn not in self._prompted:
            return
        typed = self._prompted[conn][0] + payload
        if b"\r" in typed or b"\n" in typed or len(typed) > 128:
            del self._prompted[conn]
            secret = text(re.split(rb"[\r\n]", typed)[0])
            if secret:
                self._password_alert(r, "Telnet", None, secret, now)
        else:
            self._prompted[conn] = (typed, now)

    def _password_alert(self, r, service, user, secret, now):
        who = f"user '{user}'" if user else "a user"
        if r.get("app"):
            who += f" of {r['app']}"
        self._alert("credentials", "high", (r["src"], r["dst"], r["dport"], user), now,
                    title=f"{service} password sent in clear text",
                    detail=f"{who} on {r['src']} logged in to {r['dst']}:{r['dport']} with "
                           f"{describe_secret(secret)} that anyone on the network can read",
                    src=r["src"], dst=r["dst"], focus=r["src"],
                    fix=block_port_fix(service, r["dport"]))

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

    def _alert(self, rule, severity, key, now, title, detail, src, dst, focus, fix=None):
        alert = self._open.get((rule, key))
        if alert and now - alert["last_seen"] < self.cooldown:
            alert.update(last_seen=now, count=alert["count"] + 1, detail=detail)
            return
        self._last_id += 1
        alert = {"id": self._last_id, "rule": rule, "severity": severity, "title": title,
                 "detail": detail, "src": src, "dst": dst, "focus": focus,
                 "time": now, "last_seen": now, "count": 1, "fix": fix}
        self._alerts.append(alert)
        self._open[(rule, key)] = alert
        if self.on_alert:
            self.on_alert(dict(alert))

    def _cleanup(self, now):
        """Drop tracking state that has gone quiet, so memory stays bounded."""
        for table in (self._ports, self._targets):
            for key in [k for k, seen in table.items() if next(reversed(seen.values())) < now - self.window]:
                del table[key]
        for key in [k for k, times in self._syns.items() if times[-1] < now - self.flood_window]:
            del self._syns[key]
        for key in [k for k, times in self._logins.items() if times[-1] < now - self.brute_window]:
            del self._logins[key]
        for key in [k for k, (sent, _) in self._uploads.items() if not sent or sent[-1][0] < now - self.upload_window]:
            del self._uploads[key]
        for key in [k for k, seen in self._subdomains.items() if next(reversed(seen.values())) < now - self.tunnel_window]:
            del self._subdomains[key]
        for table in (self._users, self._prompted):
            for key in [k for k, (_, seen) in table.items() if seen < now - self.cooldown]:
                del table[key]
        for key in [k for k, a in self._open.items() if now - a["last_seen"] >= self.cooldown]:
            del self._open[key]
