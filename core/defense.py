"""Fix what the security checks find.

Every alert gets plain advice (what it means and what to do), and where this
computer can protect itself, a one-click fix:

    Port scan, host sweep, brute force   block the attacker's IP, both ways (Windows Firewall)
    ARP spoofing                         pin the real MAC of the spoofed address (static ARP entry)
    Telnet / FTP / POP3 / IMAP           block that cleartext protocol going out (Windows Firewall)
    Password sent in clear text          the same, plus: change that password

Fixes change Windows settings, so they need PacketSniffer to run as
Administrator. Every firewall rule it makes is named "PacketSniffer-...", ARP
entries are temporary (gone after a restart), and every fix can be undone from
the dashboard. Fixes never touch this computer's own addresses or its router,
and commands are run without a shell, with addresses checked first, so alert
text can never be turned into a command.

With --auto-block, attackers found by a port scan, host sweep or brute-force
check are blocked as soon as they are detected.
"""

import ctypes
import ipaddress
import queue
import re
import subprocess
import sys
import threading
import time

RULE_PREFIX = "PacketSniffer"
MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.I)
AUTO_BLOCK_RULES = ("port_scan", "host_sweep", "brute_force")

SAFER = {
    "Telnet": "SSH (port 22)",
    "FTP": "SFTP or FTPS",
    "POP3": "POP3 over SSL (port 995): turn on SSL/TLS in the mail app",
    "IMAP": "IMAP over SSL (port 993): turn on SSL/TLS in the mail app",
    "HTTP": "the https:// version of the site",
}


def advice(alert):
    """What an alert means and the steps that deal with it, in plain words."""
    rule, fix = alert["rule"], alert.get("fix") or {}
    src, dst = alert.get("src"), alert.get("dst")
    service = fix.get("service") or next((s for s in SAFER if s in alert["title"]), None)
    if rule == "port_scan":
        return {"meaning": f"{src} is checking which services your computer runs. Scanning is usually "
                           "the first step of an attack.",
                "steps": [f"Block {src} if you do not recognise it.",
                          "Turn off services you do not use, such as file sharing or Remote Desktop.",
                          "Keep Windows Firewall on, set to Public on networks you do not trust."]}
    if rule == "host_sweep":
        return {"meaning": f"{src} is mapping which devices are on the network.",
                "steps": [f"Block {src} if you do not recognise it.",
                          "Check the router's list of connected devices for strangers."]}
    if rule == "syn_flood":
        return {"meaning": f"{dst} is being flooded with half-open connections, to make it stop answering "
                           "(a denial-of-service attack).",
                "steps": ["The senders are usually forged, so blocking single addresses does not help.",
                          "If the target is this computer, turn off the service on that port.",
                          "Ask the network administrator to filter or rate-limit the traffic at the router."]}
    if rule == "arp_spoof":
        return {"meaning": f"A device with MAC {src} is pretending to be {dst}, so traffic meant for it may "
                           "pass through the attacker (a man-in-the-middle attack).",
                "steps": [f"Pin the real MAC address of {dst}, so this computer ignores the fake one.",
                          "If you do not trust this network, disconnect or use a VPN.",
                          f"Tell the network administrator about the device with MAC {src}."]}
    if rule == "brute_force":
        return {"meaning": f"{src} keeps trying to log in: it is guessing passwords.",
                "steps": [f"Block {src}.",
                          "Use a long password or key-based login, and turn the service off if you do not need it.",
                          "Turn on account lockout after a few failed logins."]}
    if rule == "cleartext":
        return {"meaning": f"{service or 'This protocol'} sends everything, passwords included, without "
                           "encryption, so anyone on the network can read it.",
                "steps": [f"Use {SAFER.get(service, 'an encrypted alternative')} instead."]
                + ([f"Block {service} going out, so it cannot be used by mistake."] if fix else [])}
    if rule == "credentials":
        return {"meaning": "A password crossed the network unencrypted. Assume someone may have seen it.",
                "steps": ["Change that password now, from a secure (encrypted) connection.",
                          f"Use {SAFER.get(service, 'the encrypted version of the service')} from now on.",
                          "If the same password is used anywhere else, change it there too."]
                + ([f"Block {service} going out, so it cannot be used by mistake."] if fix else [])}
    return {"meaning": alert.get("detail", ""), "steps": []}


def fix_label(fix):
    if not fix:
        return None
    if fix["action"] == "block_ip":
        return f"Block {fix['ip']}"
    if fix["action"] == "pin_arp":
        return f"Pin the real MAC of {fix['ip']}"
    return f"Block {fix['service']} going out"


def protected_addresses():
    """This computer's own addresses and its router: never blocked."""
    found = []
    try:
        import psutil
        import socket

        found += [a.address.split("%")[0] for addrs in psutil.net_if_addrs().values() for a in addrs
                  if a.family in (socket.AF_INET, socket.AF_INET6)]
    except Exception:
        pass
    try:
        from scapy.route import Route

        found.append(Route().route("0.0.0.0")[2])
    except Exception:
        pass
    return [a for a in found if a and a != "0.0.0.0"]


def running_as_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class Defender:
    def __init__(self, interface=None, protected=(), auto_block=False,
                 run=None, is_admin=running_as_admin, platform=sys.platform, clock=time.time):
        self.interface = interface        # e.g. "Wi-Fi", for static ARP entries
        self.protected = {str(p) for p in protected if p}   # this computer's addresses, the router
        self.auto_block = auto_block
        self._run = run or self._netsh
        self._is_admin = is_admin
        self._platform = platform
        self._clock = clock
        self._lock = threading.Lock()
        self._applied = {}                # key -> fix record
        self._next_id = 0
        self._queue = queue.Queue()
        self._worker = None

    # ---- status ------------------------------------------------------------

    def unavailable_reason(self):
        if self._platform != "win32":
            return "One-click fixes use Windows Firewall, so they work on Windows only."
        if not self._is_admin():
            return "Run PacketSniffer as Administrator to apply fixes (right-click it, Run as administrator)."
        return None

    def status(self):
        with self._lock:
            applied = sorted(self._applied.values(), key=lambda f: f["id"], reverse=True)
        reason = self.unavailable_reason()
        return {"available": reason is None, "reason": reason, "auto_block": self.auto_block,
                "applied": [dict(f) for f in applied]}

    def describe(self, alert):
        """The alert plus advice, the fix's button label, and whether that fix is already applied."""
        fix = alert.get("fix")
        key = self._key(fix) if fix else None
        with self._lock:
            applied = self._applied.get(key)
        return dict(alert, advice=advice(alert), fix_label=fix_label(fix),
                    fixed=dict(applied) if applied else None)

    # ---- applying and undoing ----------------------------------------------

    def apply(self, fix, auto=False):
        """Apply one fix from an alert. Returns (ok, message)."""
        reason = self.unavailable_reason()
        if reason:
            return False, reason
        try:
            commands, label = self._plan(fix)
        except ValueError as exc:
            return False, str(exc)
        key = self._key(fix)
        with self._lock:
            if key in self._applied:
                return True, f"Already done: {self._applied[key]['label']}"
        for command in commands:
            ok, output = self._run(command)
            if not ok:
                return False, f"Windows refused: {output.strip() or 'unknown error'}"
        with self._lock:
            self._next_id += 1
            self._applied[key] = {"id": self._next_id, "key": key, "fix": dict(fix), "label": label,
                                  "time": self._clock(), "auto": auto}
        return True, label

    def undo(self, fix_id):
        with self._lock:
            record = next((f for f in self._applied.values() if f["id"] == fix_id), None)
        if record is None:
            return False, "That fix is not active."
        reason = self.unavailable_reason()
        if reason:
            return False, reason
        for command in self._undo_plan(record["fix"]):
            ok, output = self._run(command)
            if not ok:
                return False, f"Windows refused: {output.strip() or 'unknown error'}"
        with self._lock:
            self._applied.pop(record["key"], None)
        return True, f"Undone: {record['label']}"

    # ---- auto-block ----------------------------------------------------------

    def on_alert(self, alert):
        """Called for every new alert; blocks attackers in the background if --auto-block is on."""
        fix = alert.get("fix")
        if self.auto_block and fix and fix["action"] == "block_ip" and alert["rule"] in AUTO_BLOCK_RULES:
            self._queue.put(fix)
            if self._worker is None:
                self._worker = threading.Thread(target=self._work, daemon=True)
                self._worker.start()

    def _work(self):
        while True:
            self.apply(self._queue.get(), auto=True)

    # ---- commands ------------------------------------------------------------

    def _plan(self, fix):
        action = fix.get("action")
        if action == "block_ip":
            ip = self._checked_ip(fix.get("ip"))
            name = f"{RULE_PREFIX}-block-{ip}"
            return ([["advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}", "action=block",
                      f"remoteip={ip}"] for d in ("in", "out")], f"Blocked {ip} (in and out)")
        if action == "block_port":
            port, proto = int(fix["port"]), str(fix.get("protocol", "TCP")).upper()
            if not 0 < port < 65536 or proto not in ("TCP", "UDP"):
                raise ValueError("Not a valid port.")
            name = f"{RULE_PREFIX}-block-outgoing-{proto}-{port}"
            return ([["advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out", "action=block",
                      f"protocol={proto}", f"remoteport={port}"]],
                    f"Blocked outgoing {fix.get('service', proto)} ({proto} port {port})")
        if action == "pin_arp":
            ip = self._checked_ip(fix.get("ip"), allow_router=True)
            mac = str(fix.get("mac", ""))
            if not MAC.match(mac):
                raise ValueError("Not a valid MAC address.")
            if not self.interface:
                raise ValueError("The network interface is not known, so the MAC cannot be pinned.")
            return ([["interface", "ipv4", "add", "neighbors", self.interface, ip, mac.replace(":", "-"),
                      "store=active"]], f"Pinned {ip} to its real MAC {mac.lower()}")
        raise ValueError("This alert has no automatic fix.")

    def _undo_plan(self, fix):
        action = fix["action"]
        if action == "block_ip":
            return [["advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-block-{fix['ip']}"]]
        if action == "block_port":
            proto = str(fix.get("protocol", "TCP")).upper()
            return [["advfirewall", "firewall", "delete", "rule",
                     f"name={RULE_PREFIX}-block-outgoing-{proto}-{int(fix['port'])}"]]
        return [["interface", "ipv4", "delete", "neighbors", self.interface, fix["ip"]]]

    def _checked_ip(self, value, allow_router=False):
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            raise ValueError(f"'{value}' is not an IP address.") from None
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or str(ip) == "255.255.255.255":
            raise ValueError(f"{ip} is not a single device, so it cannot be blocked.")
        if str(ip) in self.protected and not allow_router:
            raise ValueError(f"{ip} is this computer or its router; blocking it would cut you off the network.")
        return str(ip)

    @staticmethod
    def _key(fix):
        if fix["action"] == "block_port":
            return ("block_port", str(fix.get("protocol", "TCP")).upper(), int(fix["port"]))
        return (fix["action"], str(fix.get("ip")))

    @staticmethod
    def _netsh(args):
        """Run netsh with a list of arguments: no shell, so nothing in them is interpreted."""
        result = subprocess.run(["netsh", *args], capture_output=True, text=True, timeout=15,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
