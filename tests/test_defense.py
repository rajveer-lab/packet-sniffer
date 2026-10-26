import time

import pytest

from core.defense import Defender, advice, fix_label
from core.security import SecurityMonitor

ME, ROUTER, ATTACKER = "172.17.76.96", "172.17.72.1", "192.168.1.66"
ROUTER_MAC = "00:1a:2b:3c:4d:5e"


class FakeNetsh:
    """Records netsh commands instead of changing Windows."""

    def __init__(self, ok=True):
        self.commands, self.ok = [], ok

    def __call__(self, args):
        self.commands.append(args)
        return self.ok, "" if self.ok else "The requested operation requires elevation (Run as administrator)."


def defender(admin=True, ok=True, **kwargs):
    netsh = FakeNetsh(ok)
    d = Defender(interface="Wi-Fi", protected=[ME, ROUTER], run=netsh, is_admin=lambda: admin,
                 platform="win32", **kwargs)
    return d, netsh


def test_blocking_an_attacker_and_undoing_it():
    d, netsh = defender()
    ok, message = d.apply({"action": "block_ip", "ip": ATTACKER})
    assert (ok, message) == (True, f"Blocked {ATTACKER} (in and out)")
    assert netsh.commands == [
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name=PacketSniffer-block-{ATTACKER}", "dir=in",
         "action=block", f"remoteip={ATTACKER}"],
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name=PacketSniffer-block-{ATTACKER}", "dir=out",
         "action=block", f"remoteip={ATTACKER}"],
    ]
    assert d.apply({"action": "block_ip", "ip": ATTACKER}) == (True, f"Already done: Blocked {ATTACKER} (in and out)")
    (applied,) = d.status()["applied"]
    assert d.undo(applied["id"]) == (True, f"Undone: Blocked {ATTACKER} (in and out)")
    assert netsh.commands[-1] == ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=PacketSniffer-block-{ATTACKER}"]
    assert d.status()["applied"] == []


def test_pinning_the_real_mac_of_a_spoofed_router():
    d, netsh = defender()
    ok, message = d.apply({"action": "pin_arp", "ip": ROUTER, "mac": ROUTER_MAC})
    assert ok and message == f"Pinned {ROUTER} to its real MAC {ROUTER_MAC}"
    assert netsh.commands == [["netsh", "interface", "ipv4", "add", "neighbors", "Wi-Fi", ROUTER, "00-1a-2b-3c-4d-5e",
                               "store=active"]]
    d.undo(d.status()["applied"][0]["id"])
    assert netsh.commands[-1] == ["netsh", "interface", "ipv4", "delete", "neighbors", "Wi-Fi", ROUTER]


def test_blocking_a_cleartext_protocol_going_out():
    d, netsh = defender()
    assert d.apply({"action": "block_port", "port": 23, "protocol": "TCP", "service": "Telnet"}) == (
        True, "Blocked outgoing Telnet (TCP port 23)")
    assert netsh.commands == [["netsh", "advfirewall", "firewall", "add", "rule", "name=PacketSniffer-block-outgoing-TCP-23",
                               "dir=out", "action=block", "protocol=TCP", "remoteport=23"]]


@pytest.mark.parametrize("fix, message", [
    ({"action": "block_ip", "ip": ME}, "this computer or its router"),
    ({"action": "block_ip", "ip": ROUTER}, "this computer or its router"),
    ({"action": "block_ip", "ip": "127.0.0.1"}, "not a single device"),
    ({"action": "block_ip", "ip": "224.0.0.251"}, "not a single device"),
    ({"action": "block_ip", "ip": "1.2.3.4 & del C:\\*"}, "not an IP address"),
    ({"action": "pin_arp", "ip": ROUTER, "mac": "zz:zz"}, "not a valid MAC"),
    ({"action": "block_port", "port": 0}, "not a valid port"),
    ({"action": "shutdown"}, "no automatic fix"),
])
def test_unsafe_or_invalid_fixes_are_refused_before_anything_runs(fix, message):
    d, netsh = defender()
    ok, text = d.apply(fix)
    assert not ok and message.lower() in text.lower()
    assert netsh.commands == []


def test_fixes_need_administrator_rights_and_windows():
    d, netsh = defender(admin=False)
    ok, text = d.apply({"action": "block_ip", "ip": ATTACKER})
    assert not ok and "Run PacketSniffer as Administrator" in text
    assert netsh.commands == [] and d.status()["available"] is False
    other = Defender(protected=[ME], is_admin=lambda: True, platform="sunos5")
    assert "Windows, Linux and macOS only" in other.status()["reason"]
    linux = Defender(protected=[ME], is_admin=lambda: False, platform="linux")
    assert linux.status()["reason"] == "Run PacketSniffer with sudo to apply fixes."


def test_a_command_windows_refuses_is_reported_and_not_recorded():
    d, _ = defender(ok=False)
    ok, text = d.apply({"action": "block_ip", "ip": ATTACKER})
    assert not ok and text.startswith("The system refused")
    assert d.status()["applied"] == []


def test_auto_block_blocks_attackers_but_not_other_alerts():
    d, netsh = defender(auto_block=True)
    d.on_alert({"rule": "cleartext", "fix": {"action": "block_port", "port": 23, "protocol": "TCP", "service": "Telnet"}})
    d.on_alert({"rule": "port_scan", "fix": {"action": "block_ip", "ip": ATTACKER}})
    deadline = time.time() + 3
    while not d.status()["applied"] and time.time() < deadline:
        time.sleep(0.02)
    (applied,) = d.status()["applied"]
    assert applied["auto"] is True and applied["label"] == f"Blocked {ATTACKER} (in and out)"
    assert all("remoteport=23" not in c for c in netsh.commands)


def test_every_alert_in_the_attack_sample_gets_advice_and_the_right_fix():
    from scapy.utils import PcapReader

    from core.parser import parse_packet, tcp_payload

    monitor = SecurityMonitor()
    with PcapReader("samples/attack_traffic.pcap") as reader:
        for pkt in reader:
            record = parse_packet(pkt)
            monitor.inspect(record, tcp_payload(pkt) if monitor.wants_payload(record) else b"")
    d, _ = defender()
    alerts = {a["title"]: d.describe(a) for a in monitor.summary()["alerts"]}
    assert all(a["advice"]["meaning"] and a["advice"]["steps"] for a in alerts.values())
    assert alerts["Port scan from 192.168.1.66"]["fix"] == {"action": "block_ip", "ip": ATTACKER}
    assert alerts["ARP spoofing of 192.168.1.1"]["fix"] == {"action": "pin_arp", "ip": "192.168.1.1", "mac": ROUTER_MAC}
    assert alerts["Unencrypted Telnet from 192.168.1.5"]["fix_label"] == "Block Telnet going out"
    assert alerts["Unencrypted HTTP from 192.168.1.5"]["fix"] is None        # blocking all HTTP would break the web
    assert alerts["SYN flood at 192.168.1.20:80"]["fix"] is None              # forged senders: nothing to block
    assert "Change that password now" in alerts["FTP password sent in clear text"]["advice"]["steps"][0]


def test_fix_labels():
    assert fix_label(None) is None
    assert fix_label({"action": "pin_arp", "ip": ROUTER, "mac": ROUTER_MAC}) == f"Pin the real MAC of {ROUTER}"
    assert advice({"rule": "unknown", "title": "x", "detail": "something"})["meaning"] == "something"


def test_linux_commands():
    netsh = FakeNetsh()
    d = Defender(interface="wlan0", protected=[ME], run=netsh, is_admin=lambda: True, platform="linux")
    d.apply({"action": "block_ip", "ip": ATTACKER})
    d.apply({"action": "block_port", "port": 23, "protocol": "TCP", "service": "Telnet"})
    d.apply({"action": "pin_arp", "ip": ROUTER, "mac": "00-1A-2B-3C-4D-5E"})
    d.apply({"action": "disable_redirects"})
    comment = ["-m", "comment", "--comment"]
    assert netsh.commands == [
        ["iptables", "-I", "INPUT", "-s", ATTACKER, "-j", "DROP", *comment, f"PacketSniffer-block-{ATTACKER}"],
        ["iptables", "-I", "OUTPUT", "-d", ATTACKER, "-j", "DROP", *comment, f"PacketSniffer-block-{ATTACKER}"],
        ["iptables", "-I", "OUTPUT", "-p", "tcp", "--dport", "23", "-j", "DROP", *comment,
         "PacketSniffer-block-outgoing-TCP-23"],
        ["ip", "neigh", "replace", ROUTER, "lladdr", "00:1a:2b:3c:4d:5e", "dev", "wlan0", "nud", "permanent"],
        ["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"],
    ]
    first = min(f["id"] for f in d.status()["applied"])
    d.undo(first)
    assert netsh.commands[-2][:3] == ["iptables", "-D", "INPUT"]
    d.apply({"action": "block_ip", "ip": "2001:db8::66"})
    assert netsh.commands[-1][0] == "ip6tables"


def test_macos_pins_arp_and_turns_off_redirects_but_cannot_block():
    netsh = FakeNetsh()
    d = Defender(protected=[ME], run=netsh, is_admin=lambda: True, platform="darwin")
    assert d.apply({"action": "pin_arp", "ip": ROUTER, "mac": ROUTER_MAC})[0]
    assert d.apply({"action": "disable_redirects"}) == (True, "Stopped obeying ICMP redirects")
    ok, message = d.apply({"action": "block_ip", "ip": ATTACKER})
    assert not ok and "pf firewall" in message
    assert netsh.commands == [["arp", "-s", ROUTER, ROUTER_MAC], ["sysctl", "-w", "net.inet.icmp.drop_redirect=1"]]


def test_windows_turns_off_icmp_redirects_and_back_on():
    d, netsh = defender()
    assert d.apply({"action": "disable_redirects"}) == (True, "Stopped obeying ICMP redirects")
    d.undo(d.status()["applied"][0]["id"])
    assert netsh.commands == [["netsh", "interface", "ipv4", "set", "global", "icmpredirects=disabled"],
                              ["netsh", "interface", "ipv4", "set", "global", "icmpredirects=enabled"]]
