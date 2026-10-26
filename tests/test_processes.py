import socket
from collections import namedtuple

import pytest

from core.processes import ProcessMap, normalize

Conn = namedtuple("Conn", "type laddr raddr status pid")
TCP, UDP = socket.SOCK_STREAM, socket.SOCK_DGRAM
ME = "172.17.76.96"
NAMES = {1200: "chrome.exe", 3300: "svchost.exe", 4: "System"}


def denied(pid):
    if pid in NAMES:
        return NAMES[pid]
    raise PermissionError("access denied")


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


def make(connections, clock=None):
    table = {"conns": connections}
    pm = ProcessMap(clock=clock or Clock(), read_connections=lambda: table["conns"],
                    process_name=denied, local_addresses=lambda: [ME, "fe80::1%12", "127.0.0.1"])
    pm.refresh()
    return pm, table


def rec(proto, src, sport, dst, dport):
    return {"proto": proto, "src": src, "sport": sport, "dst": dst, "dport": dport}


def test_tcp_packets_are_named_in_both_directions():
    pm, _ = make([Conn(TCP, (ME, 53684), ("104.18.32.47", 443), "ESTABLISHED", 1200)])
    assert pm.lookup(rec("TCP", ME, 53684, "104.18.32.47", 443)) == "chrome.exe"
    assert pm.lookup(rec("TCP", "104.18.32.47", 443, ME, 53684)) == "chrome.exe"
    assert pm.lookup(rec("UDP", ME, 53684, "104.18.32.47", 443)) is None      # protocol must match
    assert pm.lookup(rec("TCP", ME, 53685, "104.18.32.47", 443)) is None


def test_sockets_bound_to_every_address_only_name_this_computers_end():
    pm, _ = make([Conn(UDP, ("0.0.0.0", 5353), (), "NONE", 3300)])
    assert pm.lookup(rec("UDP", ME, 5353, "224.0.0.251", 5353)) == "svchost.exe"     # we send
    assert pm.lookup(rec("UDP", "172.17.76.1", 5353, ME, 5353)) == "svchost.exe"     # sent to us
    # Other devices' multicasts and broadcasts: no program here sent them
    assert pm.lookup(rec("UDP", "172.17.73.18", 5353, "224.0.0.251", 5353)) is None
    assert pm.lookup(rec("UDP", "172.17.74.251", 5353, "172.17.79.255", 5353)) is None
    # A remote server's port 5353 is not our socket
    assert pm.lookup(rec("UDP", "8.8.8.8", 5353, "8.8.4.4", 40000)) is None


def test_ipv6_zone_and_closed_or_unowned_connections():
    clock = Clock()
    pm, table = make([
        Conn(TCP, ("fe80::1%12", 6000), ("fe80::2", 443), "ESTABLISHED", 1200),
        Conn(TCP, (ME, 50000), ("1.1.1.1", 443), "TIME_WAIT", 0),          # no owner any more
        Conn(TCP, (ME, 50001), ("1.1.1.1", 443), "ESTABLISHED", 9999),     # protected process
        Conn(TCP, (ME, 445), (), "LISTEN", 4),
    ], clock)
    assert pm.lookup(rec("TCP", "fe80::1", 6000, "fe80::2", 443)) == "chrome.exe"
    assert pm.lookup(rec("TCP", ME, 50000, "1.1.1.1", 443)) is None
    assert pm.lookup(rec("TCP", ME, 50001, "1.1.1.1", 443)) == "pid 9999"
    assert pm.lookup(rec("TCP", "172.17.76.5", 51000, ME, 445)) == "System"

    # A closed connection is remembered for a minute, for its last FIN and ACK packets
    table["conns"] = []
    clock.now += 30
    pm.refresh()
    assert pm.lookup(rec("TCP", "fe80::2", 443, "fe80::1", 6000)) == "chrome.exe"
    clock.now += 31
    pm.refresh()
    assert pm.lookup(rec("TCP", "fe80::2", 443, "fe80::1", 6000)) is None


def test_other_protocols_are_never_named():
    pm, _ = make([Conn(TCP, (ME, 53684), ("1.1.1.1", 443), "ESTABLISHED", 1200)])
    assert pm.lookup({"proto": "ICMP", "src": ME, "sport": None, "dst": "1.1.1.1", "dport": None}) is None
    assert pm.lookup({"proto": "ARP", "src": ME, "sport": None, "dst": "172.17.76.1", "dport": None}) is None


def test_a_failed_read_keeps_the_last_table_and_reports_why():
    pm, table = make([Conn(TCP, (ME, 53684), ("1.1.1.1", 443), "ESTABLISHED", 1200)])
    pm._read_connections = lambda: (_ for _ in ()).throw(PermissionError("denied"))
    pm.refresh()
    assert "Cannot read the connection table" in pm.error
    assert pm.lookup(rec("TCP", ME, 53684, "1.1.1.1", 443)) == "chrome.exe"


@pytest.mark.parametrize("raw, clean", [("fe80::1%12", "fe80::1"), ("0:0:0:0:0:0:0:1", "::1"), ("x", "x")])
def test_normalize(raw, clean):
    assert normalize(raw) == clean


def test_reads_this_computers_real_connection_table():
    pm = ProcessMap()
    pm.refresh()
    assert pm.error is None
    assert pm._local, "should know this computer's own addresses"


def test_a_brand_new_connection_is_found_by_reading_again_at_once():
    clock = Clock()
    pm, table = make([], clock)
    table["conns"] = [Conn(TCP, (ME, 50102), ("49.44.130.145", 80), "ESTABLISHED", 1200)]
    clock.now += 0.1                       # too soon after the last read: not read again yet
    assert pm.lookup(rec("TCP", ME, 50102, "49.44.130.145", 80)) is None
    clock.now += 0.2
    assert pm.lookup(rec("TCP", ME, 50102, "49.44.130.145", 80)) == "chrome.exe"
    # Other devices' traffic never triggers a read
    reads = []
    pm._read_connections = lambda: reads.append(1) or []
    clock.now += 1
    assert pm.lookup(rec("TCP", "172.17.74.5", 40000, "8.8.8.8", 443)) is None
    assert reads == []
