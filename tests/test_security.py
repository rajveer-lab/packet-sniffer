import base64

from core.security import SecurityMonitor

ATTACKER = "192.168.1.66"
LAPTOP = "192.168.1.5"
ROUTER = "192.168.1.1"
ROUTER_MAC = "00:1a:2b:3c:4d:5e"
ATTACKER_MAC = "de:ad:be:ef:00:66"


def rec(time, proto="TCP", src=ATTACKER, dst=LAPTOP, sport=40000, dport=80, flags=("SYN",), **extra):
    record = {"time": time, "proto": proto, "src": src, "dst": dst, "sport": sport, "dport": dport,
              "flags": list(flags), "icmp_type": None, "arp_op": None, "arp_mac": None}
    record.update(extra)
    return record


def feed(monitor, records):
    for r in records:
        monitor.inspect(r)
    return monitor.summary()


def rules_fired(summary):
    return [a["rule"] for a in summary["alerts"]]


def test_syn_port_scan_raises_one_alert_that_keeps_updating():
    monitor = SecurityMonitor(scan_ports=15, window=10)
    s = feed(monitor, [rec(100 + i * 0.05, dport=port) for i, port in enumerate(range(1, 41))])
    assert rules_fired(s) == ["port_scan"]
    alert = s["alerts"][0]
    assert (alert["severity"], alert["src"], alert["dst"], alert["focus"]) == ("high", ATTACKER, LAPTOP, ATTACKER)
    assert alert["detail"].startswith("40 TCP ports probed")
    assert alert["count"] == 26            # fired at the 15th port, then updated
    assert s["counts"] == {"high": 1, "medium": 0, "low": 0}


def test_stealth_and_udp_scans_are_caught():
    fin_scan = [rec(100 + i * 0.1, dport=p, flags=("FIN", "PSH", "URG")) for i, p in enumerate(range(1, 20))]
    null_scan = [rec(100 + i * 0.1, dport=p, flags=()) for i, p in enumerate(range(1, 20))]
    udp_scan = [rec(100 + i * 0.1, proto="UDP", dport=p, flags=()) for i, p in enumerate(range(1, 20))]
    for probes in (fin_scan, null_scan, udp_scan):
        assert rules_fired(feed(SecurityMonitor(), probes)) == ["port_scan"]


def test_slow_or_normal_traffic_is_not_a_scan():
    monitor = SecurityMonitor(scan_ports=15, window=10)
    slow = [rec(100 + i * 2, dport=p) for i, p in enumerate(range(1, 40))]           # 5 ports per 10 s
    established = [rec(200 + i * 0.01, dport=p, flags=("ACK",)) for i, p in enumerate(range(1, 40))]
    # A DNS server answering many lookups replies to many client ports, from port 53
    dns_replies = [rec(300 + i * 0.1, proto="UDP", src="8.8.8.8", sport=53, dport=50000 + i, flags=())
                   for i in range(40)]
    assert feed(monitor, slow + established + dns_replies)["alerts"] == []


def test_ping_sweep_and_arp_sweep():
    pings = [rec(100 + i * 0.1, proto="ICMP", dst=f"192.168.1.{i}", sport=None, dport=None, flags=(), icmp_type=8)
             for i in range(1, 13)]
    arps = [rec(100 + i * 0.1, proto="ARP", dst=f"192.168.1.{i}", sport=None, dport=None, flags=(), arp_op=1,
                arp_mac=ATTACKER_MAC) for i in range(1, 13)]
    for probes, how in ((pings, "pinged"), (arps, "ARP-probed")):
        s = feed(SecurityMonitor(sweep_hosts=10), probes)
        assert rules_fired(s) == ["host_sweep"]
        assert s["alerts"][0]["detail"] == f"12 addresses {how} within 10 s"


def test_syn_flood_at_one_port():
    flood = [rec(100 + i * 0.01, src=f"10.{i // 250}.{i % 250}.1", dport=80) for i in range(150)]
    s = feed(SecurityMonitor(flood_syns=100, flood_window=5), flood)
    assert rules_fired(s) == ["syn_flood"]
    alert = s["alerts"][0]
    assert (alert["dst"], alert["focus"], alert["count"]) == (LAPTOP, LAPTOP, 51)


def test_arp_spoofing_when_an_ip_changes_mac():
    def arp_reply(time, mac):
        return rec(time, proto="ARP", src=ROUTER, dst=LAPTOP, sport=None, dport=None, flags=(),
                   arp_op=2, arp_mac=mac)

    monitor = SecurityMonitor()
    assert feed(monitor, [arp_reply(100, ROUTER_MAC), arp_reply(130, ROUTER_MAC)])["alerts"] == []
    s = feed(monitor, [arp_reply(140, ATTACKER_MAC)])
    assert rules_fired(s) == ["arp_spoof"]
    alert = s["alerts"][0]
    assert alert["detail"].startswith(f"{ROUTER} moved from {ROUTER_MAC} to {ATTACKER_MAC}")
    assert alert["focus"] == ATTACKER_MAC


def test_cleartext_logins_but_not_scans_of_those_ports():
    monitor = SecurityMonitor()
    scan_of_telnet = [rec(100, dport=23)]
    telnet = [rec(101 + i, src=LAPTOP, dst="192.168.1.20", sport=50100, dport=23, flags=("PSH", "ACK"))
              for i in range(3)]
    http = [rec(110, src=LAPTOP, dst="203.0.113.10", sport=50200, dport=80, flags=("PSH", "ACK"))]
    s = feed(monitor, scan_of_telnet + telnet + http)
    assert [(a["title"], a["severity"], a["count"]) for a in s["alerts"]] == [
        (f"Unencrypted HTTP from {LAPTOP}", "low", 1),
        (f"Unencrypted Telnet from {LAPTOP}", "medium", 3),
    ]


def test_brute_force_on_a_login_service():
    monitor = SecurityMonitor(brute_attempts=20, brute_window=60)
    normal = [rec(100 + i, src=LAPTOP, dst="192.168.1.20", sport=50000 + i, dport=22) for i in range(5)]
    assert feed(monitor, normal)["alerts"] == []                 # a few SSH sessions are fine
    attack = [rec(200 + i * 0.5, sport=42000 + i, dst="192.168.1.20", dport=22) for i in range(25)]
    s = feed(monitor, attack)
    assert rules_fired(s) == ["brute_force"]
    assert s["alerts"][0]["title"] == f"SSH brute force from {ATTACKER}"
    assert s["alerts"][0]["count"] == 6


SECRET = "s3cr3t-Pa55"


def login(monitor, dport, *payloads, sport=50300, server="192.168.1.20", start=100):
    """Feed a TCP conversation; payloads starting with '<' come from the server."""
    for i, payload in enumerate(payloads):
        from_server = payload.startswith(b"<")
        record = rec(start + i * 0.1, src=server if from_server else LAPTOP, dst=LAPTOP if from_server else server,
                     sport=dport if from_server else sport, dport=sport if from_server else dport,
                     flags=("PSH", "ACK"))
        assert monitor.wants_payload(record)
        monitor.inspect(record, payload[1:] if from_server else payload)
    return [a for a in monitor.summary()["alerts"] if a["rule"] == "credentials"]


def test_passwords_in_clear_text_are_detected_but_never_shown():
    basic = base64.b64encode(f"admin:{SECRET}".encode())
    cases = {
        "FTP": login(SecurityMonitor(), 21, b"<220 ready\r\n", b"USER backup\r\n", b"PASS " + SECRET.encode() + b"\r\n"),
        "POP3": login(SecurityMonitor(), 110, b"USER mail\r\n", b"PASS " + SECRET.encode() + b"\r\n"),
        "IMAP": login(SecurityMonitor(), 143, b'a001 LOGIN mail "' + SECRET.encode() + b'"\r\n'),
        "HTTP basic": login(SecurityMonitor(), 80, b"GET / HTTP/1.1\r\nAuthorization: Basic " + basic + b"\r\n\r\n"),
        "HTTP form": login(SecurityMonitor(), 8080, b"POST /login HTTP/1.1\r\n\r\nuser=amy&password=" + SECRET.encode()),
        # Telnet clients send what is typed one key at a time
        "Telnet": login(SecurityMonitor(), 23, b"<login: ", b"amy\r\n", b"<Password: ",
                        *[c.encode() for c in SECRET], b"\r\n"),
    }
    users = {"FTP": "backup", "POP3": "mail", "IMAP": "mail", "HTTP basic": "admin", "HTTP form": "amy", "Telnet": None}
    for case, alerts in cases.items():
        assert len(alerts) == 1, case
        alert = alerts[0]
        assert alert["severity"] == "high"
        assert "an 11-character password" in alert["detail"], case
        assert (f"user '{users[case]}'" if users[case] else "a user") in alert["detail"], case
        assert SECRET not in str(alert), case


def test_only_cleartext_login_traffic_is_opened_up():
    assert not SecurityMonitor.wants_payload(rec(100, dport=443, flags=("PSH", "ACK")))
    assert not SecurityMonitor.wants_payload(rec(100, proto="UDP", dport=53))
    assert SecurityMonitor.wants_payload(rec(100, sport=21, dport=50000, flags=("PSH", "ACK")))
    # Ordinary web pages are not logins
    assert login(SecurityMonitor(), 80, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n") == []


def test_a_quiet_alert_reopens_after_the_cooldown():
    def scan(start):
        return [rec(start + i * 0.05, dport=p) for i, p in enumerate(range(1, 20))]

    monitor = SecurityMonitor(cooldown=60)
    feed(monitor, scan(100) + scan(130))          # still the same attack
    assert len(monitor.summary()["alerts"]) == 1
    s = feed(monitor, scan(300))                  # quiet for > 60 s: a new alert
    assert [a["id"] for a in s["alerts"]] == [2, 1]
    assert (s["rules"][0]["rule"], s["rules"][0]["alerts"]) == ("port_scan", 2)
    assert s["checked"] == 19 * 3


def test_tracking_state_is_cleaned_up():
    monitor = SecurityMonitor(window=10)
    feed(monitor, [rec(100, dst=f"10.0.0.{i}", dport=p) for i in range(50) for p in (1, 2)])
    assert len(monitor._ports) == 50
    monitor.inspect(rec(200, src="10.9.9.9", dport=443, flags=("ACK",)))
    assert len(monitor._ports) == 0


def replay_sample(name):
    from scapy.utils import PcapReader

    from core.parser import parse_packet, tcp_payload

    monitor = SecurityMonitor()
    with PcapReader(f"samples/{name}") as reader:
        for pkt in reader:
            record = parse_packet(pkt)
            monitor.inspect(record, tcp_payload(pkt) if monitor.wants_payload(record) else b"")
    return monitor.summary()


def test_attack_sample_triggers_every_check():
    s = replay_sample("attack_traffic.pcap")
    assert sorted(set(rules_fired(s))) == sorted(r["rule"] for r in s["rules"])
    assert s["counts"] == {"high": 7, "medium": 3, "low": 1}


def test_normal_home_traffic_raises_no_alerts():
    assert replay_sample("sample_traffic.pcap")["alerts"] == []
