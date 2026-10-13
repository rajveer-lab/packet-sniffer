from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from core.parser import parse_packet, service_for

MAC_A = "3c:22:fb:12:34:56"
MAC_B = "00:1a:2b:3c:4d:5e"
# Explicit addresses, so Scapy never has to look up this machine's routes
ETH = Ether(src=MAC_A, dst=MAC_B)


def test_tcp_syn_ack_is_decoded_at_every_layer():
    pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src="203.0.113.10", dst="192.168.1.5", ttl=56) / TCP(
        sport=443, dport=52344, flags="SA")
    r = parse_packet(pkt, timestamp=100.0)

    assert (r["src_mac"], r["dst_mac"]) == (MAC_A, MAC_B)
    assert (r["src"], r["dst"], r["ip_version"], r["ttl"]) == ("203.0.113.10", "192.168.1.5", 4, 56)
    assert (r["proto"], r["sport"], r["dport"]) == ("TCP", 443, 52344)
    assert r["flags"] == ["SYN", "ACK"]
    assert r["service"] == "HTTPS"
    assert r["info"] == "443 -> 52344 [SYN, ACK]"
    assert r["length"] == len(pkt) == 54
    assert r["time"] == 100.0


def test_psh_ack_flags_follow_wireshark_order():
    pkt = ETH / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="PA") / Raw(b"x")
    assert parse_packet(pkt)["flags"] == ["PSH", "ACK"]


def test_dns_query_over_udp():
    pkt = ETH / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=53011, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com"))
    r = parse_packet(pkt)
    assert (r["proto"], r["sport"], r["dport"], r["service"]) == ("UDP", 53011, 53, "DNS")
    assert r["flags"] == []


def test_icmp_echo_request():
    r = parse_packet(ETH / IP(src="192.168.1.5", dst="1.1.1.1") / ICMP(type=8))
    assert (r["proto"], r["info"], r["sport"]) == ("ICMP", "Echo request", None)
    assert r["icmp_type"] == 8


def test_arp_request_has_no_ip_header():
    pkt = Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.5", pdst="192.168.1.1")
    r = parse_packet(pkt)
    assert (r["proto"], r["src"], r["dst"], r["ip_version"]) == ("ARP", "192.168.1.5", "192.168.1.1", None)
    assert r["info"] == "Who has 192.168.1.1? Tell 192.168.1.5"
    assert r["arp_op"] == 1


def test_arp_reply_records_the_claimed_mac():
    pkt = Ether(src=MAC_B, dst=MAC_A) / ARP(op=2, hwsrc=MAC_B, psrc="192.168.1.1", hwdst=MAC_A, pdst="192.168.1.5")
    r = parse_packet(pkt)
    assert (r["arp_op"], r["arp_mac"], r["src"]) == (2, MAC_B, "192.168.1.1")
    assert r["info"] == f"192.168.1.1 is at {MAC_B}"


def test_ipv6_udp_and_icmpv6():
    udp = parse_packet(ETH / IPv6(src="fe80::1", dst="ff02::fb", hlim=255) / UDP(sport=5353, dport=5353))
    assert (udp["proto"], udp["ip_version"], udp["ttl"], udp["service"]) == ("UDP", 6, 255, "MDNS")

    ping = parse_packet(ETH / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest())
    assert (ping["proto"], ping["ip_version"]) == ("ICMP", 6)


def test_other_ip_protocol_is_labelled_other():
    r = parse_packet(ETH / IP(src="10.0.0.1", dst="224.0.0.22", proto=2) / Raw(b"\x00" * 8))  # IGMP
    assert (r["proto"], r["src"]) == ("Other", "10.0.0.1")


def test_packet_without_ethernet_header():
    r = parse_packet(IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=5000, dport=60000))
    assert r["src_mac"] is None
    assert (r["proto"], r["src"]) == ("TCP", "127.0.0.1")


def test_service_uses_the_well_known_port():
    assert service_for(52344, 443) == "HTTPS"
    assert service_for(80, 61000) == "HTTP"
    assert service_for(50000, 50001) is None
    assert service_for(None, None) is None
