from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from core.names import NameCache
from core.parser import parse_packet

ETH = Ether(src="00:1a:2b:3c:4d:5e", dst="3c:22:fb:12:34:56")


def captured(pkt):
    """The packet as capture would see it: turned into bytes and decoded again."""
    return Ether(bytes(pkt))


def answer(name, *addresses, qtype="A", cname=None):
    records = [DNSRR(rrname=name, type="CNAME", rdata=cname)] if cname else []
    records += [DNSRR(rrname=cname or name, type="AAAA" if ":" in a else "A", rdata=a) for a in addresses]
    return captured(ETH / IP(src="8.8.8.8", dst="192.168.1.5") / UDP(sport=53, dport=53011) / DNS(
        qr=1, qd=DNSQR(qname=name, qtype=qtype), an=records))


def test_names_come_from_the_question_even_through_a_cname():
    cache = NameCache()
    cache.learn(answer("www.youtube.com", "142.250.1.1", cname="youtube-ui.l.google.com"))
    cache.learn(answer("example.com", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", qtype="AAAA"))
    assert cache.name("142.250.1.1") == "www.youtube.com"
    assert cache.name("2606:2800:21f:cb07:6820:80da:af6b:8b2c") == "example.com"
    assert cache.name("1.1.1.1") is None and cache.name(None) is None


def test_questions_teach_nothing_and_the_cache_is_bounded():
    cache = NameCache(max_names=2)
    query = ETH / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=53011, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com"))
    cache.learn(query)
    assert len(cache) == 0
    for i in range(3):
        cache.learn(answer(f"site{i}.example", f"10.0.0.{i}"))
    assert (len(cache), cache.name("10.0.0.0"), cache.name("10.0.0.2")) == (2, None, "site2.example")


def test_dns_rows_say_what_was_asked_and_answered():
    query = ETH / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=53011, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com", qtype="AAAA"))
    assert parse_packet(query)["info"] == "DNS query AAAA example.com"
    many = answer("cdn.example", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")
    assert parse_packet(many)["info"] == "DNS answer cdn.example = 10.0.0.1, 10.0.0.2 +2 more"
    missing = ETH / IP(src="8.8.8.8", dst="192.168.1.5") / UDP(sport=53, dport=53011) / DNS(
        qr=1, rcode=3, qd=DNSQR(qname="nope.example"))
    assert parse_packet(missing)["info"] == "DNS answer nope.example (not found)"
