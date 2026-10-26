"""Generate samples/sample_traffic.pcap: about 25 seconds of realistic home traffic.

The packets are crafted with Scapy, not captured, so the file can be shared
and used for demos and tests on machines that cannot capture live traffic.
It uses documentation-only addresses (203.0.113.0/24, 198.51.100.0/24).

    laptop 192.168.1.5   looks up a site, opens HTTPS to it, streams video
    phone  192.168.1.9   browses another site, announces itself over mDNS
    router 192.168.1.1   answers ARP
    plus pings to 1.1.1.1 and an SSDP discovery broadcast

Run:  python tools/make_sample_pcap.py [output.pcap]
"""

import os
import random
import ssl
import sys

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

LAPTOP = ("192.168.1.5", "3c:22:fb:12:34:56")
PHONE = ("192.168.1.9", "5c:f9:38:aa:bb:cc")
ROUTER = ("192.168.1.1", "00:1a:2b:3c:4d:5e")
DNS_SERVER = "8.8.8.8"
VIDEO_SITE = "203.0.113.10"
NEWS_SITE = "198.51.100.7"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

START = 1_760_000_000.0  # fixed start time so the file is reproducible
MSS = 1460               # full-size TCP payload -> 1514-byte Ethernet frame


def client_hello(server_name):
    """A real TLS ClientHello for ``server_name``, made by Python's TLS library (nothing is sent)."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class Builder:
    def __init__(self):
        self.packets = []
        self.tcp = {}   # (client ip, server, client port) -> next sequence number each way

    def add(self, t, pkt):
        pkt.time = START + t
        self.packets.append(pkt)

    def frame(self, src, dst, dst_mac=None):
        """Ethernet + IP from a LAN host; traffic to the internet goes via the router."""
        if dst_mac is None:
            dst_mac = ROUTER[1] if not dst.startswith("192.168.") else BROADCAST_MAC
        return Ether(src=src[1], dst=dst_mac) / IP(src=src[0], dst=dst)

    def inbound(self, src_ip, dst):
        return Ether(src=ROUTER[1], dst=dst[1]) / IP(src=src_ip, dst=dst[0], ttl=56)

    def dns_lookup(self, t, host, name, answer, sport):
        qid = random.randint(1, 65535)
        self.add(t, self.frame(host, DNS_SERVER) / UDP(sport=sport, dport=53)
                 / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
        self.add(t + 0.02, self.inbound(DNS_SERVER, host) / UDP(sport=53, dport=sport)
                 / DNS(id=qid, qr=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer)))

    def handshake(self, t, host, server, sport, name):
        """TCP handshake, then the TLS ClientHello naming the site and the server's first reply.

        Sequence numbers are kept per connection, as a real TCP stack would, so
        nothing looks like a retransmission."""
        client, srv = 1000, 5000
        self.add(t, self.frame(host, server) / TCP(sport=sport, dport=443, flags="S", seq=client))
        self.add(t + 0.03, self.inbound(server, host) / TCP(sport=443, dport=sport, flags="SA", seq=srv, ack=client + 1))
        client, srv = client + 1, srv + 1
        self.add(t + 0.031, self.frame(host, server) / TCP(sport=sport, dport=443, flags="A", seq=client, ack=srv))
        hello = client_hello(name)
        for i in range(0, len(hello), MSS):
            chunk = hello[i:i + MSS]
            self.add(t + 0.035 + i / 1e6, self.frame(host, server)
                     / TCP(sport=sport, dport=443, flags="PA", seq=client, ack=srv) / Raw(chunk))
            client += len(chunk)
        self.add(t + 0.07, self.inbound(server, host)
                 / TCP(sport=443, dport=sport, flags="PA", seq=srv, ack=client) / Raw(b"\x16" * 1200))
        self.tcp[(host[0], server, sport)] = {"client": client, "server": srv + 1200}

    def download(self, t, seconds, host, server, sport, start_rate, end_rate):
        """Server streams full-size segments; the client ACKs every second one."""
        seq = self.tcp[(host[0], server, sport)]
        for second in range(seconds):
            rate = int(start_rate + (end_rate - start_rate) * second / max(seconds - 1, 1))
            rate = max(1, int(rate * random.uniform(0.85, 1.15)))
            for i in range(rate):
                at = t + second + i / rate
                self.add(at, self.inbound(server, host) / TCP(sport=443, dport=sport, flags="A", seq=seq["server"],
                                                              ack=seq["client"]) / Raw(b"\x00" * MSS))
                seq["server"] += MSS
                if i % 2:
                    self.add(at + 0.001, self.frame(host, server) / TCP(sport=sport, dport=443, flags="A",
                                                                       seq=seq["client"], ack=seq["server"]))


def build():
    random.seed(8)
    b = Builder()

    # Laptop finds the router's MAC address
    b.add(0.0, Ether(src=LAPTOP[1], dst=BROADCAST_MAC) / ARP(op=1, hwsrc=LAPTOP[1], psrc=LAPTOP[0], pdst=ROUTER[0]))
    b.add(0.01, Ether(src=ROUTER[1], dst=LAPTOP[1]) / ARP(op=2, hwsrc=ROUTER[1], psrc=ROUTER[0],
                                                         hwdst=LAPTOP[1], pdst=LAPTOP[0]))

    # Laptop opens the video site: DNS lookup, TCP handshake on 443, then streaming
    b.dns_lookup(0.5, LAPTOP, "video.example.com", VIDEO_SITE, sport=53011)
    b.handshake(0.6, LAPTOP, VIDEO_SITE, sport=52344, name="video.example.com")
    b.download(1.0, 24, LAPTOP, VIDEO_SITE, sport=52344, start_rate=12, end_rate=110)

    # Phone browses a news site in short bursts
    b.dns_lookup(3.0, PHONE, "news.example.org", NEWS_SITE, sport=40122)
    b.handshake(3.1, PHONE, NEWS_SITE, sport=41870, name="news.example.org")
    for burst in (3.5, 9.0, 15.5, 21.0):
        b.download(burst, 1, PHONE, NEWS_SITE, sport=41870, start_rate=40, end_rate=40)

    # Laptop pings 1.1.1.1 four times
    for i in range(4):
        t = 5.0 + i
        b.add(t, b.frame(LAPTOP, "1.1.1.1") / ICMP(type=8, id=1, seq=i + 1) / Raw(b"abcdefgh" * 4))
        b.add(t + 0.018, b.inbound("1.1.1.1", LAPTOP) / ICMP(type=0, id=1, seq=i + 1) / Raw(b"abcdefgh" * 4))

    # Background chatter on the LAN
    for t in (2.0, 12.0, 22.0):
        b.add(t, Ether(src=PHONE[1], dst="01:00:5e:00:00:fb") / IP(src=PHONE[0], dst="224.0.0.251", ttl=255)
              / UDP(sport=5353, dport=5353) / Raw(b"\x00" * 120))
    for t in (7.0, 17.0):
        b.add(t, Ether(src=LAPTOP[1], dst="01:00:5e:7f:ff:fa") / IP(src=LAPTOP[0], dst="239.255.255.250", ttl=2)
              / UDP(sport=51900, dport=1900) / Raw(b"M-SEARCH * HTTP/1.1\r\n" + b"\x00" * 100))

    b.packets.sort(key=lambda p: p.time)
    return b.packets


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "samples", "sample_traffic.pcap")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    packets = build()
    wrpcap(out, packets)
    print(f"Wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main()
