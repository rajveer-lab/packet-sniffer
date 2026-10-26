"""Generate samples/attack_traffic.pcap: about 22 seconds of a home network
under attack, to demonstrate every security check without attacking anyone.

The packets are crafted with Scapy and only written to a file; nothing is
sent on the network. Replay it with:

    python sniffer.py --pcap samples/attack_traffic.pcap

    0 s   normal traffic: the laptop looks up a site and opens HTTPS to it
    2 s   attacker 192.168.1.66 pings 192.168.1.1-40          -> Host sweep
    5 s   attacker SYN-scans 150 ports on the laptop           -> Port scan
    9 s   attacker claims to be the router in ARP replies      -> ARP spoofing
   12 s   150 spoofed SYNs hit the NAS's web server            -> SYN flood
   15 s   laptop logs in to the NAS over Telnet and FTP, and   -> Cleartext,
          to a website through a plain-HTTP login form             Password in clear text
   18 s   attacker tries 30 SSH logins on the NAS              -> Brute-force login
   19 s   the attacker answers DHCP as well as the router      -> Rogue DHCP server
   20 s   the attacker sends the laptop an ICMP redirect       -> ICMP redirect
   20 s   something on the laptop looks up malware.example     -> Blocklisted domain
   21 s   and smuggles data out in 30 random DNS names         -> DNS tunneling
(The Unusual upload check needs 50 MB in a minute, too much for a sample file.)

Run:  python tools/make_attack_pcap.py [output.pcap]
"""

import os
import random
import sys

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from make_sample_pcap import LAPTOP, ROUTER, VIDEO_SITE, Builder

ATTACKER = ("192.168.1.66", "de:ad:be:ef:00:66")
NAS = ("192.168.1.20", "00:11:32:aa:20:20")
OPEN_PORTS = {135, 139, 445}   # what a Windows laptop typically answers on


def lan(src, dst):
    """Ethernet + IP between two hosts on the same LAN."""
    return Ether(src=src[1], dst=dst[1]) / IP(src=src[0], dst=dst[0])


def tcp_session(b, t, client, server, sport, dport, lines):
    """Handshake, then the client and server take turns sending lines of text."""
    c, s = 2000, 9000                                   # each side's next sequence number
    b.add(t, lan(client, server) / TCP(sport=sport, dport=dport, flags="S", seq=c))
    b.add(t + 0.002, lan(server, client) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1))
    c, s = c + 1, s + 1
    b.add(t + 0.003, lan(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=c, ack=s))
    for i, (from_client, text) in enumerate(lines):
        at = t + 0.2 * (i + 1)
        if from_client:
            b.add(at, lan(client, server) / TCP(sport=sport, dport=dport, flags="PA", seq=c, ack=s) / Raw(text))
            c += len(text)
        else:
            b.add(at, lan(server, client) / TCP(sport=dport, dport=sport, flags="PA", seq=s, ack=c) / Raw(text))
            s += len(text)


def build():
    random.seed(66)
    b = Builder()

    # Normal traffic: the router answers ARP, the laptop browses over HTTPS
    b.add(0.0, Ether(src=ROUTER[1], dst=LAPTOP[1]) / ARP(op=2, hwsrc=ROUTER[1], psrc=ROUTER[0],
                                                        hwdst=LAPTOP[1], pdst=LAPTOP[0]))
    b.dns_lookup(0.3, LAPTOP, "video.example.com", VIDEO_SITE, sport=53011)
    b.handshake(0.4, LAPTOP, VIDEO_SITE, sport=52344, name="video.example.com")
    b.download(1.0, 18, LAPTOP, VIDEO_SITE, sport=52344, start_rate=8, end_rate=12)

    # Host sweep: ping every address from .1 to .40; three hosts answer
    for i in range(1, 41):
        target = f"192.168.1.{i}"
        t = 2.0 + i * 0.03
        b.add(t, Ether(src=ATTACKER[1], dst="ff:ff:ff:ff:ff:ff") / IP(src=ATTACKER[0], dst=target)
              / ICMP(type=8, id=66, seq=i))
        responder = {ROUTER[0]: ROUTER, LAPTOP[0]: LAPTOP, NAS[0]: NAS}.get(target)
        if responder:
            b.add(t + 0.002, lan(responder, ATTACKER) / ICMP(type=0, id=66, seq=i))

    # Port scan: half-open SYN scan of 150 ports; closed ports answer RST, open ones SYN-ACK
    ports = list(range(1, 151))
    random.shuffle(ports)
    for i, port in enumerate(ports):
        t = 5.0 + i * 0.01
        b.add(t, lan(ATTACKER, LAPTOP) / TCP(sport=61000, dport=port, flags="S"))
        if port in OPEN_PORTS:
            b.add(t + 0.001, lan(LAPTOP, ATTACKER) / TCP(sport=port, dport=61000, flags="SA"))
            b.add(t + 0.002, lan(ATTACKER, LAPTOP) / TCP(sport=61000, dport=port, flags="R"))
        else:
            b.add(t + 0.001, lan(LAPTOP, ATTACKER) / TCP(sport=port, dport=61000, flags="RA"))

    # ARP spoofing: the attacker tells the laptop "192.168.1.1 is at <my MAC>", every second
    for i in range(5):
        b.add(9.0 + i, Ether(src=ATTACKER[1], dst=LAPTOP[1]) / ARP(op=2, hwsrc=ATTACKER[1], psrc=ROUTER[0],
                                                                  hwdst=LAPTOP[1], pdst=LAPTOP[0]))

    # SYN flood: 150 SYNs from made-up internet addresses at the NAS's web server
    for i in range(150):
        spoofed = f"198.51.100.{random.randint(1, 254)}"
        b.add(12.0 + i * 0.01, Ether(src=ROUTER[1], dst=NAS[1]) / IP(src=spoofed, dst=NAS[0])
              / TCP(sport=random.randint(1024, 65535), dport=80, flags="S"))

    # Cleartext: logins whose passwords anyone on the network can read
    tcp_session(b, 15.0, LAPTOP, NAS, 50100, 23, [
        (False, b"NAS login: "), (True, b"admin\r\n"), (False, b"Password: "), (True, b"letmein\r\n")])
    tcp_session(b, 16.0, LAPTOP, NAS, 50101, 21, [
        (False, b"220 NAS FTP ready\r\n"), (True, b"USER backup\r\n"), (True, b"PASS backup123\r\n")])
    b.add(17.0, b.frame(LAPTOP, VIDEO_SITE) / TCP(sport=50102, dport=80, flags="S", seq=3000))
    b.add(17.05, b.inbound(VIDEO_SITE, LAPTOP) / TCP(sport=80, dport=50102, flags="SA", seq=7000, ack=3001))
    b.add(17.06, b.frame(LAPTOP, VIDEO_SITE) / TCP(sport=50102, dport=80, flags="A", seq=3001, ack=7001))
    b.add(17.07, b.frame(LAPTOP, VIDEO_SITE) / TCP(sport=50102, dport=80, flags="PA", seq=3001, ack=7001)
          / Raw(b"POST /login HTTP/1.1\r\nHost: video.example.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                b"username=rajveer&password=hunter22"))

    # Brute force: a new SSH connection every 0.1 s, each one reset after a failed guess
    for i in range(30):
        t = 18.0 + i * 0.1
        sport = 42000 + i
        b.add(t, lan(ATTACKER, NAS) / TCP(sport=sport, dport=22, flags="S"))
        b.add(t + 0.002, lan(NAS, ATTACKER) / TCP(sport=22, dport=sport, flags="SA"))
        b.add(t + 0.003, lan(ATTACKER, NAS) / TCP(sport=sport, dport=22, flags="A"))
        b.add(t + 0.05, lan(NAS, ATTACKER) / TCP(sport=22, dport=sport, flags="RA"))

    # Rogue DHCP: the router answers the laptop's request, then the attacker answers too,
    # offering itself as router and DNS server
    chaddr = bytes.fromhex(LAPTOP[1].replace(":", ""))
    for t, server in ((19.0, ROUTER), (19.01, ATTACKER)):
        b.add(t, Ether(src=server[1], dst="ff:ff:ff:ff:ff:ff") / IP(src=server[0], dst="255.255.255.255")
              / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=LAPTOP[0], chaddr=chaddr)
              / DHCP(options=[("message-type", "offer"), ("server_id", server[0]), ("router", server[0]),
                              ("name_server", server[0]), "end"]))

    # ICMP redirect: "send traffic for the video site through me"
    b.add(20.0, lan(ATTACKER, LAPTOP) / ICMP(type=5, code=1, gw=ATTACKER[0])
          / IP(src=LAPTOP[0], dst=VIDEO_SITE) / TCP(sport=52344, dport=443))

    # A lookup of a blocklisted domain
    b.dns_lookup(20.5, LAPTOP, "update.malware.example", "198.51.100.66", sport=53100)

    # DNS tunneling: data hidden in 30 random-looking names under one domain
    for i in range(30):
        chunk = "".join(random.choice("abcdef0123456789") for _ in range(32))
        b.add(21.0 + i * 0.05, b.frame(LAPTOP, "8.8.8.8") / UDP(sport=53200 + i, dport=53)
              / DNS(rd=1, qd=DNSQR(qname=f"{chunk}.t.tunnel.example", qtype="TXT")))

    b.packets.sort(key=lambda p: p.time)
    return b.packets


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "samples", "attack_traffic.pcap")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    packets = build()
    wrpcap(out, packets)
    print(f"Wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main()
