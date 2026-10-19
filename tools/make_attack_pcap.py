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

Run:  python tools/make_attack_pcap.py [output.pcap]
"""

import os
import random
import sys

from scapy.layers.inet import ICMP, IP, TCP
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
    b.add(t, lan(client, server) / TCP(sport=sport, dport=dport, flags="S"))
    b.add(t + 0.002, lan(server, client) / TCP(sport=dport, dport=sport, flags="SA"))
    b.add(t + 0.003, lan(client, server) / TCP(sport=sport, dport=dport, flags="A"))
    for i, (from_client, text) in enumerate(lines):
        at = t + 0.2 * (i + 1)
        if from_client:
            b.add(at, lan(client, server) / TCP(sport=sport, dport=dport, flags="PA") / Raw(text))
        else:
            b.add(at, lan(server, client) / TCP(sport=dport, dport=sport, flags="PA") / Raw(text))


def build():
    random.seed(66)
    b = Builder()

    # Normal traffic: the router answers ARP, the laptop browses over HTTPS
    b.add(0.0, Ether(src=ROUTER[1], dst=LAPTOP[1]) / ARP(op=2, hwsrc=ROUTER[1], psrc=ROUTER[0],
                                                        hwdst=LAPTOP[1], pdst=LAPTOP[0]))
    b.dns_lookup(0.3, LAPTOP, "video.example.com", VIDEO_SITE, sport=53011)
    b.handshake(0.4, LAPTOP, VIDEO_SITE, sport=52344)
    b.download(1.0, 18, LAPTOP, VIDEO_SITE, sport=52344, start_rate=8, end_rate=12)

    # Host sweep: ping every address from .1 to .40; three hosts answer
    for i in range(1, 41):
        target = f"192.168.1.{i}"
        t = 2.0 + i * 0.03
        b.add(t, Ether(src=ATTACKER[1], dst="ff:ff:ff:ff:ff:ff") / IP(src=ATTACKER[0], dst=target)
              / ICMP(type=8, id=66, seq=i))
        if target in (ROUTER[0], LAPTOP[0], NAS[0]):
            b.add(t + 0.002, Ether(dst=ATTACKER[1], src="00:00:00:00:00:01") / IP(src=target, dst=ATTACKER[0])
                  / ICMP(type=0, id=66, seq=i))

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
    b.add(17.0, b.frame(LAPTOP, VIDEO_SITE) / TCP(sport=50102, dport=80, flags="S"))
    b.add(17.05, b.inbound(VIDEO_SITE, LAPTOP) / TCP(sport=80, dport=50102, flags="SA"))
    b.add(17.06, b.frame(LAPTOP, VIDEO_SITE) / TCP(sport=50102, dport=80, flags="A"))
    b.add(17.07, b.frame(LAPTOP, VIDEO_SITE) / TCP(sport=50102, dport=80, flags="PA")
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
