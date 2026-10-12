"""Turn a captured Scapy packet into a flat record the API and dashboard can use.

Decoding follows the layers of the packet, outermost first:
    Link       Ethernet  -> source and destination MAC
    Network    IPv4/IPv6 -> source and destination IP, TTL
               ARP       -> who-has / is-at between IPs
    Transport  TCP/UDP   -> ports, TCP flags
               ICMP      -> type (echo request, reply, ...)
"""

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# Well-known ports, used only to label rows in the packet table.
SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 137: "NETBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP", 3306: "MYSQL", 3389: "RDP", 5353: "MDNS", 5355: "LLMNR",
    8080: "HTTP-ALT",
}

# Same order Wireshark uses, so SYN+ACK reads "[SYN, ACK]" and PSH+ACK "[PSH, ACK]".
TCP_FLAG_NAMES = [
    ("F", "FIN"), ("S", "SYN"), ("R", "RST"),
    ("P", "PSH"), ("A", "ACK"), ("U", "URG"),
]

ICMP_TYPES = {
    0: "Echo reply", 3: "Destination unreachable", 5: "Redirect",
    8: "Echo request", 11: "Time exceeded",
}


def service_for(sport, dport):
    """Name the service by the lower well-known port, e.g. 52344 -> 443 is HTTPS."""
    for port in sorted(p for p in (sport, dport) if p is not None):
        if port in SERVICES:
            return SERVICES[port]
    return None


def tcp_flag_names(flags):
    text = str(flags)
    return [name for letter, name in TCP_FLAG_NAMES if letter in text]


def parse_packet(pkt, timestamp=None):
    """Return a dict describing one packet.

    ``timestamp`` overrides the capture time (used when replaying a pcap so
    that old packets show up as live traffic).
    """
    record = {
        "time": float(timestamp if timestamp is not None else pkt.time),
        "length": len(pkt),
        "src_mac": None,
        "dst_mac": None,
        "src": None,
        "dst": None,
        "ip_version": None,
        "ttl": None,
        "proto": "Other",
        "sport": None,
        "dport": None,
        "service": None,
        "flags": [],
        "info": "",
    }

    # Link layer
    if Ether in pkt:
        record["src_mac"] = pkt[Ether].src
        record["dst_mac"] = pkt[Ether].dst

    # ARP sits directly on the link layer, with no IP header
    if ARP in pkt:
        arp = pkt[ARP]
        record.update(proto="ARP", src=arp.psrc, dst=arp.pdst)
        if arp.op == 1:
            record["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            record["info"] = f"{arp.psrc} is at {arp.hwsrc}"
        return record

    # Network layer
    if IP in pkt:
        ip = pkt[IP]
        record.update(src=ip.src, dst=ip.dst, ip_version=4, ttl=ip.ttl)
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        record.update(src=ip.src, dst=ip.dst, ip_version=6, ttl=ip.hlim)
    else:
        record["info"] = pkt.lastlayer().name
        if record["src"] is None:
            record["src"] = record["src_mac"]
            record["dst"] = record["dst_mac"]
        return record

    # Transport layer
    if TCP in pkt:
        tcp = pkt[TCP]
        flags = tcp_flag_names(tcp.flags)
        record.update(proto="TCP", sport=tcp.sport, dport=tcp.dport, flags=flags)
        record["info"] = f"{tcp.sport} -> {tcp.dport}"
        if flags:
            record["info"] += f" [{', '.join(flags)}]"
    elif UDP in pkt:
        udp = pkt[UDP]
        record.update(proto="UDP", sport=udp.sport, dport=udp.dport)
        record["info"] = f"{udp.sport} -> {udp.dport}"
    elif ICMP in pkt:
        icmp_type = pkt[ICMP].type
        record["proto"] = "ICMP"
        record["info"] = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    elif record["ip_version"] == 6 and ip.nh == 58:
        record["proto"] = "ICMP"
        record["info"] = pkt.lastlayer().name
    else:
        record["info"] = pkt.lastlayer().name

    record["service"] = service_for(record["sport"], record["dport"])
    return record
