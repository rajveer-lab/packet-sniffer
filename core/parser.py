"""Turn a captured Scapy packet into a flat record the API and dashboard can use.

Decoding follows the layers of the packet, outermost first:
    Link       Ethernet  -> source and destination MAC
    Network    IPv4/IPv6 -> source and destination IP, TTL
               ARP       -> who-has / is-at between IPs
    Transport  TCP/UDP   -> ports, TCP flags, sequence numbers
               ICMP      -> type (echo request, reply, ...), ICMPv6 and MLD
    Application DNS      -> the name asked for, and the addresses answered
               DHCP      -> message type, server, the device's name
               HTTP      -> request line and host, or response status
               TLS       -> the site name in a ClientHello (see tls_sni)
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
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

DNS_TYPES = {1: "A", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}

DHCP_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak",
              7: "release", 8: "inform"}

HTTP_PORTS = {80, 8000, 8080}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")

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


def dns_name(dns):
    from .names import label, records

    questions = records(dns.qd)
    return label(questions[0].qname) if questions else None


def dns_info(dns):
    """'DNS query A example.com' or 'DNS answer example.com = 93.184.215.14'."""
    from .names import label, records

    questions = records(dns.qd)
    if not questions:
        return "DNS"
    asked = label(questions[0].qname)
    if not dns.qr:
        return f"DNS query {DNS_TYPES.get(questions[0].qtype, questions[0].qtype)} {asked}"
    addresses = [str(a.rdata) for a in records(dns.an) if getattr(a, "type", None) in (1, 28)]
    if not addresses:
        return f"DNS answer {asked}" + (" (not found)" if dns.rcode == 3 else "")
    more = f" +{len(addresses) - 2} more" if len(addresses) > 2 else ""
    return f"DNS answer {asked} = {', '.join(addresses[:2])}{more}"


def dhcp_fields(pkt):
    """Message type, server, client MAC, offered address and device name of a DHCP packet."""
    options = {}
    for option in pkt[DHCP].options:
        if isinstance(option, tuple) and len(option) >= 2:
            options[option[0]] = option[1]
    name = options.get("hostname")
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    bootp = pkt[BOOTP]
    kind = options.get("message-type")   # a number when captured, a word when built by hand
    return {
        "dhcp_type": DHCP_TYPES.get(kind, kind if isinstance(kind, str) else None),
        "dhcp_server": options.get("server_id"),
        "dhcp_hostname": name,
        "dhcp_client_mac": ":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6]),
        "dhcp_offer": bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else None,
    }


def http_info(payload):
    """'HTTP GET example.com/login' or 'HTTP 200 OK' from the start of a TCP payload."""
    first_line = payload.split(b"\r\n", 1)[0][:200]
    if payload.startswith(HTTP_METHODS):
        method, _, rest = first_line.partition(b" ")
        path = rest.rsplit(b" ", 1)[0]
        host = b""
        for line in payload.split(b"\r\n")[1:30]:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip()
                break
        return f"HTTP {method.decode()} {(host + path).decode('ascii', 'replace')}"
    if payload.startswith(b"HTTP/1."):
        parts = first_line.split(b" ", 2)
        return "HTTP " + " ".join(p.decode("ascii", "replace") for p in parts[1:])
    return None


def tls_sni(data):
    """The site name in a TLS ClientHello (the start of every HTTPS connection), or None.

    The name is sent before encryption starts. ``data`` may be the first part of
    the message only; None then means "not seen yet".
    """
    if len(data) < 47 or data[0] != 22 or data[5] != 1:   # handshake record, ClientHello
        return None
    try:
        p = 5 + 4 + 2 + 32                                   # record + handshake headers, version, random
        p += 1 + data[p]                                     # session id
        p += 2 + int.from_bytes(data[p:p + 2], "big")        # cipher suites
        p += 1 + data[p]                                     # compression methods
        end = min(p + 2 + int.from_bytes(data[p:p + 2], "big"), len(data))
        p += 2
        while p + 4 <= end:
            kind = int.from_bytes(data[p:p + 2], "big")
            size = int.from_bytes(data[p + 2:p + 4], "big")
            p += 4
            if kind == 0 and p + 5 <= len(data):             # server_name: list length, type, name length
                length = int.from_bytes(data[p + 3:p + 5], "big")
                name = data[p + 5:p + 5 + length]
                if len(name) == length and name and all(33 <= b < 127 for b in name):
                    return name.decode("ascii").lower()
                return None
            p += size
    except IndexError:
        return None
    return None


def layer_spans(raw, linktype=1):
    """Where each header starts and ends in a packet's bytes, then its data: for the hex view.

    [{"name": "Ethernet", "start": 0, "end": 14}, {"name": "IP", "start": 14, "end": 34}, ...]
    """
    from scapy.config import conf
    from scapy.packet import NoPayload, Padding, Raw

    layer = (conf.l2types.num2layer.get(linktype) or Ether)(raw)
    spans, offset = [], 0
    while layer is not None and not isinstance(layer, NoPayload) and offset < len(raw):
        if isinstance(layer, (Raw, Padding)):
            name, size = ("Padding" if isinstance(layer, Padding) else "Data"), len(layer.load)
        else:
            name, size = layer.name, len(layer) - len(layer.payload)
        if size > 0:
            spans.append({"name": name, "start": offset, "end": min(offset + size, len(raw))})
        offset += max(size, 0)
        layer = layer.payload
    if offset < len(raw):
        spans.append({"name": "Data", "start": offset, "end": len(raw)})
    return spans


def tcp_payload(pkt):
    """The bytes a TCP segment carries (empty for every other packet)."""
    return bytes(pkt[TCP].payload) if TCP in pkt else b""


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
        "icmp_type": None,
        "arp_op": None,     # 1 = request ("who has"), 2 = reply ("is at")
        "arp_mac": None,    # MAC the ARP sender claims for its IP
        "app": None,        # program on this computer, filled in during live capture
        "src_name": None,   # names learned from DNS answers, filled in during capture
        "dst_name": None,
        "seq": None,        # TCP sequence and acknowledgement numbers
        "ack": None,
        "payload_len": 0,   # bytes of data carried above TCP or UDP
        "dns_query": None,  # the name a DNS packet asks about
        "tls_sni": None,    # the site an HTTPS connection opens, filled in during capture
        "tcp_note": None,   # "Retransmission" or "Duplicate ACK", filled in during capture
        "info": "",
    }

    # Link layer
    if Ether in pkt:
        record["src_mac"] = pkt[Ether].src
        record["dst_mac"] = pkt[Ether].dst

    # ARP sits directly on the link layer, with no IP header
    if ARP in pkt:
        arp = pkt[ARP]
        record.update(proto="ARP", src=arp.psrc, dst=arp.pdst, arp_op=arp.op, arp_mac=arp.hwsrc)
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
        payload = bytes(tcp.payload)
        record.update(proto="TCP", sport=tcp.sport, dport=tcp.dport, flags=flags,
                      seq=tcp.seq, ack=tcp.ack, payload_len=len(payload))
        record["info"] = f"{tcp.sport} -> {tcp.dport}"
        if flags:
            record["info"] += f" [{', '.join(flags)}]"
        if payload and (tcp.sport in HTTP_PORTS or tcp.dport in HTTP_PORTS):
            record["info"] = http_info(payload) or record["info"]
    elif UDP in pkt:
        udp = pkt[UDP]
        record.update(proto="UDP", sport=udp.sport, dport=udp.dport, payload_len=len(udp.payload))
        record["info"] = f"{udp.sport} -> {udp.dport}"
        try:   # a malformed message keeps the plain port info
            if DNS in pkt:
                record["info"] = dns_info(pkt[DNS])
                record["dns_query"] = dns_name(pkt[DNS])
            elif DHCP in pkt:
                record.update(dhcp_fields(pkt))
                name = f" ({record['dhcp_hostname']})" if record["dhcp_hostname"] else ""
                record["info"] = f"DHCP {record['dhcp_type'] or 'message'}{name}"
        except Exception:
            pass
    elif ICMP in pkt:
        icmp_type = pkt[ICMP].type
        record.update(proto="ICMP", icmp_type=icmp_type)
        record["info"] = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    elif record["ip_version"] == 6 and any(c.__name__.startswith("ICMPv6") for c in pkt.layers()):
        # ICMPv6 can sit behind extension headers (MLD reports come after a hop-by-hop header)
        layer = next(c for c in pkt.layers() if c.__name__.startswith("ICMPv6"))
        record["proto"] = "ICMP"
        record["info"] = pkt[layer].name
    else:
        record["info"] = pkt.lastlayer().name

    record["service"] = service_for(record["sport"], record["dport"])
    return record
