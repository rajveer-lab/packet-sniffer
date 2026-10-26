"""Display filters for the packet table.

Unlike the BPF capture filter (``--filter``), which decides what is captured,
these only decide which stored packets the dashboard shows, so they can be
changed at any time without restarting capture.

    proto=TCP               one protocol (TCP, UDP, ICMP, ARP, Other); "TCP,UDP" for several
    host=192.168.1.5        packets to or from this IP or MAC address
    host=192.168.1.0/24     packets to or from any address in this subnet
    port=443                packets to or from this port
    q=dns                   text anywhere in the row (addresses, names, program, service, info)

All given conditions must match.
"""

import ipaddress


def _proto_test(proto):
    wanted = {p.strip().upper() for p in proto.split(",") if p.strip()}
    return lambda r: r["proto"].upper() in wanted


def _host_test(host):
    host = host.strip().lower()
    if "/" in host:
        try:
            network = ipaddress.ip_network(host, strict=False)
        except ValueError:
            raise ValueError(f"'{host}' is not a valid subnet, e.g. 192.168.1.0/24") from None

        def in_network(address):
            try:
                return ipaddress.ip_address(address) in network
            except ValueError:   # a MAC address, or None
                return False

        return lambda r: in_network(r["src"]) or in_network(r["dst"])

    fields = ("src", "dst", "src_mac", "dst_mac")
    return lambda r: any((r.get(f) or "").lower() == host for f in fields)


def _port_test(port):
    try:
        number = int(port)
    except ValueError:
        raise ValueError(f"'{port}' is not a port number") from None
    if not 0 <= number <= 65535:
        raise ValueError(f"port {number} is out of range (0-65535)")
    return lambda r: number in (r.get("sport"), r.get("dport"))


def _text_test(text):
    needle = text.strip().lower()

    def row_text(r):
        parts = (r.get("src"), r.get("dst"), r.get("src_name"), r.get("dst_name"), r.get("sport"),
                 r.get("dport"), r["proto"], r.get("app"), r.get("service"), r.get("info"),
                 *r.get("flags", []))
        return " ".join(str(p) for p in parts if p is not None).lower()

    return lambda r: needle in row_text(r)


def build_filter(proto=None, host=None, port=None, text=None):
    """Return a function record -> bool, or None when no condition is given.

    Raises ValueError with a readable message for a bad subnet or port.
    """
    tests = []
    if proto and proto.strip():
        tests.append(_proto_test(proto))
    if host and host.strip():
        tests.append(_host_test(host))
    if port is not None and str(port).strip():
        tests.append(_port_test(str(port).strip()))
    if text and text.strip():
        tests.append(_text_test(text))
    if not tests:
        return None
    return lambda record: all(test(record) for test in tests)
