from core.flows import FlowTable

C, S = "192.168.1.5", "203.0.113.10"


def tcp(t, src, sport, dst, dport, flags, seq=0, ack=0, data=0, **extra):
    record = {"time": t, "proto": "TCP", "src": src, "sport": sport, "dst": dst, "dport": dport,
              "flags": list(flags), "seq": seq, "ack": ack, "payload_len": data, "length": 54 + data,
              "service": "HTTPS"}
    record.update(extra)
    return record


def out(t, flags, seq, ack, data=0):
    return tcp(t, C, 52344, S, 443, flags, seq, ack, data)


def back(t, flags, seq, ack, data=0):
    return tcp(t, S, 443, C, 52344, flags, seq, ack, data)


def test_a_connection_from_handshake_to_close():
    flows = FlowTable()
    flows.update(out(100.000, ["SYN"], 1000, 0))
    assert flows.connections()[0]["state"] == "SYN sent"
    flows.update(back(100.030, ["SYN", "ACK"], 5000, 1001))
    flows.update(out(100.031, ["ACK"], 1001, 5001))
    flows.update(out(100.040, ["PSH", "ACK"], 1001, 5001, data=500))
    flows.update(back(100.080, ["PSH", "ACK"], 5001, 1501, data=1200))
    (conn,) = flows.connections()
    assert (conn["state"], conn["rtt_ms"]) == ("established", 30.0)
    assert (conn["client"], conn["client_port"], conn["server"], conn["server_port"]) == (C, 52344, S, 443)
    assert (conn["packets_out"], conn["packets_in"], conn["bytes_out"], conn["bytes_in"]) == (3, 2, 54 * 2 + 554, 54 + 1254)
    flows.update(out(101.0, ["FIN", "ACK"], 1501, 6201))
    assert flows.connections()[0]["state"] == "closing"
    flows.update(back(101.02, ["FIN", "ACK"], 6201, 1502))
    flows.update(out(101.03, ["ACK"], 1502, 6202))
    conn = flows.connections()[0]
    assert (conn["state"], conn["closed_by"], conn["duration"]) == ("closed", "client", 1.03)


def test_retransmissions_and_duplicate_acks():
    flows = FlowTable()
    for record in (out(1, ["SYN"], 0, 0), back(1.01, ["SYN", "ACK"], 0, 1), out(1.02, ["ACK"], 1, 1)):
        flows.update(record)
    assert flows.update(out(2, ["PSH", "ACK"], 1, 1, data=100)) == {"flow": 1}
    assert flows.update(out(2.5, ["PSH", "ACK"], 1, 1, data=100))["note"] == "Retransmission"
    assert flows.update(back(3, ["ACK"], 1, 101)) == {"flow": 1}
    assert flows.update(back(3.1, ["ACK"], 1, 101))["note"] == "Duplicate ACK"
    assert flows.update(back(3.2, ["ACK"], 1, 101))["note"] == "Duplicate ACK"
    conn = flows.connections()[0]
    assert (conn["retransmissions"], conn["dup_acks"]) == (1, 2)
    summary = flows.summary()
    assert summary["retransmission_percent"] == round(100 * 1 / 8, 2)
    assert (summary["avg_rtt_ms"], summary["dup_acks"]) == (10.0, 2)


def test_reset_and_a_new_connection_on_the_same_ports():
    flows = FlowTable()
    flows.update(out(1, ["SYN"], 0, 0))
    flows.update(back(1.01, ["RST", "ACK"], 0, 1))
    assert flows.connections()[0]["state"] == "reset"
    flows.update(out(5, ["SYN"], 900, 0))
    assert [c["state"] for c in flows.connections()] == ["SYN sent", "reset"]


def test_joining_a_connection_late_and_udp():
    flows = FlowTable(udp_idle_seconds=60)
    flows.update(back(1, ["ACK"], 50, 60, data=1000))
    conn = flows.connections()[0]
    assert (conn["client"], conn["server_port"], conn["state"]) == (C, 443, "joined late")
    udp = {"time": 10, "proto": "UDP", "src": C, "sport": 53011, "dst": "8.8.8.8", "dport": 53,
           "flags": [], "seq": None, "ack": None, "payload_len": 30, "length": 72, "service": "DNS"}
    flows.update(udp)
    flows.update(dict(udp, time=10.02, src="8.8.8.8", sport=53, dst=C, dport=53011))
    flows.update(dict(udp, time=200))                       # a minute of silence: a new "connection"
    assert [c["proto"] for c in flows.connections()] == ["UDP", "UDP", "TCP"]
    assert flows.connections()[1]["packets_in"] == 1


def test_https_site_name_is_read_from_a_client_hello_split_over_two_segments():
    from tests.test_parser import client_hello

    hello = client_hello("vtop.vit.ac.in")
    flows = FlowTable()
    flows.update(out(1, ["SYN"], 0, 0))
    first = flows.update(out(1.1, ["PSH", "ACK"], 1, 1, data=40), payload=hello[:40])
    assert "sni" not in first
    second = flows.update(out(1.2, ["PSH", "ACK"], 41, 1, data=len(hello) - 40), payload=hello[40:])
    assert second["sni"] == "vtop.vit.ac.in"
    assert flows.connections()[0]["server_name"] == "vtop.vit.ac.in"


def test_only_the_newest_connections_are_kept():
    flows = FlowTable(max_flows=3)
    for port in range(5):
        flows.update(tcp(port, C, 50000 + port, S, 443, ["SYN"]))
    assert [c["client_port"] for c in flows.connections()] == [50004, 50003, 50002]


def test_keep_alives_are_not_retransmissions_or_duplicate_acks():
    flows = FlowTable()
    for record in (out(1, ["SYN"], 0, 0), back(1.01, ["SYN", "ACK"], 0, 1), out(1.02, ["ACK"], 1, 1),
                   out(1.1, ["PSH", "ACK"], 1, 1, data=100), back(1.2, ["ACK"], 1, 101)):
        flows.update(record)
    # Every 45 s: one byte at the last sequence number, and the reply acknowledging it again
    for t in (46, 91):
        assert flows.update(out(t, ["ACK"], 100, 1, data=1))["note"] == "Keep-alive"
        assert flows.update(back(t + 0.03, ["ACK"], 1, 101))["note"] == "Keep-alive ACK"
    conn = flows.connections()[0]
    assert (conn["retransmissions"], conn["dup_acks"], conn["keepalives"]) == (0, 0, 2)
    # A real retransmission is still caught
    assert flows.update(out(92, ["PSH", "ACK"], 1, 1, data=100))["note"] == "Retransmission"
