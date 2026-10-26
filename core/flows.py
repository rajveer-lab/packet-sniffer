"""Group packets into connections (conversations between two endpoints).

A TCP connection is followed through its life the way the textbook draws it:

    client  SYN  ->              state: SYN sent
            <-  SYN, ACK         state: SYN received   round-trip time = SYN-ACK time - SYN time
            ACK  ->              state: established
            ... data ...
            FIN  ->  / <- FIN    state: closing, then closed      (RST: reset)

For every connection it counts packets and bytes each way and spots two signs
of trouble on the path:

    Retransmission   a segment whose data was already sent (it was lost or its ACK was)
    Duplicate ACK    the same acknowledgement again with no data: the receiver is
                     missing a segment and asking for it
    Keep-alive       an idle connection checking the other side is still there (it
                     repeats a byte on purpose, so it is not counted as either of the above)

It also reads the site name from the first message of an HTTPS connection
(the TLS ClientHello, sent before encryption starts), collecting it across
TCP segments if it is too big for one. UDP "connections" are simply all
packets between the same two endpoints, ended by a minute of silence.

The newest ``max_flows`` connections are kept.
"""

import threading
from collections import OrderedDict

from .parser import tls_sni

TLS_PORTS = {443, 8443, 993, 995, 465}
MAX_HELLO = 16384         # largest ClientHello collected while looking for the name


class Flow:
    __slots__ = ("id", "proto", "client", "client_port", "server", "server_port", "service", "app",
                 "server_name", "sni", "first_seen", "last_seen", "packets_out", "packets_in", "bytes_out",
                 "bytes_in", "state", "syn_time", "rtt_ms", "retransmissions", "dup_acks", "keepalives",
                 "closed_by", "_fins", "_next_seq", "_last_ack", "_keepalive", "_hello", "_joined_late")

    def __init__(self, flow_id, record, client_side):
        src, sport, dst, dport = record["src"], record["sport"], record["dst"], record["dport"]
        if client_side == "src":
            self.client, self.client_port, self.server, self.server_port = src, sport, dst, dport
        else:
            self.client, self.client_port, self.server, self.server_port = dst, dport, src, sport
        self.id = flow_id
        self.proto = record["proto"]
        self.service = record.get("service")
        self.app = record.get("app")
        self.server_name = None
        self.sni = None
        self.first_seen = self.last_seen = record["time"]
        self.packets_out = self.packets_in = self.bytes_out = self.bytes_in = 0
        self.state = "active" if self.proto == "UDP" else "joined late"
        self.syn_time = None
        self.rtt_ms = None
        self.retransmissions = 0
        self.dup_acks = 0
        self.keepalives = 0
        self.closed_by = None
        self._fins = set()
        self._next_seq = {}     # direction -> end of the highest data sent
        self._last_ack = {}     # direction -> (ack number, times repeated)
        self._keepalive = {}    # direction -> a keep-alive arrived, so its reply repeats an ACK
        self._hello = b""
        self._joined_late = True

    def as_dict(self):
        out = {name: getattr(self, name) for name in self.__slots__ if not name.startswith("_")}
        out["duration"] = round(self.last_seen - self.first_seen, 3)
        out.pop("syn_time")
        return out


class FlowTable:
    def __init__(self, max_flows=2000, udp_idle_seconds=60):
        self.max_flows = max_flows
        self.udp_idle_seconds = udp_idle_seconds
        self._flows = OrderedDict()    # key -> Flow, least recently active first
        self._lock = threading.Lock()
        self._next_id = 0

    def update(self, record, payload=b""):
        """Account one packet; returns what was learned: {"flow": id, "note": ..., "sni": ...}."""
        if record["proto"] not in ("TCP", "UDP") or record["sport"] is None:
            return {}
        a, b = (record["src"], record["sport"]), (record["dst"], record["dport"])
        key = (record["proto"],) + (a + b if a <= b else b + a)
        with self._lock:
            flow = self._flows.get(key)
            if flow and self._ended(flow, record):
                # The same ports used again: keep the finished connection under its own key.
                self._flows[("ended", flow.id)] = self._flows.pop(key)
                flow = None
            if flow is None:
                flow = self._new(key, record)
            self._flows.move_to_end(key)
            return self._account(flow, record, payload)

    def connections(self, limit=300):
        with self._lock:
            flows = list(self._flows.values())[-limit:]
        return [f.as_dict() for f in reversed(flows)]

    def summary(self):
        with self._lock:
            flows = list(self._flows.values())
        tcp = [f for f in flows if f.proto == "TCP"]
        rtts = [f.rtt_ms for f in tcp if f.rtt_ms is not None]
        sent = sum(f.packets_out + f.packets_in for f in tcp)
        resent = sum(f.retransmissions for f in tcp)
        states = {}
        for f in flows:
            states[f.state] = states.get(f.state, 0) + 1
        return {
            "connections": len(flows),
            "tcp": len(tcp),
            "udp": len(flows) - len(tcp),
            "states": states,
            "avg_rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
            "retransmission_percent": round(100 * resent / sent, 2) if sent else 0,
            "dup_acks": sum(f.dup_acks for f in tcp),
        }

    # ---- internals -------------------------------------------------------------

    def _ended(self, flow, record):
        if flow.proto == "UDP":
            return record["time"] - flow.last_seen > self.udp_idle_seconds
        # A fresh SYN on a closed or reset connection starts a new one.
        return record["flags"] == ["SYN"] and flow.state in ("closed", "reset")

    def _new(self, key, record):
        self._next_id += 1
        if record["proto"] == "TCP" and record["flags"] == ["SYN"]:
            client_side = "src"
        elif record["proto"] == "TCP" and set(record["flags"]) >= {"SYN", "ACK"}:
            client_side = "dst"
        else:   # joined mid-conversation: the client is usually the side with the higher port
            client_side = "src" if record["sport"] >= record["dport"] else "dst"
        flow = Flow(self._next_id, record, client_side)
        self._flows[key] = flow
        while len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)
        return flow

    def _account(self, flow, r, payload):
        outgoing = r["src"] == flow.client and r["sport"] == flow.client_port
        size = r["length"]
        flow.last_seen = r["time"]
        if outgoing:
            flow.packets_out += 1
            flow.bytes_out += size
        else:
            flow.packets_in += 1
            flow.bytes_in += size
        flow.app = flow.app or r.get("app")
        flow.server_name = flow.server_name or (r.get("dst_name") if outgoing else r.get("src_name"))
        learned = {"flow": flow.id}
        if flow.proto != "TCP":
            return learned

        flags = set(r["flags"])
        direction = "out" if outgoing else "in"
        note = self._sequence_note(flow, r, flags, direction)
        if note:
            learned["note"] = note

        # The handshake and the end of the connection
        if flags == {"SYN"} and outgoing:
            flow.syn_time = r["time"]
            flow.state = "SYN sent"
            flow._joined_late = False
        elif flags >= {"SYN", "ACK"} and not outgoing:
            if flow.syn_time is not None and flow.rtt_ms is None:
                flow.rtt_ms = round((r["time"] - flow.syn_time) * 1000, 2)
            flow.state = "SYN received"
        elif "RST" in flags:
            flow.state = "reset"
            flow.closed_by = "client" if outgoing else "server"
        elif "FIN" in flags:
            flow._fins.add(direction)
            flow.closed_by = flow.closed_by or ("client" if outgoing else "server")
            flow.state = "closed" if len(flow._fins) == 2 else "closing"
        elif flow.state == "SYN received" and outgoing and "ACK" in flags:
            flow.state = "established"
        elif flow.state == "closing" and "ACK" in flags and len(flow._fins) == 2:
            flow.state = "closed"

        # The site name of an HTTPS connection, from the ClientHello
        if outgoing and payload and flow.sni is None and flow.server_port in TLS_PORTS and len(flow._hello) < MAX_HELLO:
            flow._hello += payload
            name = tls_sni(flow._hello)
            if name:
                flow.sni = flow.server_name = name
                flow._hello = b""
                learned["sni"] = name
            elif flow._hello[:1] != b"\x16":
                flow._hello = b""
                flow.sni = ""          # not TLS: stop looking
        return learned

    @staticmethod
    def _sequence_note(flow, r, flags, direction):
        if r["seq"] is None:
            return None
        other = "in" if direction == "out" else "out"
        length = r["payload_len"] + (1 if flags & {"SYN", "FIN"} else 0)
        highest = flow._next_seq.get(direction)
        # A keep-alive ("still there?") deliberately repeats the last byte sent, or sends
        # nothing, one below the next sequence number. It is not a lost segment.
        if (flags == {"ACK"} and r["payload_len"] <= 1 and highest is not None
                and r["seq"] == (highest - 1) % 2**32):
            flow.keepalives += 1
            flow._keepalive[other] = True        # the reply will repeat its last ACK
            return "Keep-alive"
        if length:
            end = r["seq"] + length
            if highest is not None and end <= highest and "RST" not in flags:
                flow.retransmissions += 1
                return "Retransmission"
            flow._next_seq[direction] = max(end, highest or 0)
            return None
        if flags == {"ACK"}:
            last, repeats = flow._last_ack.get(direction, (None, 0))
            if r["ack"] == last:
                if flow._keepalive.pop(direction, False):
                    return "Keep-alive ACK"
                flow._last_ack[direction] = (last, repeats + 1)
                flow.dup_acks += 1
                return "Duplicate ACK"
            flow._last_ack[direction] = (r["ack"], 0)
        return None
