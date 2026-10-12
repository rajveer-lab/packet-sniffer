"""Real-Time Packet Sniffer with Live Traffic Dashboard.

Starts packet capture in the background and serves the dashboard and a JSON
API with Flask:

    GET /               the dashboard
    GET /api/packets    newest packet records   (?after=<id>&limit=<n>)
    GET /api/stats      totals, protocol share, top hosts, bandwidth, capture status

Usage:
    python sniffer.py                          capture on the default interface
    python sniffer.py --iface "Wi-Fi"          capture on a chosen interface
    python sniffer.py --filter "tcp port 443"  only capture matching packets (BPF)
    python sniffer.py --pcap samples/sample_traffic.pcap --loop
                                               replay a capture file instead
    python sniffer.py --list-interfaces        show interfaces you can capture on
    python sniffer.py --print                  also print every packet in the terminal
"""

import argparse
import logging
import os
import time

from flask import Flask, jsonify, request, send_from_directory

from core.capture import PacketPipeline
from core.store import TrafficStore

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def create_app(store, pipeline=None):
    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")

    @app.get("/")
    def dashboard():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/api/packets")
    def packets():
        after = request.args.get("after", default=0, type=int)
        limit = request.args.get("limit", default=200, type=int)
        limit = max(1, min(limit, 1000))
        return jsonify(packets=store.packets_after(after, limit), last_id=store.last_id)

    @app.get("/api/stats")
    def stats():
        data = store.stats()
        data["capture"] = pipeline.status() if pipeline else None
        return jsonify(data)

    return app


def print_record(record):
    """One terminal line per packet, e.g.
    10:42:07  TCP   192.168.1.5 -> 203.0.113.10:443    66 B  HTTPS [SYN]"""
    clock = time.strftime("%H:%M:%S", time.localtime(record["time"]))
    dst = record["dst"] or "?"
    if record["dport"] is not None:
        dst = f"{dst}:{record['dport']}"
    flags = f" [{', '.join(record['flags'])}]" if record["flags"] else ""
    service = record["service"] or ""
    print(f"{clock}  {record['proto']:<5} {record['src'] or '?':>15} -> {dst:<22} "
          f"{record['length']:>5} B  {service}{flags}", flush=True)


def parse_args():
    parser = argparse.ArgumentParser(description="Real-time packet sniffer with a live web dashboard.")
    parser.add_argument("--iface", help="interface to capture on (default: the system's default interface)")
    parser.add_argument("--filter", help='BPF capture filter, e.g. "tcp port 80" or "udp"')
    parser.add_argument("--pcap", help="replay packets from this .pcap file instead of capturing live")
    parser.add_argument("--loop", action="store_true", help="with --pcap, replay the file forever")
    parser.add_argument("--speed", type=float, default=1.0, help="with --pcap, replay speed multiplier (0 = no delay)")
    parser.add_argument("--host", default="127.0.0.1", help="address for the dashboard server")
    parser.add_argument("--port", type=int, default=5000, help="port for the dashboard server")
    parser.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    parser.add_argument("--print", dest="print_packets", action="store_true",
                        help="also print every packet in the terminal")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_interfaces:
        from scapy.config import conf
        print(conf.ifaces)
        return

    store = TrafficStore()
    pipeline = PacketPipeline(store, on_record=print_record if args.print_packets else None)
    if args.pcap:
        pipeline.start_replay(args.pcap, speed=args.speed, loop=args.loop)
        print(f"Replaying: {args.pcap}" + (" (looping)" if args.loop else ""))
    else:
        pipeline.start_live(iface=args.iface, bpf_filter=args.filter)
        status = pipeline.status()
        print(f"Capturing on: {status['source']}" + (f"  filter: {args.filter}" if args.filter else ""))
        if status["error"]:
            print(f"WARNING: {status['error']}")

    host = "localhost" if args.host in ("127.0.0.1", "localhost") else args.host
    print(f"Dashboard: http://{host}:{args.port}")

    # Flask logs every request, and the dashboard polls twice a second.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    create_app(store, pipeline).run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
