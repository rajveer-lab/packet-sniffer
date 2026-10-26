"""Real-Time Packet Sniffer with Live Traffic Dashboard.

Starts packet capture in the background and serves the dashboard and a JSON
API with Flask:

    GET /               the dashboard
    GET /api/packets    newest packet records   (?after=<id>&limit=<n>)
                        filtered by &proto=TCP &host=192.168.1.5 &port=443 &q=text
    GET /api/stats      totals, protocol share, top hosts, bandwidth, capture status
    GET /api/alerts     security alerts with advice and fixes, and the checks that raise them
    GET /api/export/packets.csv, /api/export/alerts.csv    downloads
    POST /api/defense/apply, /api/defense/undo             one-click fixes (JSON only)
    POST /api/capture/stop, /api/capture/start             stop or restart capture (JSON only)

The dashboard and API need the access code printed at startup (see core/access.py).

Usage:
    python sniffer.py                          capture on the default interface
    python sniffer.py --iface "Wi-Fi"          capture on a chosen interface
    python sniffer.py --filter "tcp port 443"  only capture matching packets (BPF)
    python sniffer.py --pcap samples/sample_traffic.pcap --loop
                                               replay a capture file instead
    python sniffer.py --duration 300           stop capturing after 5 minutes
    python sniffer.py --save                   also save packets to captures/*.pcap
    python sniffer.py --list-interfaces        show interfaces you can capture on
    python sniffer.py --print                  also print every packet in the terminal
"""

import argparse
import csv
import io
import logging
import os
import sys
import time
import webbrowser

from flask import Flask, Response, jsonify, request, send_from_directory

from core import __version__
from core.access import add_security_headers, new_token, protect
from core.capture import PacketPipeline, interface_name
from core.defense import Defender, advice, protected_addresses
from core.filters import build_filter
from core.names import NameCache
from core.processes import ProcessMap
from core.recorder import RotatingPcapWriter
from core.security import SecurityMonitor
from core.store import TrafficStore

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def csv_cell(value):
    """Text from the network could start with '=' and run as a formula in Excel; make it plain text."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def csv_download(filename, header, rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(header)
    writer.writerows([csv_cell(v) for v in row] for row in rows)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def local_time(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def create_app(store, pipeline=None, monitor=None, token=None, defender=None, names=None):
    """The Flask app; with a ``token``, the dashboard and API need that access code."""
    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")
    app.after_request(add_security_headers)
    if token:
        protect(app, token)

    def packet_filter():
        return build_filter(
            proto=request.args.get("proto"),
            host=request.args.get("host"),
            port=request.args.get("port"),
            text=request.args.get("q"),
        )

    def refuse_unless_same_site_json():
        """Actions that change something must be JSON sent by this page. A form or a
        link on another website cannot send JSON here, so it cannot trigger them."""
        if not request.is_json:
            return jsonify(ok=False, message="Send this as JSON."), 415
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            return jsonify(ok=False, message="Not allowed from another website."), 403
        return None

    @app.get("/")
    def dashboard():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/api/packets")
    def packets():
        after = request.args.get("after", default=0, type=int)
        limit = request.args.get("limit", default=200, type=int)
        limit = max(1, min(limit, 1000))
        try:
            match = packet_filter()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(store.query(after, limit, match))

    @app.get("/api/stats")
    def stats():
        data = store.stats()
        data["capture"] = pipeline.status() if pipeline else None
        data["version"] = __version__
        if names is not None:
            for host in data["top_hosts"]:
                host["name"] = names.name(host["host"])
        return jsonify(data)

    @app.get("/api/alerts")
    def alerts():
        if monitor is None:
            return jsonify(alerts=[], counts={}, rules=[], checked=0, enabled=False, defense=None)
        summary = monitor.summary()
        if defender:
            summary["alerts"] = [defender.describe(a) for a in summary["alerts"]]
        return jsonify(dict(summary, enabled=True, defense=defender.status() if defender else None))

    @app.post("/api/defense/apply")
    def apply_fix():
        refused = refuse_unless_same_site_json()
        if refused:
            return refused
        alert_id = request.get_json(silent=True).get("alert_id")
        alert = monitor.get(alert_id) if (monitor and defender and isinstance(alert_id, int)) else None
        if not alert or not alert.get("fix"):
            return jsonify(ok=False, message="That alert has no fix."), 404
        ok, message = defender.apply(alert["fix"])
        return jsonify(ok=ok, message=message, defense=defender.status()), 200 if ok else 409

    @app.post("/api/defense/undo")
    def undo_fix():
        refused = refuse_unless_same_site_json()
        if refused:
            return refused
        fix_id = request.get_json(silent=True).get("fix_id")
        if not defender or not isinstance(fix_id, int):
            return jsonify(ok=False, message="That fix is not active."), 404
        ok, message = defender.undo(fix_id)
        return jsonify(ok=ok, message=message, defense=defender.status()), 200 if ok else 409

    @app.post("/api/capture/<action>")
    def capture_control(action):
        refused = refuse_unless_same_site_json()
        if refused:
            return refused
        if pipeline is None or action not in ("start", "stop"):
            return jsonify(ok=False, message="Unknown action."), 404
        if action == "stop":
            pipeline.stop_from_dashboard()
        elif not pipeline.restart():
            return jsonify(ok=False, message="Capture is already running.", capture=pipeline.status()), 409
        return jsonify(ok=True, capture=pipeline.status())

    @app.get("/api/export/packets.csv")
    def export_packets():
        try:
            match = packet_filter()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        rows = [
            [p["id"], local_time(p["time"]), p.get("app"), p["src"], p.get("src_name"), p.get("sport"),
             p["dst"], p.get("dst_name"), p.get("dport"), p["proto"], p.get("service"), p["length"],
             p.get("flags"), p.get("info")]
            for p in store.query(0, 10**9, match)["packets"]
        ]
        header = ["id", "time", "program", "source", "source name", "source port", "destination",
                  "destination name", "destination port", "protocol", "service", "bytes", "tcp flags", "info"]
        return csv_download("packets.csv", header, rows)

    @app.get("/api/export/alerts.csv")
    def export_alerts():
        alerts = monitor.summary(limit=10**9)["alerts"] if monitor else []
        rows = []
        for alert in alerts:
            described = defender.describe(alert) if defender else dict(alert, advice=advice(alert), fixed=None)
            rows.append([alert["id"], local_time(alert["time"]), local_time(alert["last_seen"]), alert["severity"],
                         alert["title"], alert["detail"], alert["count"], described["advice"]["meaning"],
                         " ".join(described["advice"]["steps"]),
                         described["fixed"]["label"] if described["fixed"] else ""])
        header = ["id", "first seen", "last seen", "severity", "alert", "detail", "times seen",
                  "what it means", "what to do", "fix applied"]
        return csv_download("security-alerts.csv", header, rows)

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

    limits = parser.add_argument_group("limits", "keep the sniffer from collecting packets forever")
    limits.add_argument("--count", type=int, help="stop capturing after this many packets")
    limits.add_argument("--duration", type=float, help="stop capturing after this many seconds")
    limits.add_argument("--retention", type=int, default=300,
                        help="seconds a packet stays in the table and the statistics (default 300)")
    limits.add_argument("--max-packets", type=int, default=2000,
                        help="most packets kept in memory at once (default 2000)")

    saving = parser.add_argument_group("saving", "write packets to rotating .pcap files")
    saving.add_argument("--save", nargs="?", const="captures", metavar="FOLDER",
                        help="save packets as .pcap files in FOLDER (default: captures)")
    saving.add_argument("--file-size", type=float, default=10, metavar="MB",
                        help="start a new file after this many MB (default 10)")
    saving.add_argument("--keep-files", type=int, default=5, metavar="N",
                        help="keep only the newest N files, deleting older ones (default 5)")
    parser.add_argument("--no-security", action="store_true", help="turn off the security checks")
    parser.add_argument("--auto-block", action="store_true",
                        help="block attackers found by the port-scan, host-sweep and brute-force checks "
                             "straight away (needs Administrator)")
    parser.add_argument("--no-apps", action="store_true",
                        help="do not name the program behind each packet (live capture only)")

    access = parser.add_argument_group("access", "who may open the dashboard")
    access.add_argument("--token", help="access code for the dashboard (default: a new random one each run)")
    access.add_argument("--no-auth", action="store_true",
                        help="open the dashboard without an access code (only on a computer you trust)")
    access.add_argument("--open", action="store_true", help="open the dashboard in the browser at startup")
    parser.add_argument("--version", action="version", version=f"Packet Sniffer {__version__}")
    parser.add_argument("--print", dest="print_packets", action="store_true",
                        help="also print every packet in the terminal")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_interfaces:
        from scapy.config import conf
        print(conf.ifaces)
        return

    store = TrafficStore(max_packets=args.max_packets, retention_seconds=args.retention)
    monitor = None if args.no_security else SecurityMonitor()
    names = NameCache()
    defender = Defender(interface=interface_name(args.iface), protected=protected_addresses(),
                        auto_block=args.auto_block)
    if monitor:
        monitor.on_alert = defender.on_alert
    recorder = RotatingPcapWriter(args.save, args.file_size, args.keep_files) if args.save else None
    # Programs can only be named for this computer's own live traffic, not for a replayed file.
    processes = None if (args.pcap or args.no_apps) else ProcessMap()
    if processes:
        processes.start()
    pipeline = PacketPipeline(
        store,
        on_record=print_record if args.print_packets else None,
        monitor=monitor,
        recorder=recorder,
        limit_packets=args.count,
        limit_seconds=args.duration,
        processes=processes,
        names=names,
    )
    if args.pcap:
        pipeline.start_replay(args.pcap, speed=args.speed, loop=args.loop)
        print(f"Replaying: {args.pcap}" + (" (looping)" if args.loop else ""))
    else:
        pipeline.start_live(iface=args.iface, bpf_filter=args.filter)
        status = pipeline.status()
        print(f"Capturing on: {status['source']}" + (f"  filter: {args.filter}" if args.filter else ""))
        if status["error"]:
            print(f"WARNING: {status['error']}")

    print(f"Keeping: packets from the last {args.retention} s, at most {args.max_packets:,} in memory")
    if args.count or args.duration:
        stop = [f"{args.count:,} packets" if args.count else None, f"{args.duration:g} s" if args.duration else None]
        print("Stops after: " + " or ".join(s for s in stop if s))
    if recorder:
        print(f"Saving to: {os.path.abspath(args.save)}  ({args.file_size:g} MB files, newest {args.keep_files} kept)")
    print("Security checks: " + ("off" if monitor is None else "on"))
    if monitor:
        reason = defender.unavailable_reason()
        print("One-click fixes: " + ("ready" if reason is None else f"advice only. {reason}")
              + ("  Auto-block: on" if args.auto_block else ""))
    if processes:
        print("Programs: named from this computer's open connections"
              + (f" (WARNING: {processes.error})" if processes.error else ""))

    token = None if args.no_auth else (args.token or new_token())
    local = args.host in ("127.0.0.1", "localhost", "::1")
    host = "localhost" if local else args.host
    url = f"http://{host}:{args.port}/" + (f"?token={token}" if token else "")
    print(f"Dashboard: {url}")
    if token:
        print(f"Access code: {token}  (anyone with it can see the captured traffic)")
    elif not local:
        print("WARNING: no access code, and the dashboard is reachable from other computers.")

    # A double-clicked PacketSniffer.exe (no options) opens the browser itself.
    if args.open or (getattr(sys, "frozen", False) and len(sys.argv) == 1):
        webbrowser.open(url)

    # Flask logs every request, and the dashboard polls twice a second.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    try:
        app = create_app(store, pipeline, monitor, token, defender=defender, names=names)
        app.run(host=args.host, port=args.port, threaded=True)
    finally:
        pipeline.stop()   # closes the current .pcap file cleanly


if __name__ == "__main__":
    main()
