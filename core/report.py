"""The printable report: one page summing up a capture, for saving as PDF.

Opened at /report from the dashboard. Everything on it is escaped (captured
text such as DNS names comes from the network), bars are drawn with SVG so the
page needs no inline styles or scripts, and the only script is the Print button
in /static/report.js.
"""

import time
from collections import Counter
from html import escape


def size(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def clock(epoch, with_date=False):
    return time.strftime("%Y-%m-%d %I:%M:%S %p" if with_date else "%I:%M:%S %p", time.localtime(epoch))


def bar(fraction):
    width = max(0.0, min(100.0, 100 * fraction))
    return (f'<svg class="bar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">'
            f'<rect class="track" width="100" height="8"/><rect class="fill" width="{width:.1f}" height="8"/></svg>')


def table(headers, rows, numeric=()):
    if not rows:
        return '<p class="none">None.</p>'
    head = "".join(f'<th class="{"num" if i in numeric else ""}">{escape(h)}</th>' for i, h in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(f'<td class="{"num" if i in numeric else ""}">{cell}</td>' for i, cell in enumerate(row))
        + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def ranked(title, items, total=None):
    """A list of (label, value text, amount) drawn as bars."""
    if not items:
        return f"<section><h2>{escape(title)}</h2><p class='none'>None yet.</p></section>"
    top = total or max(amount for _, _, amount in items) or 1
    rows = "".join(f'<div class="rank"><span class="name">{label}</span>{bar(amount / top)}'
                   f'<span class="value">{escape(value)}</span></div>' for label, value, amount in items)
    return f"<section><h2>{escape(title)}</h2>{rows}</section>"


def render(stats, capture, alerts, connections, flow_summary, devices, version, generated=None):
    generated = generated or time.time()
    capture = capture or {}
    counts = Counter(a["severity"] for a in alerts)
    source = escape(str(capture.get("source") or ""))
    mode = "Replay of" if capture.get("mode") == "replay" else "Live capture on"

    tiles = [
        ("Packets captured", f"{stats['total_packets']:,}"),
        ("Data captured", size(stats["total_bytes"])),
        ("Connections", f"{flow_summary.get('connections', 0):,}"),
        ("Devices seen", f"{len(devices):,}"),
        ("Alerts", f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low"),
        ("Average round trip", f"{flow_summary['avg_rtt_ms']} ms" if flow_summary.get("avg_rtt_ms") else "-"),
        ("Retransmissions", f"{flow_summary.get('retransmission_percent', 0)}% of TCP packets"),
    ]
    tile_html = "".join(f'<div class="tile"><span>{escape(k)}</span><b>{escape(v)}</b></div>' for k, v in tiles)

    alert_rows = [[
        f'<span class="sev {escape(a["severity"])}">{escape(a["severity"].upper())}</span>',
        f'<b>{escape(a["title"])}</b><br><span class="muted">{escape(a["detail"])}</span>',
        f'{escape(clock(a["time"]))}<br><span class="muted">&times;{a["count"]:,}</span>',
        escape(a.get("advice", {}).get("meaning", "")) + "<ol>" + "".join(
            f"<li>{escape(step)}</li>" for step in a.get("advice", {}).get("steps", [])) + "</ol>",
        escape(a["fixed"]["label"]) if a.get("fixed") else '<span class="muted">not applied</span>',
    ] for a in alerts]

    sites = Counter()
    for c in connections:
        sites[c.get("server_name") or c["server"]] += c["bytes_in"] + c["bytes_out"]
    busiest = sorted(connections, key=lambda c: c["bytes_in"] + c["bytes_out"], reverse=True)[:15]
    connection_rows = [[
        escape(f"{c['client']}:{c['client_port']}"),
        escape(f"{c['server']}:{c['server_port']}") + (f'<br><span class="muted">{escape(c["server_name"])}</span>'
                                                       if c.get("server_name") else ""),
        escape(c.get("app") or "-"), escape(c["proto"]), escape(c["state"]),
        escape(f"{c['rtt_ms']} ms" if c.get("rtt_ms") is not None else "-"),
        escape(size(c["bytes_out"])), escape(size(c["bytes_in"])), f"{c.get('retransmissions', 0):,}",
    ] for c in busiest]

    device_rows = [[
        escape(d.get("name") or ("This computer" if d.get("is_this_computer") else "Router" if d.get("is_router") else "-")),
        escape(d.get("maker") or "unknown"), escape(", ".join(d["addresses"]) or "-"), escape(d["mac"]),
        f"{d['packets']:,}",
    ] for d in devices[:30]]

    programs = [(escape(a["app"]), size(a["bytes"]), a["bytes"]) for a in stats.get("top_apps", [])]
    site_items = [(escape(name), size(n), n) for name, n in sites.most_common(8)]
    protocol_items = [(escape(p["name"]), f"{p['percent']}%", p["percent"]) for p in stats.get("protocols", [])]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Packet Sniffer report</title>
  <link rel="stylesheet" href="/static/report.css">
</head>
<body>
  <header>
    <div>
      <p class="kicker">Packet Sniffer {escape(version)} &middot; team Big Packet</p>
      <h1>Network traffic report</h1>
      <p class="muted">{mode} {source} &middot; {escape(clock(generated - (stats.get('uptime') or 0), True))} to
        {escape(clock(generated, True))}</p>
    </div>
    <button id="print" type="button">Print or save as PDF</button>
  </header>
  <div class="tiles">{tile_html}</div>
  <section>
    <h2>Security alerts</h2>
    {table(["Severity", "Alert", "When", "What it means and what to do", "Fix"], alert_rows)}
  </section>
  <div class="columns">
    {ranked("Top programs", programs)}
    {ranked("Top websites and servers", site_items)}
    {ranked("Protocols (share of packets)", protocol_items, total=100)}
  </div>
  <section>
    <h2>Busiest connections</h2>
    {table(["Client", "Server", "Program", "Proto", "State", "Round trip", "Sent", "Received", "Retrans."],
           connection_rows, numeric=(5, 6, 7, 8))}
  </section>
  <section>
    <h2>Devices on the network</h2>
    {table(["Name", "Maker", "Addresses", "MAC", "Packets"], device_rows, numeric=(4,))}
  </section>
  <footer>Statistics cover the last {stats.get('retention', 0) // 60} minutes of traffic; totals cover the whole
    capture. Capture only on your own device and network.</footer>
  <script src="/static/report.js"></script>
</body>
</html>
"""
