# Real-Time Packet Sniffer with Live Traffic Dashboard

Computer Networks project (team Big Packet). The sniffer captures live packets from a
network interface, decodes the Ethernet, IP, TCP and UDP headers, and shows the
traffic on a web dashboard that refreshes every second. It filters the packet table,
checks every packet for common attacks, and lets old data decay so it can run for
hours without filling memory or disk.

## Setup

1. Install Python 3.10 or newer.
2. Install the libraries:
   ```
   pip install -r requirements.txt
   ```
3. **Windows only:** install [Npcap](https://npcap.com) (the capture driver Wireshark also
   uses). Keep the default options. Without it Windows cannot capture packets, and the
   dashboard will tell you so.

## Run

```
python sniffer.py
```

```
Capturing on: Wi-Fi
Keeping: packets from the last 300 s, at most 2,000 in memory
Security checks: on
Dashboard: http://localhost:5000
```

Open http://localhost:5000, then browse a website to see packets arrive.
If no packets appear on Windows, run the terminal as Administrator.

| Option | What it does |
|---|---|
| `--iface "Wi-Fi"` | capture on a chosen interface (`--list-interfaces` shows them) |
| `--filter "tcp port 443"` | BPF capture filter, applied before packets reach Python |
| `--count 5000` | stop capturing after 5,000 packets |
| `--duration 600` | stop capturing after 10 minutes |
| `--retention 300` | seconds a packet stays in the table and the statistics |
| `--max-packets 2000` | most packets kept in memory at once |
| `--save [FOLDER]` | also save packets to rotating .pcap files (default folder `captures`) |
| `--file-size 10 --keep-files 5` | with `--save`: new file every 10 MB, keep only the newest 5 |
| `--no-security` | turn off the security checks |
| `--print` | also print every packet in the terminal |
| `--pcap FILE --loop` | replay a saved capture instead of capturing live |
| `--port 5000` | dashboard port |

### Without live capture

Two crafted captures in `samples/` let you demo everything on any machine:

```
python sniffer.py --pcap samples/sample_traffic.pcap --loop
python sniffer.py --pcap samples/attack_traffic.pcap
```

- `sample_traffic.pcap`: 25 seconds of normal home traffic (DNS lookup, HTTPS video
  stream, a phone browsing, ping, ARP). It raises no security alerts.
- `attack_traffic.pcap`: 20 seconds of a network under attack (a ping sweep, a port
  scan, ARP spoofing, a SYN flood, Telnet and FTP logins). It raises one alert for
  every check.

The dashboard marks replayed traffic clearly as **REPLAY**, not live. The files are
made by `python tools/make_sample_pcap.py` and `python tools/make_attack_pcap.py`,
which only write a file and send nothing on the network.

## Dashboard

- **Bandwidth graph**: bytes per second over the last minute. Hover over it, or use the
  arrow keys, to read any second.
- **Live packets** with filters: protocol buttons, an IP, MAC or subnet
  (`192.168.1.0/24`), a port, and a free-text search over every column. All filters
  combine. Clicking a protocol, a top host or an alert filters the table to it.
- **Packet details**: click a row to see its headers decoded layer by layer.
- **Security**: the five checks with their status, and the alerts they raised.
- **Protocols** and **Top hosts**: shares over the retention period (5 minutes by default).

The protocol buttons and other table filters only change what is shown, so they can be
changed at any time. The BPF `--filter` decides what is captured in the first place.

## Security checks

Every decoded packet goes through `core/security.py`. Each check looks at a short
sliding window of traffic:

| Check | Raises an alert when | Severity |
|---|---|---|
| Port scan | one source probes 15+ ports on one host within 10 s (SYN, FIN, NULL, Xmas or UDP probes) | high |
| Host sweep | one source pings or ARP-probes 10+ addresses within 10 s | medium |
| SYN flood | 100+ connection requests reach one server port within 5 s | high |
| ARP spoofing | an IP address starts answering from a different MAC address | high |
| Cleartext | Telnet, FTP, POP3, IMAP or HTTP carries data, so logins can be read | medium / low (HTTP) |

An ongoing attack keeps updating one alert (its count and detail) instead of flooding
the list; the same check for the same source alerts again after 60 quiet seconds.
Replies are not mistaken for probes: a SYN-ACK or RST is not a scan, and a DNS server
answering many lookups is not a UDP scan. Windows use the packets' own timestamps, so
replaying a capture gives the same alerts the live traffic did.

## Keeping data under control

The sniffer never keeps collecting forever:

- **Packets decay.** A packet leaves the table after `--retention` seconds (or when
  `--max-packets` newer ones arrive). Protocol share and top hosts count only that same
  period, kept as one small tally per second that is dropped as it expires. The
  bandwidth graph keeps 60 seconds. Only the lifetime totals keep growing.
- **Capture can stop by itself** after `--count` packets or `--duration` seconds. The
  dashboard then shows **STOPPED** and why.
- **Saved files rotate.** With `--save`, packets go to `captures/capture-<time>-001.pcap`
  (open them in Wireshark). A new file starts every `--file-size` MB and the oldest are
  deleted so only `--keep-files` remain, so disk use stays under about
  `file-size x keep-files` MB. Other files in that folder are never touched.
- Security tracking state is cleaned up as it goes quiet, and at most 200 alerts are kept.

## How it works

```
 network card
      |
 [capture thread]  Scapy sniff() over Npcap/libpcap, optional BPF filter,
      |            stops by itself at --count / --duration
      |  raw packets
   [queue]         producer-consumer: capture never waits for decoding
      |
 [consumer thread] parse_packet(): Ethernet -> IPv4/IPv6/ARP -> TCP/UDP/ICMP
      |  records
      +--> [TrafficStore]     recent packets, protocol and host tallies, bandwidth;
      |                       everything older than the retention period decays
      +--> [SecurityMonitor]  port scan, host sweep, SYN flood, ARP spoofing, cleartext
      +--> [RotatingPcapWriter]  optional .pcap files, oldest deleted
      |
 [Flask API]       GET /api/packets   GET /api/stats   GET /api/alerts
      |  JSON, polled every second
 [React dashboard] bandwidth graph, filtered packet table, security panel,
                   protocol share, top hosts, packet details
```

| File | Role |
|---|---|
| `sniffer.py` | entry point: command-line options, Flask API, serves the dashboard |
| `core/capture.py` | capture and replay threads, queue, consumer, capture limits |
| `core/parser.py` | decodes one packet into a record, layer by layer |
| `core/store.py` | thread-safe packet buffer and statistics, with decay |
| `core/filters.py` | protocol, host, subnet, port and text filters for the table |
| `core/security.py` | the five security checks and their alerts |
| `core/recorder.py` | saves packets to rotating .pcap files |
| `static/` | dashboard (React, loaded from a CDN, so there is no build step) |
| `tools/` | scripts that generate the two sample captures |
| `tests/` | unit tests for every module |

### API

`GET /api/packets?after=120&limit=200` returns packets newer than id 120. Add
`proto=TCP`, `host=192.168.1.5` (or a subnet), `port=443` and `q=text` to filter; a bad
value returns 400 with an `error` message.

```json
{"last_id": 125, "packets": [{"id": 121, "time": 1760290927.1, "src": "192.168.1.5",
  "dst": "203.0.113.10", "proto": "TCP", "sport": 52344, "dport": 443,
  "service": "HTTPS", "flags": ["SYN"], "length": 66, "ttl": 64, "ip_version": 4,
  "src_mac": "3c:22:fb:12:34:56", "dst_mac": "00:1a:2b:3c:4d:5e",
  "icmp_type": null, "arp_op": null, "arp_mac": null, "info": "52344 -> 443 [SYN]"}]}
```

`last_id` is the newest packet the server has, so the next request asks `after` it even
when a filter hid some packets.

`GET /api/stats` returns totals, current speed, protocol share, top hosts, the last
60 seconds of bandwidth, the retention period, and the capture status (mode, interface,
errors, dropped packets, why capture stopped, saved files).

`GET /api/alerts` returns the newest alerts, counts by severity, and each check with its
number of alerts:

```json
{"enabled": true, "checked": 772, "counts": {"high": 3, "medium": 3, "low": 1},
 "alerts": [{"id": 2, "rule": "port_scan", "severity": "high",
   "title": "Port scan from 192.168.1.66",
   "detail": "150 TCP ports probed on 192.168.1.5 within 10 s",
   "src": "192.168.1.66", "dst": "192.168.1.5", "focus": "192.168.1.66",
   "time": 1760000005.0, "last_seen": 1760000006.5, "count": 136}],
 "rules": [{"rule": "port_scan", "name": "Port scan", "severity": "high", "alerts": 1,
   "description": "one source probes 15+ ports on a host within 10 s"}]}
```

## Tests

```
python -m pytest
```

57 tests cover the parser, the store and its decay, the filters, every security check
(including both sample captures: every check fires on the attack, none on normal
traffic), file rotation, capture limits and the API.

## Progress

| Milestone | Status |
|---|---|
| Literature survey, requirements, architecture | done |
| Live capture with Scapy, BPF filters, pcap replay | done |
| Header parsing: Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP | done |
| Flask API: packet records, protocol and host counters, bandwidth window | done |
| Dashboard: live table, protocol share, top hosts, packet details, pause | done |
| Bandwidth-over-time graph and table filters | done |
| Data decay, capture limits, rotating .pcap files | done |
| Security checks: port scan, host sweep, SYN flood, ARP spoofing, cleartext | done |
| Testing on live traffic | done |
| Final report | next |

Capture only on your own device and network.
