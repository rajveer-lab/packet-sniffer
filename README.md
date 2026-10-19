# Real-Time Packet Sniffer with Live Traffic Dashboard

Computer Networks project (team Big Packet). The sniffer captures live packets from a
network interface, decodes the Ethernet, IP, TCP and UDP headers, and shows the
traffic on a web dashboard that refreshes every second. It names the program on this
computer behind each packet (chrome.exe, Spotify.exe, ...), filters the packet table,
checks every packet for common attacks and for passwords sent in clear text, keeps
the dashboard locked behind an access code, and lets old data decay so it can run for
hours without filling memory or disk.

## Download and run (Windows)

`PacketSniffer-1.0.0-windows.zip` holds a ready-made program; Python is not needed.

1. Install [Npcap](https://npcap.com) with the default options.
2. Unzip, then double-click `PacketSniffer\PacketSniffer.exe`. It starts capturing and
   opens the dashboard in your browser, already unlocked.
3. Close its window (or press Ctrl+C in it) to stop.

`HOW TO RUN.txt` in the zip has the demo commands. To make the zip yourself, see
[Building](#building).

## Setup (from source)

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
Dashboard: http://localhost:5000/?token=pV3k9q...
Access code: pV3k9q...  (anyone with it can see the captured traffic)
```

Open the printed link, then browse a website to see packets arrive.
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
| `--no-apps` | do not name the program behind each packet |
| `--token CODE` | choose the dashboard access code (default: a new random one each run) |
| `--no-auth` | no access code (only on a computer you trust) |
| `--open` | open the dashboard in the browser at startup |
| `--print` | also print every packet in the terminal |
| `--pcap FILE --loop` | replay a saved capture instead of capturing live |
| `--port 5000` | dashboard port |
| `--version` | show the version |

### Without live capture

Two crafted captures in `samples/` let you demo everything on any machine:

```
python sniffer.py --pcap samples/sample_traffic.pcap --loop
python sniffer.py --pcap samples/attack_traffic.pcap
```

- `sample_traffic.pcap`: 25 seconds of normal home traffic (DNS lookup, HTTPS video
  stream, a phone browsing, ping, ARP). It raises no security alerts.
- `attack_traffic.pcap`: 22 seconds of a network under attack (a ping sweep, a port
  scan, ARP spoofing, a SYN flood, Telnet, FTP and plain-HTTP logins, an SSH brute
  force). Every one of the seven checks raises an alert.

The dashboard marks replayed traffic clearly as **REPLAY**, not live. The files are
made by `python tools/make_sample_pcap.py` and `python tools/make_attack_pcap.py`,
which only write a file and send nothing on the network.

## Dashboard

- **Bandwidth graph**: bytes per second over the last minute. Hover over it, or use the
  arrow keys, to read any second.
- **Live packets** with filters: protocol buttons, an IP, MAC or subnet
  (`192.168.1.0/24`), a port, and a free-text search over every column. All filters
  combine. Clicking a protocol, a top host or an alert filters the table to it.
  Click **TIME** to sort newest first or oldest first (new packets then arrive at the
  bottom, as in Wireshark). Scrolling into the table holds its rows still so they can be
  read; **Back to live** returns to the newest packets.
- **APP column** and **Top applications**: the program on this computer that sent or
  received each packet, and which programs use the most traffic. Click a program to see
  only its packets.
- **Packet details**: click a row to see its program and headers, layer by layer.
- **Security**: the seven checks with their status, and the alerts they raised.
- **Protocols** and **Top hosts**: shares over the retention period (5 minutes by default).

The protocol buttons and other table filters only change what is shown, so they can be
changed at any time. The BPF `--filter` decides what is captured in the first place.

## Which program sent it?

Packets do not carry the name of the program that sent them, so during live capture the
sniffer asks the operating system instead (`core/processes.py`). Windows keeps a table
of open connections and the process that owns each one, the table `netstat -ano`
prints. It is read with psutil once a second (it takes a few milliseconds), and again
straight away when a new connection of this computer shows up:

```
TCP  172.17.76.96:53684 -> 104.18.32.47:443    chrome.exe
UDP  0.0.0.0:5353                              svchost.exe
```

Each packet is matched by its local address and port. A connection that has just
closed is remembered for a minute so its last packets are still named. On a test run
98% of the laptop's own TCP and UDP packets were named. The rest show "&mdash;": other
devices' broadcasts (no program here sent them), ICMP and ARP (they have no ports), and
connections that opened and closed between two reads. Replayed files never have names.
No administrator rights are needed.

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
| Brute-force login | one source opens 20+ connections to SSH, RDP, FTP, Telnet, SMB, VNC or a database within 60 s | high |
| Password in clear text | a password crosses the network unencrypted: FTP or POP3 `PASS`, IMAP `LOGIN`, HTTP Basic auth or a login form, or what is typed after a Telnet `Password:` prompt | high |

An ongoing attack keeps updating one alert (its count and detail) instead of flooding
the list; the same check for the same source alerts again after 60 quiet seconds.
Replies are not mistaken for probes: a SYN-ACK or RST is not a scan, and a DNS server
answering many lookups is not a UDP scan. Windows use the packets' own timestamps, so
replaying a capture gives the same alerts the live traffic did.

Only packets to or from those cleartext login ports are opened up and read, and a
password alert says who logged in where and how long the password was, never the
password itself. Encrypted traffic (HTTPS, SSH) cannot be read, which is the point.

## Protecting the dashboard

Captured traffic shows what every device on the network is doing, so the dashboard
itself is protected (`core/access.py`):

- **Access code.** Each run makes a new random 128-bit code and prints a link with it.
  Opening the link stores the code in an `HttpOnly`, `SameSite=Strict` cookie, which
  page scripts and other websites cannot read or send, and removes it from the address
  bar. Without it, the API answers 401 and the page asks for the code.
- **Guessing is slowed down.** After 5 wrong codes, that address must wait a minute.
  Codes are compared in constant time.
- **Strict browser policy.** Every response sends a Content-Security-Policy allowing
  scripts from this server only, plus headers that stop the page being framed by another
  site (clickjacking) or files being read as another type. React is served from
  `static/vendor/` rather than a CDN, so the dashboard also works with no internet.
- The server listens on `127.0.0.1` (this computer only) unless `--host` says otherwise.

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
      +--> [SecurityMonitor]  port scan, host sweep, SYN flood, ARP spoofing, cleartext,
      |                       brute force, passwords (reads cleartext login payloads only)
      +--> [RotatingPcapWriter]  optional .pcap files, oldest deleted
      ^
      |    [ProcessMap]   names the program behind each record, from the
      |                   OS connection table (live capture only)
      |
 [Flask API]       GET /api/packets   GET /api/stats   GET /api/alerts
      |            behind the access code; strict security headers
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
| `core/security.py` | the seven security checks and their alerts |
| `core/recorder.py` | saves packets to rotating .pcap files |
| `core/processes.py` | names the program on this computer behind each packet |
| `core/access.py` | access code, lockout and security headers for the dashboard |
| `static/app.jsx` | dashboard source (React) |
| `static/app.js` | the same, compiled to plain JavaScript by `tools/build.py` |
| `static/vendor/` | React and ReactDOM 18.3.1, served locally |
| `tools/build.py` | builds the dashboard, `PacketSniffer.exe` and the release zips |
| `tools/make_*.py` | scripts that generate the two sample captures |
| `tests/` | unit tests for every module |

### API

Every API call needs the access-code cookie (or answers 401), unless the sniffer runs
with `--no-auth`.

`GET /api/packets?after=120&limit=200` returns packets newer than id 120. Add
`proto=TCP`, `host=192.168.1.5` (or a subnet), `port=443` and `q=text` to filter; a bad
value returns 400 with an `error` message.

```json
{"last_id": 125, "packets": [{"id": 121, "time": 1760290927.1, "src": "192.168.1.5",
  "dst": "203.0.113.10", "proto": "TCP", "sport": 52344, "dport": 443,
  "service": "HTTPS", "flags": ["SYN"], "length": 66, "ttl": 64, "ip_version": 4,
  "src_mac": "3c:22:fb:12:34:56", "dst_mac": "00:1a:2b:3c:4d:5e",
  "icmp_type": null, "arp_op": null, "arp_mac": null, "app": "chrome.exe",
  "info": "52344 -> 443 [SYN]"}]}
```

`last_id` is the newest packet the server has, so the next request asks `after` it even
when a filter hid some packets.

`GET /api/stats` returns totals, current speed, protocol share, top hosts, top programs, the last
60 seconds of bandwidth, the retention period, the version, and the capture status
(mode, interface, errors, dropped packets, why capture stopped, saved files).

`GET /api/alerts` returns the newest alerts, counts by severity, and each check with its
number of alerts:

```json
{"enabled": true, "checked": 892, "counts": {"high": 7, "medium": 3, "low": 1},
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

83 tests cover the parser, the store and its decay, the filters, program naming, every security check
(including both sample captures: every check fires on the attack, none on normal
traffic, and no password ever appears in an alert), file rotation, capture limits, the
access code and lockout, the security headers and the API. One test fails if
`static/app.js` is older than `static/app.jsx`.

## Building

```
pip install pyinstaller
python tools/build.py
```

This needs Node.js and git as well, and makes, in `dist/`:

- `PacketSniffer/PacketSniffer.exe` with Python, Flask, Scapy and the dashboard inside,
  plus both sample captures, this README and `HOW TO RUN.txt`;
- `PacketSniffer-1.0.0-windows.zip`, that folder zipped (about 14 MB);
- `packet-sniffer-1.0.0-source.zip`, the source code of the current commit.

After editing `static/app.jsx`, run `python tools/build.py dashboard` to recompile
`static/app.js`. Downloaded files (React, and Babel for compiling) are checked against
pinned SHA-256 hashes.

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
| Brute-force and cleartext-password detection | done |
| Program behind each packet: APP column, top applications | done |
| Dashboard access code, lockout and security headers | done |
| Offline dashboard, Windows .exe and release zips | done |
| Testing on live traffic | done |
| Final report | next |

Capture only on your own device and network.
