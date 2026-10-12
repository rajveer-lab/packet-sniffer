# Real-Time Packet Sniffer with Live Traffic Dashboard

Computer Networks project (team Big Packet). The sniffer captures live packets from a
network interface, decodes the Ethernet, IP, TCP and UDP headers, and shows the
traffic on a web dashboard that refreshes every second.

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
Dashboard: http://localhost:5000
```

Open http://localhost:5000, then browse a website to see packets arrive.
If no packets appear on Windows, run the terminal as Administrator.

| Option | What it does |
|---|---|
| `--iface "Wi-Fi"` | capture on a chosen interface (`--list-interfaces` shows them) |
| `--filter "tcp port 443"` | BPF capture filter, applied before packets reach Python |
| `--print` | also print every packet in the terminal |
| `--pcap FILE --loop` | replay a saved capture instead of capturing live |
| `--port 5000` | dashboard port |

### Without live capture

`samples/sample_traffic.pcap` holds 25 seconds of crafted home traffic (DNS lookup,
HTTPS video stream, a phone browsing, ping, ARP). Replay it with:

```
python sniffer.py --pcap samples/sample_traffic.pcap --loop
```

The dashboard marks this clearly as **REPLAY**, not live. Regenerate the file with
`python tools/make_sample_pcap.py`.

## How it works

```
 network card
      |
 [capture thread]  Scapy sniff() over Npcap/libpcap, optional BPF filter
      |  raw packets
   [queue]         producer-consumer: capture never waits for decoding
      |
 [consumer thread] parse_packet(): Ethernet -> IPv4/IPv6/ARP -> TCP/UDP/ICMP
      |  records
 [TrafficStore]    last 2000 packets, protocol and host counters,
      |            60-second sliding window of bytes per second
 [Flask API]       GET /api/packets?after=<id>   GET /api/stats
      |  JSON, polled every second
 [React dashboard] live table, protocol share, top hosts, packet details
```

| File | Role |
|---|---|
| `sniffer.py` | entry point: command-line options, Flask API, serves the dashboard |
| `core/capture.py` | capture and replay threads, queue, consumer |
| `core/parser.py` | decodes one packet into a record, layer by layer |
| `core/store.py` | thread-safe packet buffer and statistics |
| `static/` | dashboard (React, loaded from a CDN, so there is no build step) |
| `tests/` | unit tests for every module |

### API

`GET /api/packets?after=120&limit=200` returns packets newer than id 120:

```json
{"last_id": 125, "packets": [{"id": 121, "time": 1760290927.1, "src": "192.168.1.5",
  "dst": "203.0.113.10", "proto": "TCP", "sport": 52344, "dport": 443,
  "service": "HTTPS", "flags": ["SYN"], "length": 66, "ttl": 64, "ip_version": 4,
  "src_mac": "3c:22:fb:12:34:56", "dst_mac": "00:1a:2b:3c:4d:5e", "info": "52344 -> 443 [SYN]"}]}
```

`GET /api/stats` returns totals, current speed, protocol share, top hosts, the last
60 seconds of bandwidth, and the capture status (mode, interface, errors, dropped packets).

## Tests

```
python -m pytest
```

## Progress

| Milestone | Status |
|---|---|
| Literature survey, requirements, architecture | done |
| Live capture with Scapy, BPF filters, pcap replay | done |
| Header parsing: Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP | done |
| Flask API: packet records, protocol and host counters, bandwidth window | done |
| Dashboard: live table, protocol share, top hosts, packet details, pause | done |
| Bandwidth-over-time graph and table filters | next |
| Port-scan alert, testing on live traffic, report | next |

Capture only on your own device and network.
