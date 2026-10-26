"""Thread-safe store of recent packets and running traffic statistics.

The consumer thread calls ``add`` for every decoded packet while Flask
request threads read from it, so every access goes through one lock.

Old data decays instead of piling up:
  * a packet leaves the buffer once it is older than ``retention_seconds``,
    or when ``max_packets`` newer ones have arrived;
  * protocol share and top hosts count only the last ``retention_seconds``
    (kept as one small tally per second, dropped as it expires);
  * the bandwidth graphs (total and per program) keep only the last ``window_seconds``.
Only the lifetime totals (packets and bytes captured) keep growing.

The raw bytes of each packet are kept alongside it, for the hex view and the
.pcap download, and leave with it.
"""

import threading
import time
from collections import Counter, deque


class Tally:
    """Packets and bytes per protocol and per host."""

    def __init__(self):
        self.packets = 0
        self.proto_packets = Counter()
        self.proto_bytes = Counter()
        self.host_packets = Counter()
        self.host_bytes = Counter()
        self.app_packets = Counter()
        self.app_bytes = Counter()

    def add(self, record):
        size = record["length"]
        self.packets += 1
        self.proto_packets[record["proto"]] += 1
        self.proto_bytes[record["proto"]] += size
        # Source then destination; a packet a host sends to itself counts once.
        for host in dict.fromkeys(h for h in (record["src"], record["dst"]) if h is not None):
            self.host_packets[host] += 1
            self.host_bytes[host] += size
        if record.get("app"):
            self.app_packets[record["app"]] += 1
            self.app_bytes[record["app"]] += size

    def remove(self, other):
        # Counter's -= also drops entries that reach zero, so idle hosts disappear.
        self.packets -= other.packets
        self.proto_packets -= other.proto_packets
        self.proto_bytes -= other.proto_bytes
        self.host_packets -= other.host_packets
        self.host_bytes -= other.host_bytes
        self.app_packets -= other.app_packets
        self.app_bytes -= other.app_bytes


class TrafficStore:
    def __init__(self, max_packets=2000, window_seconds=60, retention_seconds=300, clock=time.time):
        self._lock = threading.Lock()
        self._clock = clock
        self._window = window_seconds
        self.retention = retention_seconds
        self._packets = deque(maxlen=max_packets)
        self._last_id = 0
        self.started_at = clock()

        self._total_packets = 0
        self._total_bytes = 0
        # Statistics for the retention period: one tally per whole second,
        # plus their running sum so reads never have to add them up.
        self._seconds = {}
        self._recent = Tally()
        # Sliding window: whole second -> bytes / packets seen in that second
        self._second_bytes = Counter()
        self._second_packets = Counter()
        self._second_apps = {}          # whole second -> Counter of bytes per program
        self._raw = {}                  # packet id -> (bytes, link type)

    @property
    def last_id(self):
        with self._lock:
            return self._last_id

    def add(self, record, raw=None):
        """Store one parsed packet record (and its raw bytes) and update every counter."""
        with self._lock:
            self._last_id += 1
            record = dict(record, id=self._last_id)
            if len(self._packets) == self._packets.maxlen:   # the oldest is about to drop out
                self._raw.pop(self._packets[0]["id"], None)
            self._packets.append(record)
            if raw is not None:
                self._raw[self._last_id] = raw

            size = record["length"]
            self._total_packets += 1
            self._total_bytes += size
            second = int(record["time"])
            self._seconds.setdefault(second, Tally()).add(record)
            self._recent.add(record)

            self._second_bytes[second] += size
            self._second_packets[second] += 1
            if record.get("app"):
                self._second_apps.setdefault(second, Counter())[record["app"]] += size
            self._expire()
            self._prune_window()
            return record

    def query(self, after_id=0, limit=200, match=None):
        """Packets with id > after_id that pass ``match``, oldest first, at most
        the newest ``limit``; plus the id to ask ``after`` next time."""
        with self._lock:
            self._expire()
            newer = []
            for record in reversed(self._packets):
                if record["id"] <= after_id or len(newer) >= limit:
                    break
                if match is None or match(record):
                    newer.append(record)
            last_id = self._last_id
        newer.reverse()
        return {"packets": newer, "last_id": last_id}

    def packets_after(self, after_id=0, limit=200, match=None):
        return self.query(after_id, limit, match)["packets"]

    def get(self, packet_id):
        """One stored packet and its raw bytes ((bytes, link type) or None), or None if it has decayed."""
        with self._lock:
            for record in reversed(self._packets):
                if record["id"] == packet_id:
                    return record, self._raw.get(packet_id)
        return None

    def with_raw(self, match=None):
        """Every stored packet that passes ``match``, oldest first, with its raw bytes."""
        with self._lock:
            self._expire()
            return [(r, self._raw[r["id"]]) for r in self._packets
                    if r["id"] in self._raw and (match is None or match(r))]

    def stats(self, top_hosts=5, top_apps=6, graph_apps=4):
        with self._lock:
            self._expire()
            self._prune_window()
            now = int(self._clock())
            recent = self._recent

            protocols = [
                {
                    "name": name,
                    "packets": count,
                    "bytes": recent.proto_bytes[name],
                    "percent": round(100 * count / recent.packets, 1) if recent.packets else 0,
                }
                for name, count in recent.proto_packets.most_common()
            ]
            hosts = [
                {"host": host, "bytes": size, "packets": recent.host_packets[host]}
                for host, size in recent.host_bytes.most_common(top_hosts)
            ]
            apps = [
                {"app": app, "bytes": size, "packets": recent.app_packets[app]}
                for app, size in recent.app_bytes.most_common(top_apps)
            ]
            bandwidth = [
                {
                    "t": second,
                    "bytes": self._second_bytes.get(second, 0),
                    "packets": self._second_packets.get(second, 0),
                }
                for second in range(now - self._window + 1, now + 1)
            ]
            # Bytes per second for the busiest programs of the window
            seconds = range(now - self._window + 1, now + 1)
            totals = Counter()
            for counts in self._second_apps.values():
                totals.update(counts)
            graphed = [app for app, _ in totals.most_common(graph_apps)]
            app_bandwidth = {
                "apps": graphed,
                "points": [{"t": s, "bytes": {a: self._second_apps.get(s, {}).get(a, 0) for a in graphed}}
                           for s in seconds],
            }
            # The current second is still filling up, so rates use the last full one.
            last_full = now - 1
            return {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "bytes_per_sec": self._second_bytes.get(last_full, 0),
                "packets_per_sec": self._second_packets.get(last_full, 0),
                "uptime": round(self._clock() - self.started_at, 1),
                "last_id": self._last_id,
                "retention": self.retention,
                "recent_packets": recent.packets,
                "buffered": len(self._packets),
                "protocols": protocols,
                "top_hosts": hosts,
                "top_apps": apps,
                "bandwidth": bandwidth,
                "app_bandwidth": app_bandwidth,
            }

    def _expire(self):
        """Forget packets and per-second tallies older than the retention period."""
        cutoff = self._clock() - self.retention
        while self._packets and self._packets[0]["time"] < cutoff:
            self._raw.pop(self._packets.popleft()["id"], None)
        # Seconds arrive in order, so the oldest tallies are at the front.
        while self._seconds:
            second = next(iter(self._seconds))
            if second + 1 > cutoff:
                break
            self._recent.remove(self._seconds.pop(second))

    def _prune_window(self):
        oldest = int(self._clock()) - self._window
        for second in [s for s in self._second_bytes if s <= oldest]:
            del self._second_bytes[second]
            del self._second_packets[second]
            self._second_apps.pop(second, None)
