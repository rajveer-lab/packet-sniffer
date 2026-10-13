"""Thread-safe store of recent packets and running traffic statistics.

The consumer thread calls ``add`` for every decoded packet while Flask
request threads read from it, so every access goes through one lock.

Old data decays instead of piling up:
  * a packet leaves the buffer once it is older than ``retention_seconds``,
    or when ``max_packets`` newer ones have arrived;
  * protocol share and top hosts count only the last ``retention_seconds``
    (kept as one small tally per second, dropped as it expires);
  * the bandwidth graph keeps only the last ``window_seconds``.
Only the lifetime totals (packets and bytes captured) keep growing.
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

    def add(self, record):
        size = record["length"]
        self.packets += 1
        self.proto_packets[record["proto"]] += 1
        self.proto_bytes[record["proto"]] += size
        # Source then destination; a packet a host sends to itself counts once.
        for host in dict.fromkeys(h for h in (record["src"], record["dst"]) if h is not None):
            self.host_packets[host] += 1
            self.host_bytes[host] += size

    def remove(self, other):
        # Counter's -= also drops entries that reach zero, so idle hosts disappear.
        self.packets -= other.packets
        self.proto_packets -= other.proto_packets
        self.proto_bytes -= other.proto_bytes
        self.host_packets -= other.host_packets
        self.host_bytes -= other.host_bytes


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

    @property
    def last_id(self):
        with self._lock:
            return self._last_id

    def add(self, record):
        """Store one parsed packet record and update every counter."""
        with self._lock:
            self._last_id += 1
            record = dict(record, id=self._last_id)
            self._packets.append(record)

            size = record["length"]
            self._total_packets += 1
            self._total_bytes += size
            second = int(record["time"])
            self._seconds.setdefault(second, Tally()).add(record)
            self._recent.add(record)

            self._second_bytes[second] += size
            self._second_packets[second] += 1
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

    def stats(self, top_hosts=5):
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
            bandwidth = [
                {
                    "t": second,
                    "bytes": self._second_bytes.get(second, 0),
                    "packets": self._second_packets.get(second, 0),
                }
                for second in range(now - self._window + 1, now + 1)
            ]
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
                "bandwidth": bandwidth,
            }

    def _expire(self):
        """Forget packets and per-second tallies older than the retention period."""
        cutoff = self._clock() - self.retention
        while self._packets and self._packets[0]["time"] < cutoff:
            self._packets.popleft()
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
