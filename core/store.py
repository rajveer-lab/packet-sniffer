"""Thread-safe store of recent packets and running traffic statistics.

The consumer thread calls ``add`` for every decoded packet while Flask
request threads read from it, so every access goes through one lock.
"""

import threading
import time
from collections import Counter, deque


class TrafficStore:
    def __init__(self, max_packets=2000, window_seconds=60, clock=time.time):
        self._lock = threading.Lock()
        self._clock = clock
        self._window = window_seconds
        self._packets = deque(maxlen=max_packets)
        self._last_id = 0
        self.started_at = clock()

        self._total_packets = 0
        self._total_bytes = 0
        self._proto_packets = Counter()
        self._proto_bytes = Counter()
        self._host_packets = Counter()
        self._host_bytes = Counter()
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
            self._proto_packets[record["proto"]] += 1
            self._proto_bytes[record["proto"]] += size

            # Source then destination; a packet a host sends to itself counts once.
            for host in dict.fromkeys(h for h in (record["src"], record["dst"]) if h is not None):
                self._host_packets[host] += 1
                self._host_bytes[host] += size

            second = int(record["time"])
            self._second_bytes[second] += size
            self._second_packets[second] += 1
            self._prune_window()
            return record

    def packets_after(self, after_id=0, limit=200):
        """Packets with id > after_id, oldest first, at most the newest ``limit``."""
        with self._lock:
            newer = []
            for record in reversed(self._packets):
                if record["id"] <= after_id or len(newer) >= limit:
                    break
                newer.append(record)
        newer.reverse()
        return newer

    def stats(self, top_hosts=5):
        with self._lock:
            self._prune_window()
            now = int(self._clock())
            total = self._total_packets

            protocols = [
                {
                    "name": name,
                    "packets": count,
                    "bytes": self._proto_bytes[name],
                    "percent": round(100 * count / total, 1) if total else 0,
                }
                for name, count in self._proto_packets.most_common()
            ]
            hosts = [
                {"host": host, "bytes": size, "packets": self._host_packets[host]}
                for host, size in self._host_bytes.most_common(top_hosts)
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
                "total_packets": total,
                "total_bytes": self._total_bytes,
                "bytes_per_sec": self._second_bytes.get(last_full, 0),
                "packets_per_sec": self._second_packets.get(last_full, 0),
                "uptime": round(self._clock() - self.started_at, 1),
                "last_id": self._last_id,
                "protocols": protocols,
                "top_hosts": hosts,
                "bandwidth": bandwidth,
            }

    def _prune_window(self):
        oldest = int(self._clock()) - self._window
        for second in [s for s in self._second_bytes if s <= oldest]:
            del self._second_bytes[second]
            del self._second_packets[second]
