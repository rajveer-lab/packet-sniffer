"""Save captured packets to disk without ever filling it up.

Packets are written to .pcap files (they open in Wireshark) in one folder:

    captures/capture-20261013-101500-001.pcap
    captures/capture-20261013-101942-002.pcap   <- a new file every max_mb
    ...

Whenever a new file starts, the oldest ones are deleted so that at most
``keep_files`` remain. A capture left running for days therefore never uses
more than about ``max_mb * keep_files`` of disk: old traffic decays away.
"""

import glob
import os
import threading
import time

from scapy.utils import PcapWriter

FILE_HEADER = 24     # bytes at the start of every pcap file
PACKET_HEADER = 16   # bytes before every packet in a pcap file


class RotatingPcapWriter:
    def __init__(self, folder, max_mb=10, keep_files=5, prefix="capture", clock=time.time):
        self.folder = folder
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.keep_files = max(1, int(keep_files))
        self.prefix = prefix
        self._clock = clock
        self._lock = threading.Lock()
        self._writer = None
        self._path = None
        self._size = 0
        self._sequence = 0
        self._last_flush = 0
        self._closed = False
        self.written = 0
        self.deleted = 0
        self.error = None
        os.makedirs(folder, exist_ok=True)

    def write(self, pkt):
        with self._lock:
            if self.error or self._closed:
                return
            try:
                size = PACKET_HEADER + len(pkt)
                if self._writer is None or (self._size + size > self.max_bytes and self._size > FILE_HEADER):
                    self._rotate()
                self._writer.write(pkt)
                self._size += size
                self.written += 1
                # Flush about once a second, so a killed sniffer loses little.
                now = self._clock()
                if now - self._last_flush >= 1:
                    self._writer.flush()
                    self._last_flush = now
            except OSError as exc:
                self.error = f"Stopped saving packets: {exc}"

    def close(self):
        """Finish the current file; packets that still arrive afterwards are ignored."""
        with self._lock:
            self._closed = True
            if self._writer:
                self._writer.close()
                self._writer = None

    def files(self):
        """Saved capture files, oldest first (names start with the time)."""
        pattern = os.path.join(glob.escape(self.folder), f"{glob.escape(self.prefix)}-*.pcap")
        return sorted(glob.glob(pattern))

    def status(self):
        with self._lock:
            files = self.files()
            return {
                "folder": self.folder,
                "file": self._path,
                "files": len(files),
                "bytes": sum(os.path.getsize(f) for f in files if os.path.exists(f)),
                "max_mb": self.max_bytes / 1024 / 1024,
                "keep_files": self.keep_files,
                "written": self.written,
                "deleted": self.deleted,
                "error": self.error,
            }

    def _rotate(self):
        if self._writer:
            self._writer.close()
        self._sequence += 1
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self._clock()))
        self._path = os.path.join(self.folder, f"{self.prefix}-{stamp}-{self._sequence:03d}.pcap")
        self._writer = PcapWriter(self._path, sync=False)
        self._size = FILE_HEADER
        for old in self.files()[:-self.keep_files]:
            if old != self._path:
                os.remove(old)
                self.deleted += 1
