"""Packet capture as producer-consumer threads.

    capture thread  --(raw packets)-->  queue  --> consumer thread --> TrafficStore
       (Scapy sniff,                                (parse_packet,
        or pcap replay)                              update counters)

The sniff callback only puts the packet on the queue, so slow decoding never
makes the capture thread miss packets. If the queue ever fills up the packet
is counted as dropped instead of blocking capture.
"""

import queue
import sys
import threading
import time

from .parser import parse_packet


def interface_name(iface=None):
    """Friendly name of an interface such as "Wi-Fi", or of the default one."""
    from scapy.config import conf
    from scapy.interfaces import resolve_iface

    try:
        return resolve_iface(iface or conf.iface).name
    except Exception:
        return str(iface or conf.iface)


def capture_problem():
    """Explain why live capture cannot start on this machine, or return None."""
    from scapy.config import conf

    if sys.platform == "win32" and not conf.use_pcap:
        return (
            "Npcap is not installed, so Windows cannot capture packets. "
            "Install it from https://npcap.com, then restart the sniffer. "
            "You can still try the dashboard with --pcap samples/sample_traffic.pcap."
        )
    return None


class PacketPipeline:
    def __init__(self, store, queue_size=10000, on_record=None):
        self.store = store
        self.on_record = on_record  # optional callback, e.g. print each packet
        self.queue = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._threads = []
        self._lock = threading.Lock()
        self._status = {
            "mode": None,       # "live" or "replay"
            "source": None,     # interface name or pcap file
            "filter": None,     # BPF filter expression, if any
            "running": False,
            "error": None,
            "dropped": 0,
            "parse_errors": 0,
        }

    def status(self):
        with self._lock:
            return dict(self._status, queued=self.queue.qsize())

    def _set(self, **changes):
        with self._lock:
            self._status.update(changes)

    def _count(self, key):
        with self._lock:
            self._status[key] += 1

    # Producer side: called for every captured packet, so it must stay cheap.
    def _enqueue(self, pkt, timestamp=None):
        try:
            self.queue.put_nowait((pkt, timestamp))
        except queue.Full:
            self._count("dropped")

    # Consumer side: decode the packet and update the statistics.
    def _consume(self):
        while not (self._stop.is_set() and self.queue.empty()):
            try:
                pkt, timestamp = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                record = self.store.add(parse_packet(pkt, timestamp))
            except Exception:
                self._count("parse_errors")
                continue
            if self.on_record:
                self.on_record(record)

    def _start(self, target, *args):
        self._stop.clear()
        self._set(running=True, error=None)
        for fn, fn_args in ((self._consume, ()), (target, args)):
            thread = threading.Thread(target=fn, args=fn_args, daemon=True)
            thread.start()
            self._threads.append(thread)

    def start_live(self, iface=None, bpf_filter=None):
        self._set(mode="live", source=interface_name(iface), filter=bpf_filter)
        problem = capture_problem()
        if problem:
            self._set(running=False, error=problem)
            return
        self._start(self._sniff_live, iface, bpf_filter)

    def start_replay(self, path, speed=1.0, loop=False):
        """Feed packets from a pcap file as if they were arriving now.

        Gaps between packets are kept (divided by ``speed``, capped at one
        second) and each packet is stamped with the current time, so the
        dashboard behaves the same as with live capture.
        """
        self._set(mode="replay", source=path, filter=None)
        self._start(self._replay, path, speed, loop)

    def stop(self, timeout=2):
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout)
        self._threads = []
        self._set(running=False)

    def _sniff_live(self, iface, bpf_filter):
        from scapy.sendrecv import sniff

        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=self._enqueue,
                store=False,
                stop_filter=lambda _pkt: self._stop.is_set(),
            )
        except PermissionError:
            self._set(error="Permission denied. Run the sniffer as Administrator (or with sudo on Linux/macOS).")
        except Exception as exc:
            self._set(error=f"Capture stopped: {exc}")
        finally:
            self._set(running=False)

    def _replay(self, path, speed, loop):
        from scapy.utils import PcapReader

        try:
            while not self._stop.is_set():
                previous = None
                with PcapReader(path) as reader:
                    for pkt in reader:
                        if self._stop.is_set():
                            return
                        sent_at = float(pkt.time)
                        if previous is not None and speed > 0:
                            gap = max(sent_at - previous, 0) / speed
                            self._stop.wait(min(gap, 1.0))
                        previous = sent_at
                        self._enqueue(pkt, time.time())
                if not loop:
                    return
        except FileNotFoundError:
            self._set(error=f"Capture file not found: {path}")
        except Exception as exc:
            self._set(error=f"Could not read {path}: {exc}")
        finally:
            self._set(running=False)
