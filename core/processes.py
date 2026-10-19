"""Name the program on this computer behind each packet (live capture only).

The operating system keeps a table of open connections and the process that
owns each one, the same table `netstat -ano` prints. About once a second this
module reads it with psutil:

    TCP  172.17.76.96:53684 -> 104.18.32.47:443     chrome.exe
    UDP  0.0.0.0:5353                               svchost.exe

and each packet is matched to it by its local address and port. A connection
that has just closed is remembered for a minute, so its last packets (FIN,
ACK) are still named. Packets of a connection that opened and closed between
two reads, other devices' traffic, and packets replayed from a file stay
unnamed.
"""

import ipaddress
import socket
import threading
import time

ANY_ADDRESS = "*"   # a socket bound to every address, such as 0.0.0.0:5353


def normalize(ip):
    """'fe80::1%12' -> 'fe80::1', and the same spelling Scapy uses."""
    ip = ip.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def is_group_address(ip):
    """Broadcast or multicast: delivered to sockets bound to every address."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_multicast or (address.version == 4 and ip.endswith(".255"))


class ProcessMap:
    def __init__(self, refresh_seconds=1.0, keep_seconds=60, min_reread_seconds=0.25, clock=time.monotonic,
                 read_connections=None, process_name=None, local_addresses=None):
        import psutil

        self._psutil = psutil
        self.refresh_seconds = refresh_seconds
        self.keep_seconds = keep_seconds
        self.min_reread_seconds = min_reread_seconds
        self._refresh_lock = threading.Lock()
        self._last_read = float("-inf")
        self._clock = clock
        self._read_connections = read_connections or (lambda: psutil.net_connections(kind="inet"))
        self._process_name = process_name or (lambda pid: psutil.Process(pid).name())
        self._local_addresses = local_addresses or self._interface_addresses
        self._table = {}     # (proto, local ip or "*", local port) -> (program, last seen)
        self._names = {}     # pid -> (program, when it was looked up)
        self._local = set()
        self._stop = threading.Event()
        self._thread = None
        self.error = None

    def start(self):
        """Read the table now, then keep it fresh in a background thread."""
        self.refresh()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self.refresh_seconds):
            self.refresh()

    def refresh(self):
        # Called by the background thread and, for new connections, by the capture consumer.
        with self._refresh_lock:
            self._refresh()

    def _refresh(self):
        now = self._last_read = self._clock()
        try:
            connections = self._read_connections()
            local = {normalize(ip) for ip in self._local_addresses()}
        except Exception as exc:
            self.error = f"Cannot read the connection table: {exc}"
            return
        table = {key: entry for key, entry in self._table.items() if now - entry[1] < self.keep_seconds}
        for conn in connections:
            if not conn.pid or not conn.laddr:   # pid 0: closing (TIME_WAIT), no owner any more
                continue
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            ip = normalize(conn.laddr[0])
            if ip in ("0.0.0.0", "::"):
                ip = ANY_ADDRESS
            table[(proto, ip, conn.laddr[1])] = (self._name(conn.pid, now), now)
        # Building a new dict and swapping it in keeps lookups from other threads safe.
        self._table, self._local, self.error = table, local, None

    def lookup(self, record):
        """The program that sent or received this packet, or None."""
        proto = record["proto"]
        if proto not in ("TCP", "UDP"):
            return None
        name = self._find(record)
        # A connection of ours that opened since the last read: read the table again
        # (it takes milliseconds), but at most a few times a second.
        if name is None and (record["src"] in self._local or record["dst"] in self._local):
            if self._clock() - self._last_read >= self.min_reread_seconds:
                self.refresh()
                name = self._find(record)
        return name

    def _find(self, record):
        proto = record["proto"]
        table = self._table
        ends = [(record["src"], record["sport"]), (record["dst"], record["dport"])]
        for ip, port in ends:
            if port is not None and (proto, ip, port) in table:
                return table[(proto, ip, port)][0]
        # Sockets bound to every address receive our own, broadcast and multicast traffic.
        for ip, port in ends:
            if port is not None and (ip in self._local or is_group_address(ip or "")):
                if (proto, ANY_ADDRESS, port) in table:
                    return table[(proto, ANY_ADDRESS, port)][0]
        return None

    def _name(self, pid, now):
        cached = self._names.get(pid)
        if cached and now - cached[1] < self.keep_seconds:   # PIDs are reused, so look again now and then
            return cached[0]
        try:
            name = self._process_name(pid)
        except Exception:   # the process ended, or belongs to a protected system service
            name = "System" if pid == 4 else f"pid {pid}"
        self._names[pid] = (name, now)
        return name

    def _interface_addresses(self):
        return [a.address for addrs in self._psutil.net_if_addrs().values() for a in addrs
                if a.family in (socket.AF_INET, socket.AF_INET6)]
