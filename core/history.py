"""Remember sessions, alerts and connections after the sniffer closes.

Everything else lives in memory and is gone when the program stops. This
keeps a small SQLite database (one file, no server) with:

    sessions      each run of the sniffer: when, where, how much traffic
    alerts        every security alert, as it was last seen
    connections   every connection: who talked to whom, how much, how it ended

It is written every few seconds and when the sniffer stops, and anything older
than ``keep_days`` is deleted, so the file stays small. Packet contents are
never stored.
"""

import os
import sqlite3
import sys
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL, ended REAL, mode TEXT, source TEXT,
    packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS alerts (
    session INTEGER, alert_id INTEGER, time REAL, last_seen REAL, severity TEXT, rule TEXT,
    title TEXT, detail TEXT, count INTEGER, PRIMARY KEY (session, alert_id));
CREATE TABLE IF NOT EXISTS connections (
    session INTEGER, flow_id INTEGER, proto TEXT, client TEXT, client_port INTEGER, server TEXT,
    server_port INTEGER, server_name TEXT, app TEXT, first_seen REAL, last_seen REAL,
    packets_out INTEGER, packets_in INTEGER, bytes_out INTEGER, bytes_in INTEGER, state TEXT,
    rtt_ms REAL, retransmissions INTEGER, PRIMARY KEY (session, flow_id));
CREATE INDEX IF NOT EXISTS alerts_time ON alerts (last_seen);
CREATE INDEX IF NOT EXISTS connections_time ON connections (last_seen);
"""

CONNECTION_FIELDS = ("proto", "client", "client_port", "server", "server_port", "server_name", "app",
                     "first_seen", "last_seen", "packets_out", "packets_in", "bytes_out", "bytes_in",
                     "state", "rtt_ms", "retransmissions")


def default_path():
    """%LOCALAPPDATA%\\PacketSniffer\\history.db on Windows, ~/.local/share/packet-sniffer elsewhere."""
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return os.path.join(os.environ["LOCALAPPDATA"], "PacketSniffer", "history.db")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "packet-sniffer", "history.db")


class History:
    def __init__(self, path, keep_days=7, clock=time.time):
        self.path = path
        self.keep_days = keep_days
        self._clock = clock
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
        self.session = None
        self.error = None

    def start_session(self, mode, source):
        with self._lock, self._db:
            cursor = self._db.execute("INSERT INTO sessions (started, ended, mode, source) VALUES (?, ?, ?, ?)",
                                      (self._clock(), self._clock(), mode, source))
            self.session = cursor.lastrowid
        self.prune()
        return self.session

    def save(self, alerts, connections, packets, bytes_):
        """Write the current alerts and connections of this session (new rows or updates)."""
        if self.session is None:
            return
        try:
            with self._lock, self._db:
                self._db.execute("UPDATE sessions SET ended = ?, packets = ?, bytes = ? WHERE id = ?",
                                 (self._clock(), packets, bytes_, self.session))
                self._db.executemany(
                    "INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(self.session, a["id"], a["time"], a["last_seen"], a["severity"], a["rule"], a["title"],
                      a["detail"], a["count"]) for a in alerts])
                self._db.executemany(
                    f"INSERT OR REPLACE INTO connections VALUES (?, ?, {', '.join('?' * len(CONNECTION_FIELDS))})",
                    [(self.session, c["id"], *(c.get(f) for f in CONNECTION_FIELDS)) for c in connections])
            self.error = None
        except sqlite3.Error as exc:
            self.error = f"Could not save history: {exc}"

    def prune(self):
        cutoff = self._clock() - self.keep_days * 86400
        with self._lock, self._db:
            self._db.execute("DELETE FROM alerts WHERE last_seen < ?", (cutoff,))
            self._db.execute("DELETE FROM connections WHERE last_seen < ?", (cutoff,))
            self._db.execute("DELETE FROM sessions WHERE ended < ?", (cutoff,))

    def query(self, hours=24, limit=200):
        """Sessions, alerts and the busiest servers of the last ``hours``."""
        since = self._clock() - hours * 3600
        with self._lock:
            sessions = self._rows("SELECT id, started, ended, mode, source, packets, bytes FROM sessions "
                                  "WHERE ended >= ? ORDER BY started DESC, id DESC", since)
            alerts = self._rows("SELECT session, time, last_seen, severity, rule, title, detail, count FROM alerts "
                                "WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?", since, limit)
            servers = self._rows("SELECT server, MAX(server_name) AS name, COUNT(*) AS connections, "
                                 "SUM(bytes_out) AS bytes_out, SUM(bytes_in) AS bytes_in, MAX(app) AS app "
                                 "FROM connections WHERE last_seen >= ? GROUP BY server "
                                 "ORDER BY SUM(bytes_out + bytes_in) DESC LIMIT 15", since)
            apps = self._rows("SELECT app, COUNT(*) AS connections, SUM(bytes_out + bytes_in) AS bytes "
                              "FROM connections WHERE last_seen >= ? AND app IS NOT NULL GROUP BY app "
                              "ORDER BY bytes DESC LIMIT 10", since)
        return {"hours": hours, "sessions": sessions, "alerts": alerts, "top_servers": servers, "top_apps": apps,
                "path": self.path, "keep_days": self.keep_days}

    def _rows(self, sql, *args):
        cursor = self._db.execute(sql, args)
        names = [column[0] for column in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]

    def close(self):
        with self._lock:
            self._db.close()


class HistoryWriter:
    """Saves to the history every few seconds in the background, and once more at the end."""

    def __init__(self, history, collect, every_seconds=10):
        self.history = history
        self.collect = collect          # () -> (alerts, connections, packets, bytes)
        self.every_seconds = every_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        while not self._stop.wait(self.every_seconds):
            self.history.save(*self.collect())

    def stop(self):
        self._stop.set()
        self.history.save(*self.collect())
