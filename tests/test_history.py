from core.history import History, HistoryWriter

ALERT = {"id": 1, "time": 1000.0, "last_seen": 1005.0, "severity": "high", "rule": "port_scan",
         "title": "Port scan from 192.168.1.66", "detail": "150 TCP ports probed", "count": 136}
CONN = {"id": 7, "proto": "TCP", "client": "192.168.1.5", "client_port": 52344, "server": "203.0.113.10",
        "server_port": 443, "server_name": "video.example.com", "app": "chrome.exe", "first_seen": 1000.0,
        "last_seen": 1010.0, "packets_out": 10, "packets_in": 20, "bytes_out": 1000, "bytes_in": 30000,
        "state": "established", "rtt_ms": 30.0, "retransmissions": 0}


class Clock:
    now = 1020.0

    def __call__(self):
        return self.now


def test_history_survives_a_restart(tmp_path):
    path = str(tmp_path / "sub" / "history.db")
    clock = Clock()
    first = History(path, clock=clock)
    first.start_session("live", "Wi-Fi")
    first.save([ALERT], [CONN], packets=5000, bytes_=4_000_000)
    first.save([dict(ALERT, count=200, last_seen=1015.0)], [dict(CONN, bytes_in=50000)], 6000, 5_000_000)
    first.close()

    again = History(path, clock=clock)            # the next run of the sniffer
    again.start_session("replay", "attack_traffic.pcap")
    found = again.query(hours=24)
    assert [s["mode"] for s in found["sessions"]] == ["replay", "live"]
    assert found["sessions"][1]["packets"] == 6000
    (alert,) = found["alerts"]
    assert (alert["title"], alert["count"]) == ("Port scan from 192.168.1.66", 200)       # updated, not duplicated
    (server,) = found["top_servers"]
    assert (server["server"], server["name"], server["bytes_in"], server["app"]) == (
        "203.0.113.10", "video.example.com", 50000, "chrome.exe")
    assert found["top_apps"] == [{"app": "chrome.exe", "connections": 1, "bytes": 51000}]


def test_old_history_is_deleted(tmp_path):
    clock = Clock()
    history = History(str(tmp_path / "h.db"), keep_days=7, clock=clock)
    history.start_session("live", "Wi-Fi")
    history.save([ALERT], [CONN], 1, 1)
    clock.now += 8 * 86400
    history.start_session("live", "Wi-Fi")         # starting a session prunes
    found = history.query(hours=24 * 30)
    assert found["alerts"] == [] and found["top_servers"] == []
    assert len(found["sessions"]) == 1


def test_the_writer_saves_at_the_end(tmp_path):
    history = History(str(tmp_path / "h.db"))
    history.start_session("live", "Wi-Fi")
    writer = HistoryWriter(history, lambda: ([ALERT], [CONN], 10, 20), every_seconds=3600)
    writer.start()
    writer.stop()
    assert history.query(hours=10**6)["alerts"][0]["rule"] == "port_scan"
