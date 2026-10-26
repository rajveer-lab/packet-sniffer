from core.store import TrafficStore


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def record(time, proto="TCP", src="192.168.1.5", dst="203.0.113.10", length=100):
    return {"time": time, "proto": proto, "src": src, "dst": dst, "length": length}


def test_add_assigns_increasing_ids():
    store = TrafficStore(clock=FakeClock())
    first = store.add(record(1000))
    second = store.add(record(1000))
    assert (first["id"], second["id"], store.last_id) == (1, 2, 2)


def test_packets_after_returns_only_newer_packets_oldest_first():
    store = TrafficStore(clock=FakeClock())
    for _ in range(5):
        store.add(record(1000))
    assert [p["id"] for p in store.packets_after(2)] == [3, 4, 5]
    assert [p["id"] for p in store.packets_after(2, limit=2)] == [4, 5]  # newest when limited
    assert store.packets_after(5) == []


def test_old_packets_are_evicted_but_totals_keep_counting():
    store = TrafficStore(max_packets=3, clock=FakeClock())
    for _ in range(10):
        store.add(record(1000))
    assert [p["id"] for p in store.packets_after(0)] == [8, 9, 10]
    assert store.stats()["total_packets"] == 10


def test_protocol_share_and_top_hosts():
    store = TrafficStore(clock=FakeClock())
    for _ in range(3):
        store.add(record(1000, proto="TCP", length=1000))
    store.add(record(1000, proto="UDP", src="192.168.1.9", dst="8.8.8.8", length=100))

    s = store.stats(top_hosts=2)
    assert s["total_bytes"] == 3100
    assert s["protocols"][0] == {"name": "TCP", "packets": 3, "bytes": 3000, "percent": 75.0}
    assert s["protocols"][1]["percent"] == 25.0
    # Both ends of a packet count towards a host's traffic
    assert s["top_hosts"] == [
        {"host": "192.168.1.5", "bytes": 3000, "packets": 3},
        {"host": "203.0.113.10", "bytes": 3000, "packets": 3},
    ]


def test_arp_style_record_with_missing_host_is_counted_once():
    store = TrafficStore(clock=FakeClock())
    store.add(record(1000, proto="Other", src="aa:bb", dst=None))
    assert store.stats()["top_hosts"] == [{"host": "aa:bb", "bytes": 100, "packets": 1}]


def test_bandwidth_window_and_rates_use_the_last_full_second():
    clock = FakeClock(1000.5)
    store = TrafficStore(window_seconds=10, clock=clock)
    store.add(record(998.2, length=500))
    store.add(record(999.1, length=300))
    store.add(record(999.7, length=200))
    store.add(record(1000.3, length=50))   # current second, still filling

    s = store.stats()
    assert len(s["bandwidth"]) == 10
    assert s["bandwidth"][-1] == {"t": 1000, "bytes": 50, "packets": 1}
    assert s["bytes_per_sec"] == 500       # 300 + 200 during second 999
    assert s["packets_per_sec"] == 2

    clock.now = 1020.0                     # everything has left the 10 s window
    s = store.stats()
    assert sum(point["bytes"] for point in s["bandwidth"]) == 0
    assert s["bytes_per_sec"] == 0
    assert s["total_bytes"] == 1050        # totals are not windowed


def test_packets_older_than_the_retention_period_decay():
    clock = FakeClock(1000.0)
    store = TrafficStore(retention_seconds=30, clock=clock)
    store.add(record(1000.0, proto="UDP", src="192.168.1.9", dst="8.8.8.8", length=80))
    clock.now = 1020.0
    store.add(record(1020.0, length=400))

    clock.now = 1040.0                     # the UDP packet is now 40 s old
    assert [p["proto"] for p in store.packets_after(0)] == ["TCP"]
    s = store.stats()
    assert [p["name"] for p in s["protocols"]] == ["TCP"]
    assert "8.8.8.8" not in [h["host"] for h in s["top_hosts"]]
    assert (s["recent_packets"], s["buffered"]) == (1, 1)
    assert s["total_packets"] == 2         # lifetime total still counts it

    clock.now = 1100.0                     # everything has decayed
    s = store.stats()
    assert (s["protocols"], s["top_hosts"], s["recent_packets"]) == ([], [], 0)
    assert store.packets_after(0) == []


def test_query_filters_packets_and_reports_the_newest_id():
    store = TrafficStore(clock=FakeClock())
    store.add(record(1000, proto="TCP"))
    store.add(record(1000, proto="UDP"))
    store.add(record(1000, proto="TCP"))
    result = store.query(0, match=lambda p: p["proto"] == "UDP")
    assert [p["id"] for p in result["packets"]] == [2]
    assert result["last_id"] == 3          # next poll starts after every scanned packet


def test_top_applications_over_the_retention_period():
    clock = FakeClock(1000.0)
    store = TrafficStore(retention_seconds=30, clock=clock)
    store.add(dict(record(1000, length=1500), app="chrome.exe"))
    store.add(dict(record(1000, length=1500), app="chrome.exe"))
    store.add(dict(record(1000, length=200), app="Spotify.exe"))
    store.add(dict(record(1000, length=900), app=None))      # unnamed packets are not listed
    assert store.stats()["top_apps"] == [
        {"app": "chrome.exe", "bytes": 3000, "packets": 2},
        {"app": "Spotify.exe", "bytes": 200, "packets": 1},
    ]
    clock.now = 1100.0
    assert store.stats()["top_apps"] == []


def test_raw_bytes_stay_with_their_packet_and_leave_with_it():
    clock = FakeClock(1000.0)
    store = TrafficStore(max_packets=2, retention_seconds=30, clock=clock)
    first = store.add(record(1000), raw=(b"\x01\x02", 1))
    store.add(record(1000), raw=(b"\x03", 1))
    assert store.get(first["id"]) == (first, (b"\x01\x02", 1))
    store.add(record(1000), raw=(b"\x04", 1))              # pushes the first one out
    assert store.get(first["id"]) is None
    assert [raw for _, raw in store.with_raw()] == [(b"\x03", 1), (b"\x04", 1)]
    assert [r["id"] for r, _ in store.with_raw(lambda r: r["id"] == 3)] == [3]
    clock.now = 1100.0                                      # everything decays, bytes too
    assert store.with_raw() == [] and store._raw == {}


def test_bytes_per_second_for_the_busiest_programs():
    clock = FakeClock(1000.5)
    store = TrafficStore(window_seconds=10, clock=clock)
    for t, app, size in ((999.1, "chrome.exe", 1000), (999.2, "chrome.exe", 500), (1000.1, "Spotify.exe", 300),
                         (1000.2, None, 9000)):
        store.add(dict(record(t, length=size), app=app))
    graph = store.stats(graph_apps=4)["app_bandwidth"]
    assert graph["apps"] == ["chrome.exe", "Spotify.exe"]
    assert graph["points"][-2] == {"t": 999, "bytes": {"chrome.exe": 1500, "Spotify.exe": 0}}
    assert graph["points"][-1] == {"t": 1000, "bytes": {"chrome.exe": 0, "Spotify.exe": 300}}
    clock.now = 1020.0
    assert store.stats()["app_bandwidth"]["apps"] == []
