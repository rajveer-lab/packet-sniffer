import time

import pytest

from core.security import SecurityMonitor
from core.store import TrafficStore
from sniffer import create_app


class FakePipeline:
    def status(self):
        return {"mode": "live", "source": "Wi-Fi", "filter": None, "running": True,
                "error": None, "dropped": 0, "parse_errors": 0, "queued": 0}


@pytest.fixture
def store():
    store = TrafficStore()
    now = time.time()
    for i in range(5):
        store.add({"time": now, "length": 66, "proto": "TCP", "src": "192.168.1.5",
                   "dst": "203.0.113.10", "sport": 52344, "dport": 443, "flags": ["ACK"], "info": ""})
    return store


@pytest.fixture
def monitor():
    return SecurityMonitor()


@pytest.fixture
def client(store, monitor):
    return create_app(store, FakePipeline(), monitor).test_client()


def test_packets_endpoint_returns_newer_packets(client):
    data = client.get("/api/packets?after=2").get_json()
    assert [p["id"] for p in data["packets"]] == [3, 4, 5]
    assert data["last_id"] == 5


def test_packets_endpoint_clamps_bad_limits(client):
    assert len(client.get("/api/packets?limit=0").get_json()["packets"]) == 1
    assert len(client.get("/api/packets?limit=abc").get_json()["packets"]) == 5


def test_packets_endpoint_filters(client, store):
    store.add({"time": time.time(), "length": 80, "proto": "UDP", "src": "192.168.1.9", "dst": "8.8.8.8",
               "sport": 40122, "dport": 53, "service": "DNS", "flags": [], "info": "40122 -> 53"})
    udp = client.get("/api/packets?proto=udp").get_json()
    assert [p["id"] for p in udp["packets"]] == [6]
    assert udp["last_id"] == 6
    both = client.get("/api/packets?host=192.168.1.0/24&port=443").get_json()
    assert [p["id"] for p in both["packets"]] == [1, 2, 3, 4, 5]
    assert client.get("/api/packets?q=dns").get_json()["packets"][0]["dst"] == "8.8.8.8"


def test_bad_filter_is_a_400_with_a_message(client):
    response = client.get("/api/packets?port=https")
    assert response.status_code == 400
    assert "not a port number" in response.get_json()["error"]


def test_alerts_endpoint(client, monitor):
    for port in range(1, 21):
        monitor.inspect({"time": 100 + port * 0.01, "proto": "TCP", "src": "192.168.1.66", "dst": "192.168.1.5",
                         "sport": 40000, "dport": port, "flags": ["SYN"]})
    data = client.get("/api/alerts").get_json()
    assert data["enabled"] is True
    assert [a["rule"] for a in data["alerts"]] == ["port_scan"]
    assert data["counts"]["high"] == 1
    assert len(data["rules"]) == 5


def test_alerts_endpoint_without_a_monitor(store):
    data = create_app(store).test_client().get("/api/alerts").get_json()
    assert (data["enabled"], data["alerts"]) == (False, [])


def test_stats_endpoint_includes_capture_status(client):
    data = client.get("/api/stats").get_json()
    assert data["total_packets"] == 5
    assert data["protocols"][0]["name"] == "TCP"
    assert data["capture"]["source"] == "Wi-Fi"
    assert len(data["bandwidth"]) == 60


def test_dashboard_page_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Packet Sniffer Dashboard" in response.data
    response.close()
    js = client.get("/static/app.jsx")
    assert js.status_code == 200
    js.close()
