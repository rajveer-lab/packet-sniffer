import time

import pytest

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
def client(store):
    return create_app(store, FakePipeline()).test_client()


def test_packets_endpoint_returns_newer_packets(client):
    data = client.get("/api/packets?after=2").get_json()
    assert [p["id"] for p in data["packets"]] == [3, 4, 5]
    assert data["last_id"] == 5


def test_packets_endpoint_clamps_bad_limits(client):
    assert len(client.get("/api/packets?limit=0").get_json()["packets"]) == 1
    assert len(client.get("/api/packets?limit=abc").get_json()["packets"]) == 5


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
