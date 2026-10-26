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
    assert len(data["rules"]) == 12


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
    for script in ("/static/app.js", "/static/vendor/react.production.min.js",
                   "/static/vendor/react-dom.production.min.js"):
        js = client.get(script)
        assert js.status_code == 200, script
        js.close()


def test_page_loads_scripts_only_from_this_server(client):
    page = client.get("/")
    html = page.get_data(as_text=True)
    page.close()
    assert "<script src=\"/static/app.js\">" in html
    assert "https://" not in html and "text/babel" not in html


def test_compiled_dashboard_is_up_to_date():
    """static/app.js must be rebuilt (python tools/build.py dashboard) after editing app.jsx."""
    import hashlib

    source = hashlib.sha256(open("static/app.jsx", "rb").read().replace(b"\r\n", b"\n")).hexdigest()
    with open("static/app.js", encoding="utf-8") as built:
        assert f"sha256 {source}" in built.readline()


# ---- one-click fixes, capture control and exports ---------------------------------------

from core.defense import Defender  # noqa: E402


class Netsh:
    def __init__(self):
        self.commands = []

    def __call__(self, args):
        self.commands.append(args)
        return True, ""


def scan(monitor):
    for port in range(1, 21):
        monitor.inspect({"time": 100 + port * 0.01, "proto": "TCP", "src": "192.168.1.66", "dst": "192.168.1.5",
                         "sport": 40000, "dport": port, "flags": ["SYN"]})
    return monitor.summary()["alerts"][0]["id"]


@pytest.fixture
def defended(store, monitor):
    netsh = Netsh()
    defender = Defender(interface="Wi-Fi", protected=["192.168.1.5"], run=netsh, is_admin=lambda: True,
                        platform="win32")
    return create_app(store, FakePipeline(), monitor, defender=defender).test_client(), netsh


def test_alerts_come_with_advice_and_a_fix(defended, monitor):
    client, _ = defended
    scan(monitor)
    data = client.get("/api/alerts").get_json()
    alert = data["alerts"][0]
    assert alert["fix_label"] == "Block 192.168.1.66"
    assert alert["advice"]["steps"][0] == "Block 192.168.1.66 if you do not recognise it."
    assert data["defense"]["available"] is True


def test_applying_and_undoing_a_fix(defended, monitor):
    client, netsh = defended
    alert_id = scan(monitor)
    response = client.post("/api/defense/apply", json={"alert_id": alert_id})
    assert response.status_code == 200 and response.get_json()["message"] == "Blocked 192.168.1.66 (in and out)"
    assert len(netsh.commands) == 2
    assert client.get("/api/alerts").get_json()["alerts"][0]["fixed"]["label"].startswith("Blocked")
    fix_id = response.get_json()["defense"]["applied"][0]["id"]
    assert client.post("/api/defense/undo", json={"fix_id": fix_id}).get_json()["ok"] is True
    assert client.post("/api/defense/apply", json={"alert_id": 999}).status_code == 404


def test_fixes_cannot_be_triggered_by_a_form_or_another_website(defended, monitor):
    client, netsh = defended
    alert_id = scan(monitor)
    assert client.post("/api/defense/apply", data={"alert_id": alert_id}).status_code == 415
    other_site = client.post("/api/defense/apply", json={"alert_id": alert_id}, headers={"Origin": "https://evil.example"})
    assert other_site.status_code == 403
    assert netsh.commands == []


class ControllablePipeline(FakePipeline):
    def __init__(self):
        self.running, self.stopped = True, None

    def status(self):
        return dict(super().status(), running=self.running, stopped=self.stopped)

    def stop_from_dashboard(self):
        self.running, self.stopped = False, "stopped from the dashboard"

    def restart(self, iface=None, bpf_filter=None, change=False):
        if self.running and not change:
            return False
        self.running, self.stopped = True, None
        self.changed_to = (iface, bpf_filter) if change else None
        return True


def test_stopping_and_starting_capture_from_the_dashboard(store):
    client = create_app(store, ControllablePipeline()).test_client()
    stopped = client.post("/api/capture/stop", json={}).get_json()
    assert stopped["capture"]["stopped"] == "stopped from the dashboard"
    assert client.post("/api/capture/start", json={}).get_json()["capture"]["running"] is True
    assert client.post("/api/capture/start", json={}).status_code == 409
    assert client.post("/api/capture/reboot", json={}).status_code == 404


def test_csv_exports_are_safe_to_open_in_excel(store, monitor):
    store.add({"time": time.time(), "length": 90, "proto": "UDP", "src": "192.168.1.9", "dst": "8.8.8.8",
               "sport": 40122, "dport": 53, "flags": [], "info": "=HYPERLINK(\"http://evil\")", "app": "chrome.exe"})
    scan(monitor)
    client = create_app(store, FakePipeline(), monitor).test_client()
    packets = client.get("/api/export/packets.csv?proto=UDP")
    assert packets.headers["Content-Disposition"] == 'attachment; filename="packets.csv"'
    lines = packets.get_data(as_text=True).splitlines()
    assert lines[0].startswith("id,time,program,source")
    assert len(lines) == 2 and "chrome.exe" in lines[1]
    assert "'=HYPERLINK" in lines[1]                         # shown as text, never run as a formula
    alerts = client.get("/api/export/alerts.csv").get_data(as_text=True).splitlines()
    assert "Port scan from 192.168.1.66" in alerts[1] and "Block 192.168.1.66" in alerts[1]


def test_top_hosts_get_names_from_dns(store):
    from core.names import NameCache

    names = NameCache()
    names._remember("203.0.113.10", "video.example.com")
    data = create_app(store, names=names).test_client().get("/api/stats").get_json()
    assert {"host": "203.0.113.10", "name": "video.example.com"} in [
        {"host": h["host"], "name": h["name"]} for h in data["top_hosts"]]



# ---- connections, devices, bytes, pcap, history, interfaces and the report ----------

def test_connections_devices_and_packet_bytes():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from core.devices import DeviceTable
    from core.flows import FlowTable

    store, flows, devices = TrafficStore(), FlowTable(), DeviceTable()
    pkt = Ether(src="3c:22:fb:12:34:56", dst="00:1a:2b:3c:4d:5e") / IP(src="192.168.1.5", dst="203.0.113.10") / TCP(
        sport=52344, dport=443, flags="S", seq=1000)
    record = {"time": time.time(), "length": len(pkt), "proto": "TCP", "src": "192.168.1.5", "dst": "203.0.113.10",
              "sport": 52344, "dport": 443, "flags": ["SYN"], "seq": 1000, "ack": 0, "payload_len": 0,
              "src_mac": "3c:22:fb:12:34:56", "info": "52344 -> 443 [SYN]"}
    flows.update(record)
    devices.update(record)
    stored = store.add(record, raw=(bytes(pkt), 1))
    client = create_app(store, flows=flows, devices=devices).test_client()

    data = client.get("/api/connections").get_json()
    assert data["connections"][0]["state"] == "SYN sent" and data["summary"]["tcp"] == 1
    assert client.get("/api/devices").get_json()["devices"][0]["mac"] == "3c:22:fb:12:34:56"
    hexview = client.get(f"/api/packets/{stored['id']}/bytes").get_json()
    assert hexview["hex"] == bytes(pkt).hex()
    assert [layer["name"] for layer in hexview["layers"]] == ["Ethernet", "IP", "TCP"]
    assert client.get("/api/packets/999/bytes").status_code == 404


def test_pcap_download_opens_in_wireshark(store, tmp_path):
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import rdpcap

    pkt = Ether() / IP(src="192.168.1.9", dst="8.8.8.8") / UDP(sport=40122, dport=53)
    store.add({"time": 1_760_000_000.25, "length": len(pkt), "proto": "UDP", "src": "192.168.1.9", "dst": "8.8.8.8",
               "sport": 40122, "dport": 53, "flags": [], "info": ""}, raw=(bytes(pkt), 1))
    response = create_app(store).test_client().get("/api/export/packets.pcap?proto=UDP")
    assert response.headers["Content-Disposition"] == 'attachment; filename="packets.pcap"'
    saved = tmp_path / "packets.pcap"
    saved.write_bytes(response.data)
    (back,) = rdpcap(str(saved))
    assert bytes(back) == bytes(pkt) and float(back.time) == 1_760_000_000.25


def test_history_endpoint(store, tmp_path):
    from core.history import History

    history = History(str(tmp_path / "h.db"))
    history.start_session("live", "Wi-Fi")
    data = create_app(store, history=history).test_client().get("/api/history?hours=6").get_json()
    assert data["enabled"] is True and data["hours"] == 6 and data["sessions"][0]["source"] == "Wi-Fi"
    assert create_app(store).test_client().get("/api/history").get_json() == {"enabled": False}


def capture_driver_missing():
    from core.capture import capture_problem

    return capture_problem() is not None


@pytest.mark.skipif(capture_driver_missing(), reason="checking a capture filter needs Npcap/libpcap")
def test_changing_interface_and_filter(store):
    pipeline = ControllablePipeline()
    client = create_app(store, pipeline).test_client()
    assert client.get("/api/interfaces").get_json()["interfaces"]        # this computer has some
    bad_filter = client.post("/api/capture/start", json={"filter": "tcp port banana"})
    assert bad_filter.status_code == 400 and "Not a valid capture filter" in bad_filter.get_json()["message"]
    assert client.post("/api/capture/start", json={"iface": "No Such Adapter"}).status_code == 400
    ok = client.post("/api/capture/start", json={"filter": "tcp port 443"})
    assert ok.get_json()["ok"] and pipeline.changed_to == (None, "tcp port 443")


def test_report_page_escapes_captured_text(store, monitor):
    from core.flows import FlowTable

    flows = FlowTable()
    flows.update({"time": 100, "proto": "TCP", "src": "192.168.1.5", "sport": 50000, "dst": "203.0.113.10",
                  "dport": 443, "flags": ["SYN"], "seq": 1, "ack": 0, "payload_len": 0, "length": 60,
                  "dst_name": "<script>alert(1)</script>.example"})
    scan(monitor)
    page = create_app(store, FakePipeline(), monitor, flows=flows).test_client().get("/report")
    html = page.get_data(as_text=True)
    assert page.status_code == 200 and "Network traffic report" in html
    assert "Port scan from 192.168.1.66" in html and "Block 192.168.1.66 if you do not recognise it." in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert '<script src="/static/report.js"></script>' in html
