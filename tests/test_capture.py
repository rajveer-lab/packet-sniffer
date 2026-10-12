import time

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from core.capture import PacketPipeline
from core.store import TrafficStore

# Explicit addresses, so Scapy never has to look up this machine's routes
ETH = Ether(src="3c:22:fb:12:34:56", dst="00:1a:2b:3c:4d:5e")


def wait_for(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def write_pcap(path):
    packets = [
        ETH / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=53011, dport=53),
        ETH / IP(src="192.168.1.5", dst="203.0.113.10") / TCP(sport=52344, dport=443, flags="S"),
        ETH / IP(src="203.0.113.10", dst="192.168.1.5") / TCP(sport=443, dport=52344, flags="SA"),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = 1_000_000 + i * 0.5   # old timestamps, half a second apart
    wrpcap(str(path), packets)


def test_replay_goes_through_queue_parser_and_store(tmp_path):
    pcap = tmp_path / "three.pcap"
    write_pcap(pcap)
    store = TrafficStore()
    printed = []
    pipeline = PacketPipeline(store, on_record=printed.append)

    started = time.time()
    pipeline.start_replay(str(pcap), speed=0)
    assert wait_for(lambda: store.last_id == 3)
    pipeline.stop()

    packets = store.packets_after(0)
    assert [p["proto"] for p in packets] == ["UDP", "TCP", "TCP"]
    assert packets[2]["flags"] == ["SYN", "ACK"]
    # Replayed packets are stamped with the current time, not the file's
    assert all(p["time"] >= started for p in packets)
    assert [p["id"] for p in printed] == [1, 2, 3]
    status = pipeline.status()
    assert (status["mode"], status["running"], status["error"]) == ("replay", False, None)


def test_replay_keeps_the_gaps_between_packets(tmp_path):
    pcap = tmp_path / "three.pcap"
    write_pcap(pcap)
    store = TrafficStore()
    pipeline = PacketPipeline(store)

    pipeline.start_replay(str(pcap), speed=2)   # 0.5 s gaps at 2x speed -> 0.25 s
    assert wait_for(lambda: store.last_id == 3)
    pipeline.stop()

    times = [p["time"] for p in store.packets_after(0)]
    assert 0.4 <= times[2] - times[0] <= 1.0


def test_missing_pcap_reports_an_error(tmp_path):
    pipeline = PacketPipeline(TrafficStore())
    pipeline.start_replay(str(tmp_path / "nope.pcap"))
    assert wait_for(lambda: pipeline.status()["error"] is not None)
    assert "not found" in pipeline.status()["error"]
    pipeline.stop()


def test_full_queue_counts_dropped_packets_instead_of_blocking():
    pipeline = PacketPipeline(TrafficStore(), queue_size=2)
    for _ in range(5):
        pipeline._enqueue(ETH / IP(src="10.0.0.1", dst="10.0.0.2") / TCP())   # no consumer running
    assert pipeline.status()["dropped"] == 3
