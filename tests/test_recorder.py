import os

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from core.recorder import RotatingPcapWriter

# 54 header bytes + 946 payload = 1000-byte frames
FRAME = Ether(src="3c:22:fb:12:34:56", dst="00:1a:2b:3c:4d:5e") / IP(src="192.168.1.5", dst="203.0.113.10") / TCP(
    sport=52344, dport=443, flags="A") / Raw(b"\x00" * 946)


class TickingClock:
    """Each call is one second later, so every file gets a distinct name."""

    def __init__(self):
        self.now = 1_760_000_000.0

    def __call__(self):
        self.now += 1
        return self.now


def test_packets_are_saved_and_readable(tmp_path):
    writer = RotatingPcapWriter(str(tmp_path), max_mb=1)
    for _ in range(5):
        writer.write(FRAME)
    writer.close()
    writer.write(FRAME)              # arrives after shutdown: no new file
    (saved,) = writer.files()
    packets = rdpcap(saved)
    assert len(packets) == 5
    assert bytes(packets[0]) == bytes(FRAME)


def test_files_rotate_and_the_oldest_are_deleted(tmp_path):
    # About 4 frames fit in a 4 KB file; keep at most 3 files
    writer = RotatingPcapWriter(str(tmp_path), max_mb=4 / 1024, keep_files=3, clock=TickingClock())
    for _ in range(30):
        writer.write(FRAME)
    writer.close()

    files = writer.files()
    assert len(files) == 3
    assert all(os.path.getsize(f) <= 4096 for f in files)
    # 30 frames at 4 per file made 8 files; the 5 oldest decayed away
    assert [len(rdpcap(f)) for f in files] == [4, 4, 2]
    status = writer.status()
    assert (status["written"], status["deleted"], status["files"], status["error"]) == (30, 5, 3, None)


def test_unrelated_files_in_the_folder_are_left_alone(tmp_path):
    keep = tmp_path / "notes.txt"
    keep.write_text("mine")
    other = tmp_path / "evidence.pcap"
    other.write_bytes(b"")
    writer = RotatingPcapWriter(str(tmp_path), max_mb=4 / 1024, keep_files=1, clock=TickingClock())
    for _ in range(20):
        writer.write(FRAME)
    writer.close()
    assert keep.exists() and other.exists()
    assert len(writer.files()) == 1
