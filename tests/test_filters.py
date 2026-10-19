import pytest

from core.filters import build_filter

HTTPS = {"proto": "TCP", "src": "192.168.1.5", "dst": "203.0.113.10", "sport": 52344, "dport": 443,
         "src_mac": "3c:22:fb:12:34:56", "dst_mac": "00:1a:2b:3c:4d:5e",
         "service": "HTTPS", "flags": ["SYN"], "info": "52344 -> 443 [SYN]"}
DNS = {"proto": "UDP", "src": "192.168.1.9", "dst": "8.8.8.8", "sport": 40122, "dport": 53,
       "src_mac": "5c:f9:38:aa:bb:cc", "dst_mac": "00:1a:2b:3c:4d:5e",
       "service": "DNS", "flags": [], "info": "40122 -> 53"}
ARP = {"proto": "ARP", "src": "192.168.1.5", "dst": "192.168.1.1", "sport": None, "dport": None,
       "src_mac": "3c:22:fb:12:34:56", "dst_mac": "ff:ff:ff:ff:ff:ff",
       "service": None, "flags": [], "info": "Who has 192.168.1.1? Tell 192.168.1.5"}
PACKETS = [HTTPS, DNS, ARP]


def shown(**conditions):
    match = build_filter(**conditions)
    return [p["proto"] for p in PACKETS if match(p)]


def test_no_conditions_means_no_filter():
    assert build_filter() is None
    assert build_filter(proto="", host="  ", port="", text=None) is None


def test_protocol_is_case_insensitive_and_takes_a_list():
    assert shown(proto="udp") == ["UDP"]
    assert shown(proto="TCP,ARP") == ["TCP", "ARP"]


def test_host_matches_either_end_by_ip_or_mac():
    assert shown(host="192.168.1.5") == ["TCP", "ARP"]
    assert shown(host="8.8.8.8") == ["UDP"]
    assert shown(host="5C:F9:38:AA:BB:CC") == ["UDP"]
    assert shown(host="192.168.1.50") == []        # exact, not a prefix


def test_host_subnet():
    assert shown(host="192.168.1.0/24") == ["TCP", "UDP", "ARP"]
    assert shown(host="203.0.113.0/24") == ["TCP"]


def test_port_matches_source_or_destination():
    assert shown(port="443") == ["TCP"]
    assert shown(port=40122) == ["UDP"]


def test_text_searches_the_whole_row():
    assert shown(text="dns") == ["UDP"]
    assert shown(text="who has") == ["ARP"]
    assert shown(text="syn") == ["TCP"]
    assert shown(text="192.168.1") == ["TCP", "UDP", "ARP"]   # partial addresses work here


def test_conditions_are_combined():
    assert shown(host="192.168.1.5", proto="TCP") == ["TCP"]
    assert shown(host="192.168.1.5", port="53") == []


@pytest.mark.parametrize("conditions, message", [
    ({"port": "https"}, "not a port number"),
    ({"port": "70000"}, "out of range"),
    ({"host": "192.168.1.0/99"}, "not a valid subnet"),
])
def test_bad_values_raise_readable_errors(conditions, message):
    with pytest.raises(ValueError, match=message):
        build_filter(**conditions)


def test_search_finds_the_program():
    named = dict(HTTPS, app="chrome.exe")
    assert build_filter(text="chrome")(named)
    assert not build_filter(text="spotify")(named)
