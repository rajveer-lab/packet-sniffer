from core.devices import DeviceTable, is_randomised, maker

LAPTOP_MAC, ROUTER_MAC, PHONE_MAC = "3c:22:fb:12:34:56", "00:1a:2b:3c:4d:5e", "5e:f9:38:aa:bb:cc"


def rec(time, src_mac, src, length=100, **extra):
    record = {"time": time, "src_mac": src_mac, "src": src, "length": length}
    record.update(extra)
    return record


def test_devices_are_listed_with_addresses_maker_and_name():
    table = DeviceTable(own_macs=["3C-22-FB-12-34-56"], router_ip="192.168.1.1")
    table.update(rec(100, LAPTOP_MAC, "192.168.1.5"))
    table.update(rec(101, ROUTER_MAC, "192.168.1.1"))
    table.update(rec(102, ROUTER_MAC, "142.250.1.1", length=1500))      # internet traffic via the router
    table.update(rec(103, PHONE_MAC, "0.0.0.0", dhcp_type="request", dhcp_hostname="Pixel-8"))
    table.update(rec(104, ROUTER_MAC, "192.168.1.1", dhcp_type="ack", dhcp_client_mac=PHONE_MAC,
                     dhcp_offer="192.168.1.9"))
    table.update(rec(105, "ff:ff:ff:ff:ff:ff", "192.168.1.200"))          # broadcast: not a device
    devices = {d["mac"]: d for d in table.devices()}
    assert set(devices) == {LAPTOP_MAC, ROUTER_MAC, PHONE_MAC}
    laptop, router, phone = devices[LAPTOP_MAC], devices[ROUTER_MAC], devices[PHONE_MAC]
    assert laptop["maker"] == "Apple, Inc." and laptop["is_this_computer"]
    assert router["is_router"] and router["addresses"] == ["192.168.1.1"]         # no internet addresses
    assert (router["packets"], router["bytes"]) == (3, 1700)
    assert (phone["name"], phone["addresses"], phone["maker"]) == ("Pixel-8", ["192.168.1.9"], "Private (randomised) address")
    assert table.devices()[0]["mac"] == ROUTER_MAC                               # most recently seen first


def test_randomised_and_unknown_makers():
    assert is_randomised("da:a1:19:00:00:01") and not is_randomised(LAPTOP_MAC)
    assert maker("04:ff:ff:12:34:56") is None                       # prefix registered to no one
    assert maker("de:ad:be:ef:00:66") == "Private (randomised) address"   # second digit e: made up


def test_the_table_is_bounded():
    table = DeviceTable(max_devices=2)
    for i in range(5):
        table.update(rec(i, f"00:00:00:00:00:0{i}", f"192.168.1.{i + 10}"))
    assert len(table.devices()) == 2


def test_only_home_network_addresses_are_listed():
    from core.devices import is_lan_address

    assert is_lan_address("192.168.1.5") and is_lan_address("10.0.0.7") and is_lan_address("fe80::1")
    # Documentation and internet ranges are not a device's own address, even if Python calls some "private"
    assert not is_lan_address("198.51.100.7") and not is_lan_address("203.0.113.10") and not is_lan_address("8.8.8.8")
