import pytest

from advisory_rss.server.bind import assert_loopback, is_loopback


def test_accepts_127_0_0_1():
    assert is_loopback("127.0.0.1") is True


def test_accepts_127_variants():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("127.0.0.2") is True
    assert is_loopback("127.1.2.3") is True
    assert is_loopback("[127.0.0.1]") is True
    assert is_loopback(" 127.0.0.1 ") is True


def test_accepts_ipv6_loopback():
    assert is_loopback("::1") is True
    assert is_loopback("[::1]") is True
    assert is_loopback("::1") is True


def test_rejects_0_0_0_0():
    assert is_loopback("0.0.0.0") is False
    with pytest.raises(SystemExit):
        assert_loopback("0.0.0.0")


def test_rejects_ipv6_any():
    assert is_loopback("::") is False
    assert is_loopback("[::]") is False
    with pytest.raises(SystemExit):
        assert_loopback("::")


def test_rejects_lan_ips():
    assert is_loopback("192.168.1.1") is False
    assert is_loopback("10.0.0.1") is False
    assert is_loopback("172.16.0.1") is False
    for ip in ["192.168.1.1", "10.0.0.1", "172.16.5.4"]:
        with pytest.raises(SystemExit):
            assert_loopback(ip)


def test_rejects_hostname():
    assert is_loopback("localhost") is False
    assert is_loopback("example.com") is False
    with pytest.raises(SystemExit):
        assert_loopback("localhost")


def test_rejects_empty():
    assert is_loopback("") is False
    assert is_loopback("   ") is False
    assert is_loopback(None) is False  


def test_rejects_bracket_colon_form():
    assert is_loopback("[::]") is False
    assert is_loopback("0.0.0.0:8765") is False 
    with pytest.raises(SystemExit):
        assert_loopback("[::]")


def test_accepts_with_brackets_and_spaces():
    assert is_loopback("::1") is True
    assert is_loopback(" [::1] ") is True
