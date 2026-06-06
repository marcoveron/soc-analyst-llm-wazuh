"""IP validation used by the response tools before any action is proposed."""

from response_tools import _valid_ip


def test_accepts_ipv4():
    assert _valid_ip("192.168.1.1")


def test_accepts_ipv6():
    assert _valid_ip("::1")


def test_rejects_garbage():
    assert not _valid_ip("not-an-ip")


def test_rejects_empty():
    assert not _valid_ip("")


def test_rejects_out_of_range_octet():
    assert not _valid_ip("999.1.1.1")
