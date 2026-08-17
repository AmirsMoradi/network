import pytest

from app.network.ports import parse_ports


def test_parse_ports_normalizes_and_deduplicates() -> None:
    assert parse_ports("443,80,80,8000-8002") == (80, 443, 8000, 8001, 8002)


def test_parse_ports_rejects_invalid_range() -> None:
    with pytest.raises(ValueError):
        parse_ports("9000-8000")


def test_parse_ports_rejects_out_of_bounds() -> None:
    with pytest.raises(ValueError):
        parse_ports("0,80")
