from __future__ import annotations

import pytest

from app.network.targets import expand_target, validate_private_ipv4_target


def test_expand_ipv4_cidr() -> None:
    assert expand_target("192.168.10.0/30", max_hosts=10) == (
        "192.168.10.1",
        "192.168.10.2",
    )


def test_expand_target_enforces_host_limit() -> None:
    with pytest.raises(ValueError, match="limit"):
        expand_target("10.0.0.0/24", max_hosts=10)


def test_private_monitor_target_validation() -> None:
    assert validate_private_ipv4_target("192.168.10.0/24") == "192.168.10.0/24"
    assert validate_private_ipv4_target("10.20.30.40") == "10.20.30.40"

    with pytest.raises(ValueError, match="private IPv4"):
        validate_private_ipv4_target("8.8.8.8")
    with pytest.raises(ValueError, match="private IPv4"):
        validate_private_ipv4_target("2001:db8::1")
    with pytest.raises(ValueError, match="4096-host"):
        validate_private_ipv4_target("10.0.0.0/8")


def test_huge_network_is_rejected_before_materialization() -> None:
    with pytest.raises(ValueError, match="limit"):
        expand_target("10.0.0.0/8", max_hosts=4096)
    with pytest.raises(ValueError, match="limit"):
        expand_target("2001:db8::/64", max_hosts=4096)
