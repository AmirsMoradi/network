from __future__ import annotations

import pytest

from app.network.targets import expand_target


def test_expand_ipv4_cidr() -> None:
    assert expand_target("192.168.10.0/30", max_hosts=10) == (
        "192.168.10.1",
        "192.168.10.2",
    )


def test_expand_target_enforces_host_limit() -> None:
    with pytest.raises(ValueError, match="limit"):
        expand_target("10.0.0.0/24", max_hosts=10)
