from __future__ import annotations

import ipaddress


def expand_target(target: str, *, max_hosts: int) -> tuple[str, ...]:
    text = target.strip()
    if not text:
        raise ValueError("Target is required")

    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            addresses = tuple(str(ip) for ip in network.hosts())
        else:
            addresses = (str(ipaddress.ip_address(text)),)
    except ValueError as exc:
        raise ValueError("Target must be a valid IPv4/IPv6 address or CIDR") from exc

    if len(addresses) > max_hosts:
        raise ValueError(f"Target expands to {len(addresses)} hosts; limit is {max_hosts}")
    return addresses
