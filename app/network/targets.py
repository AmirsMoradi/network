from __future__ import annotations

import ipaddress


def expand_target(target: str, *, max_hosts: int) -> tuple[str, ...]:
    text = target.strip()
    if not text:
        raise ValueError("Target is required")
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1")

    if "/" not in text:
        try:
            return (str(ipaddress.ip_address(text)),)
        except ValueError as exc:
            raise ValueError("Target must be a valid IPv4/IPv6 address or CIDR") from exc

    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError("Target must be a valid IPv4/IPv6 address or CIDR") from exc

    # Avoid materializing massive networks (especially IPv6) merely to reject
    # them after allocation. ``hosts()`` excludes at most a very small number of
    # reserved addresses, so num_addresses > max_hosts + 2 is always too large.
    if int(network.num_addresses) > max_hosts + 2:
        raise ValueError(f"Target exceeds configured host limit of {max_hosts}")

    addresses = tuple(str(ip) for ip in network.hosts())
    if len(addresses) > max_hosts:
        raise ValueError(f"Target expands to {len(addresses)} hosts; limit is {max_hosts}")
    return addresses


def validate_private_ipv4_target(target: str, *, max_hosts: int = 4096) -> str:
    """Validate a bounded private IPv4 host/CIDR for unattended monitoring.

    Manual assessment can intentionally target other authorized addresses, but the
    persistent background monitor is deliberately restricted to local/private IPv4
    space so a configuration-file edit cannot turn it into unattended Internet
    scanning.
    """
    text = target.strip()
    if not text:
        raise ValueError("Monitoring target is required")
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1")
    try:
        network = (
            ipaddress.ip_network(text, strict=False)
            if "/" in text
            else ipaddress.ip_network(f"{text}/32", strict=False)
        )
    except ValueError as exc:
        raise ValueError("Monitoring target must be a valid private IPv4 address or CIDR") from exc
    if network.version != 4 or not network.is_private:
        raise ValueError("Automatic monitoring is limited to private IPv4 networks")

    # Exact IPv4 host count matching ipaddress.hosts() behavior for the cases
    # relevant to local monitoring (/31 and /32 include all addresses).
    host_count = (
        int(network.num_addresses)
        if network.prefixlen >= 31
        else max(0, int(network.num_addresses) - 2)
    )
    if host_count > max_hosts:
        raise ValueError(f"Monitoring target expands beyond the {max_hosts}-host limit")
    return text
