from __future__ import annotations


def parse_ports(value: str) -> tuple[int, ...]:
    ports: set[int] = set()
    for chunk in value.split(","):
        token = chunk.strip()
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", maxsplit=1)
            start = _validate_port(int(left.strip()))
            end = _validate_port(int(right.strip()))
            if start > end:
                raise ValueError(f"Invalid range: {token}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_validate_port(int(token)))
    if not ports:
        raise ValueError("At least one port is required")
    return tuple(sorted(ports))


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port outside 1..65535: {port}")
    return port
