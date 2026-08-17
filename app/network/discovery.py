from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass

import psutil

from app.core.config import DEFAULT_SCAN_CONFIG, ScanConfig
from app.domain.models import DeviceObservation
from app.network.targets import expand_target

DiscoveryProgress = Callable[[int, int], None]


@dataclass(frozen=True, slots=True)
class _ProbeResult:
    ip: str
    alive: bool
    latency_ms: float | None
    methods: tuple[str, ...]


class HostDiscoveryService:
    """Auditable host discovery using ICMP and ordinary TCP connect probes.

    No stealth/evasion behavior is used. ARP data is read from the local OS cache
    to enrich local IPv4 observations with MAC addresses.
    """

    _TCP_DISCOVERY_PORTS = (22, 80, 443, 445, 3389)

    def __init__(self, config: ScanConfig = DEFAULT_SCAN_CONFIG) -> None:
        self._config = config

    async def discover(
        self,
        target: str,
        *,
        progress: DiscoveryProgress | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[DeviceObservation]:
        hosts = expand_target(target, max_hosts=self._config.max_hosts)
        semaphore = asyncio.Semaphore(min(128, self._config.max_concurrency))
        completed = 0

        async def run_one(ip: str) -> _ProbeResult:
            nonlocal completed
            async with semaphore:
                if cancel_event is not None and cancel_event.is_set():
                    return _ProbeResult(ip, False, None, ())
                result = await self._probe_host(ip)
                completed += 1
                if progress is not None:
                    progress(completed, len(hosts))
                return result

        results = await asyncio.gather(*(run_one(ip) for ip in hosts))
        if cancel_event is not None and cancel_event.is_set():
            return []

        arp = await asyncio.to_thread(self._read_arp_cache)
        alive_results = [result for result in results if result.alive]
        resolver_semaphore = asyncio.Semaphore(64)

        async def build_observation(result: _ProbeResult) -> DeviceObservation | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            async with resolver_semaphore:
                hostname = await self._resolve_hostname(result.ip)
            if cancel_event is not None and cancel_event.is_set():
                return None
            return DeviceObservation(
                ip=result.ip,
                hostname=hostname,
                mac_address=arp.get(result.ip),
                vendor=None,
                methods=result.methods,
                latency_ms=result.latency_ms,
            )

        built = await asyncio.gather(*(build_observation(result) for result in alive_results))
        if cancel_event is not None and cancel_event.is_set():
            return []
        observations = [item for item in built if item is not None]
        observations.sort(key=lambda item: ipaddress.ip_address(item.ip))
        return observations

    async def _probe_host(self, ip: str) -> _ProbeResult:
        icmp_alive, latency = await self._icmp_probe(ip)
        methods: list[str] = ["icmp"] if icmp_alive else []
        if icmp_alive:
            return _ProbeResult(ip, True, latency, tuple(methods))
        tcp_alive = False
        for port in self._TCP_DISCOVERY_PORTS:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=min(0.35, self._config.timeout_seconds),
                )
            except (TimeoutError, OSError):
                continue
            else:
                writer.close()
                await writer.wait_closed()
                tcp_alive = True
                methods.append(f"tcp:{port}")
                break
        return _ProbeResult(ip, icmp_alive or tcp_alive, latency, tuple(methods))

    async def _icmp_probe(self, ip: str) -> tuple[bool, float | None]:
        system = platform.system().lower()
        if system == "windows":
            command = ["ping", "-n", "1", "-w", "700", ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]
        started = asyncio.get_running_loop().time()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return_code = await asyncio.wait_for(process.wait(), timeout=1.5)
        except (OSError, TimeoutError):
            return False, None
        if return_code != 0:
            return False, None
        latency = round((asyncio.get_running_loop().time() - started) * 1000, 2)
        return True, latency

    async def _resolve_hostname(self, ip: str) -> str | None:
        try:
            hostname, _, _ = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip),
                timeout=1.25,
            )
            return hostname
        except (socket.herror, socket.gaierror, OSError, TimeoutError):
            return None

    @staticmethod
    def _read_arp_cache() -> dict[str, str]:
        if platform.system().lower() != "windows":
            return {}
        try:
            completed = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError:
            return {}
        mapping: dict[str, str] = {}
        pattern = re.compile(
            r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
            r"(?P<mac>[0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+"
        )
        for line in completed.stdout.splitlines():
            match = pattern.search(line)
            if match:
                mapping[match.group("ip")] = match.group("mac").replace("-", ":").upper()
        return mapping

    @staticmethod
    def local_ipv4_networks() -> tuple[str, ...]:
        networks: set[str] = set()
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family != socket.AF_INET or not address.netmask:
                    continue
                try:
                    interface = ipaddress.IPv4Interface(f"{address.address}/{address.netmask}")
                except ValueError:
                    continue
                if interface.ip.is_loopback:
                    continue
                networks.add(str(interface.network))
        return tuple(sorted(networks))
