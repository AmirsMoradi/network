from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from app.core.config import DEFAULT_SCAN_CONFIG, ScanConfig
from app.domain.models import HostResult, PortResult, ScanResult

ProgressCallback = Callable[[int, int], None]


class ScanCancelled(RuntimeError):
    pass


class AsyncTcpScanner:
    def __init__(self, config: ScanConfig = DEFAULT_SCAN_CONFIG) -> None:
        self._config = config

    async def scan(
        self,
        target: str,
        ports: Iterable[int],
        progress: ProgressCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        hosts = self._expand_target(target)
        port_list = tuple(ports)
        if not port_list:
            raise ValueError("No ports selected")

        total = len(hosts) * len(port_list)
        if total > self._config.max_operations:
            raise ValueError(
                f"Scan requires {total:,} socket checks; configured limit is "
                f"{self._config.max_operations:,}. Narrow the host range or port set."
            )

        started = datetime.now(timezone.utc)
        results: dict[str, HostResult] = {ip: HostResult(ip=ip) for ip in hosts}
        queue: asyncio.Queue[tuple[str, int] | None] = asyncio.Queue(
            maxsize=max(64, self._config.max_concurrency * 4)
        )
        completed = 0
        worker_count = min(self._config.max_concurrency, max(1, total))

        async def producer() -> None:
            try:
                for ip in hosts:
                    for port in port_list:
                        if cancel_event is not None and cancel_event.is_set():
                            return
                        await queue.put((ip, port))
            finally:
                for _ in range(worker_count):
                    await queue.put(None)

        async def worker() -> None:
            nonlocal completed
            while True:
                item = await queue.get()
                try:
                    if item is None:
                        return
                    if cancel_event is not None and cancel_event.is_set():
                        continue
                    ip, port = item
                    opened, latency = await self._probe(ip, port)
                    if opened:
                        results[ip].ports.append(
                            PortResult(
                                port=port,
                                service=self._service_name(port),
                                latency_ms=latency,
                            )
                        )
                    completed += 1
                    if progress is not None:
                        progress(completed, total)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
        producer_task = asyncio.create_task(producer())
        await asyncio.gather(producer_task, *workers)

        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by user")

        visible_hosts = [host for host in results.values() if host.ports]
        await asyncio.gather(*(self._resolve_hostname(host) for host in visible_hosts))
        visible_hosts.sort(key=lambda item: ipaddress.ip_address(item.ip))
        for host in visible_hosts:
            host.ports.sort(key=lambda item: item.port)

        return ScanResult(
            target=target,
            hosts=visible_hosts,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
        )

    async def _probe(self, ip: str, port: int) -> tuple[bool, float | None]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self._config.timeout_seconds,
            )
            del reader
            writer.close()
            await writer.wait_closed()
            return True, round((loop.time() - started) * 1000, 2)
        except asyncio.CancelledError:
            raise
        except (TimeoutError, OSError):
            return False, None

    async def _resolve_hostname(self, host: HostResult) -> None:
        try:
            hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, host.ip)
            host.hostname = hostname
        except (socket.herror, socket.gaierror, OSError):
            host.hostname = None

    def _expand_target(self, target: str) -> tuple[str, ...]:
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

        if len(addresses) > self._config.max_hosts:
            raise ValueError(
                f"Target expands to {len(addresses)} hosts; limit is {self._config.max_hosts}"
            )
        return addresses

    @staticmethod
    def _service_name(port: int) -> str:
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"
