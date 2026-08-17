from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from datetime import datetime

from app.domain.models import DeviceObservation, MonitorCycleSummary
from app.network.discovery import HostDiscoveryService
from app.network.targets import validate_private_ipv4_target
from app.network.vendor import MacVendorResolver
from app.services.history import HistoryService

LOGGER = logging.getLogger(__name__)

MonitorCycleCallback = Callable[[MonitorCycleSummary], None]
MonitorErrorCallback = Callable[[Exception], None]


class NetworkMonitorService:
    """Periodic local-network presence monitoring using normal discovery probes."""

    def __init__(
        self,
        discovery: HostDiscoveryService,
        vendor_resolver: MacVendorResolver,
        history: HistoryService,
        *,
        on_cycle: MonitorCycleCallback | None = None,
        on_error: MonitorErrorCallback | None = None,
    ) -> None:
        self._discovery = discovery
        self._vendor = vendor_resolver
        self._history = history
        self._on_cycle = on_cycle
        self._on_error = on_error
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._target = ""
        self._interval = 60
        self._lock = threading.Lock()
        self._last_cycle: datetime | None = None
        self._last_error: str | None = None

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def target(self) -> str:
        return self._target

    @property
    def interval_seconds(self) -> int:
        return self._interval

    @property
    def last_cycle(self) -> datetime | None:
        return self._last_cycle

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def start(self, target: str, interval_seconds: int) -> None:
        target = validate_private_ipv4_target(target, max_hosts=4096)
        interval = min(86_400, max(15, int(interval_seconds)))

        # Stop the previous worker before replacing its Event object. This avoids
        # a stale monitor thread accidentally observing the new worker's Event.
        self.stop(wait=True)
        if self.running:
            raise RuntimeError("Previous monitoring worker is still stopping; try again in a moment")
        stop_event = threading.Event()
        wake_event = threading.Event()
        thread = threading.Thread(
            target=self._run,
            args=(stop_event, wake_event, target, interval),
            daemon=True,
            name="network-presence-monitor",
        )
        with self._lock:
            self._target = target
            self._interval = interval
            self._last_error = None
            self._stop_event = stop_event
            self._wake_event = wake_event
            self._thread = thread
        thread.start()

    def stop(self, *, wait: bool = False) -> None:
        with self._lock:
            thread = self._thread
            stop_event = self._stop_event
            wake_event = self._wake_event
        if thread is None:
            return
        stop_event.set()
        wake_event.set()
        if wait and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=6)
        with self._lock:
            if self._thread is thread and not thread.is_alive():
                self._thread = None

    def trigger_now(self) -> bool:
        """Wake an active monitor so the next cycle starts immediately."""
        with self._lock:
            thread = self._thread
            wake_event = self._wake_event
        if thread is None or not thread.is_alive():
            return False
        wake_event.set()
        return True

    def run_once(self, target: str) -> MonitorCycleSummary:
        target = validate_private_ipv4_target(target, max_hosts=4096)
        return asyncio.run(self._cycle(target, threading.Event()))

    def _run(
        self,
        stop_event: threading.Event,
        wake_event: threading.Event,
        target: str,
        interval: int,
    ) -> None:
        try:
            while not stop_event.is_set():
                try:
                    summary = asyncio.run(self._cycle(target, stop_event))
                    if stop_event.is_set():
                        break
                    self._last_cycle = summary.completed_at
                    self._last_error = None
                    if self._on_cycle is not None:
                        self._on_cycle(summary)
                except Exception as exc:  # monitoring must stay alive after a transient failure
                    if stop_event.is_set():
                        break
                    LOGGER.exception("Network monitoring cycle failed")
                    self._last_error = str(exc)
                    if self._on_error is not None:
                        self._on_error(exc)
                wake_event.wait(interval)
                wake_event.clear()
                if stop_event.is_set():
                    break
        finally:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None

    async def _cycle(
        self,
        target: str,
        stop_event: threading.Event,
    ) -> MonitorCycleSummary:
        observations = await self._discovery.discover(target, cancel_event=stop_event)
        if stop_event.is_set():
            # A partial discovery caused by application shutdown must never mark
            # unseen devices offline.
            raise RuntimeError("Monitoring cycle cancelled")
        enriched = [
            DeviceObservation(
                ip=item.ip,
                hostname=item.hostname,
                mac_address=item.mac_address,
                vendor=self._vendor.resolve(item.mac_address),
                methods=item.methods,
                latency_ms=item.latency_ms,
            )
            for item in observations
        ]
        return self._history.record_monitor_cycle(enriched, target)
