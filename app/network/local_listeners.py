from __future__ import annotations

from collections.abc import Iterable

import psutil

from app.domain.models import ListenerRecord
from app.security.defender import WindowsDefenderCorrelator
from app.security.risk_engine import ListenerRiskEngine
from app.security.signatures import get_authenticode_status


class LocalListenerInspector:
    def __init__(self, risk_engine: ListenerRiskEngine | None = None) -> None:
        self._risk_engine = risk_engine or ListenerRiskEngine()
        self._defender = WindowsDefenderCorrelator()

    def list_listeners(self) -> list[ListenerRecord]:
        records: list[ListenerRecord] = []
        for connection in self._safe_connections():
            if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                continue
            pid = connection.pid
            process_name = "Unknown"
            executable: str | None = None
            username: str | None = None
            if pid is not None:
                try:
                    process = psutil.Process(pid)
                    with process.oneshot():
                        process_name = process.name()
                        executable = process.exe() or None
                        username = process.username() or None
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    pass

            signature_status = get_authenticode_status(executable)
            defender_detected = self._defender.detected(executable)
            score, level, reasons = self._risk_engine.score(
                port=connection.laddr.port,
                local_ip=connection.laddr.ip,
                process_name=process_name,
                executable=executable,
                signature_status=signature_status,
                defender_detected=defender_detected,
            )
            records.append(
                ListenerRecord(
                    protocol="TCP",
                    local_ip=connection.laddr.ip,
                    port=connection.laddr.port,
                    pid=pid,
                    process_name=process_name,
                    executable=executable,
                    username=username,
                    signature_status=signature_status,
                    defender_detected=defender_detected,
                    risk_score=score,
                    risk_level=level,
                    risk_reasons=reasons,
                )
            )
        return sorted(records, key=lambda item: (-item.risk_score, item.port, item.process_name))

    @staticmethod
    def _safe_connections() -> Iterable[psutil._common.sconn]:  # type: ignore[attr-defined]
        try:
            return psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            return []
