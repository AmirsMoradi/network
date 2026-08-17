from __future__ import annotations

import platform
import re
import subprocess

from app.domain.models import PingResult


class PingService:
    """Small, auditable ICMP health check for a selected host."""

    def ping(self, host: str, *, count: int = 4, timeout_seconds: int = 1) -> PingResult:
        count = min(10, max(1, int(count)))
        timeout_seconds = min(5, max(1, int(timeout_seconds)))
        system = platform.system().lower()
        if system == "windows":
            command = ["ping", "-n", str(count), "-w", str(timeout_seconds * 1000), host]
        else:
            command = ["ping", "-c", str(count), "-W", str(timeout_seconds), host]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=count * timeout_seconds + 5,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Ping failed: {exc}") from exc

        output = f"{completed.stdout}\n{completed.stderr}"
        transmitted, received, loss = self._parse_counts(output, count, system)
        average = self._parse_average(output, system)
        return PingResult(
            host=host,
            transmitted=transmitted,
            received=received,
            packet_loss_percent=loss,
            average_latency_ms=average,
        )

    @staticmethod
    def _parse_counts(output: str, requested: int, system: str) -> tuple[int, int, float]:
        if system == "windows":
            match = re.search(
                r"Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*(\d+).*?\((\d+)%\s*loss\)",
                output,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if match:
                sent, received, _lost, loss = map(int, match.groups())
                return sent, received, float(loss)
        else:
            match = re.search(
                r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received,\s*([\d.]+)%\s+packet loss",
                output,
                flags=re.IGNORECASE,
            )
            if match:
                sent = int(match.group(1))
                received = int(match.group(2))
                return sent, received, float(match.group(3))
        received = requested if "ttl=" in output.lower() else 0
        loss = 100.0 * (requested - received) / requested
        return requested, received, round(loss, 1)

    @staticmethod
    def _parse_average(output: str, system: str) -> float | None:
        if system == "windows":
            match = re.search(r"Average\s*=\s*(\d+)ms", output, flags=re.IGNORECASE)
            return float(match.group(1)) if match else None
        match = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms", output)
        return float(match.group(1)) if match else None
