from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


APP_NAME = "SurNet Guardian"
APP_VERSION = "0.2.0"
APP_DIR = Path.home() / ".surnet_guardian"
DB_PATH = APP_DIR / "surnet.db"
LOG_PATH = APP_DIR / "surnet.log"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    timeout_seconds: float = 0.45
    max_concurrency: int = 350
    max_hosts: int = 4096
    max_operations: int = 2_000_000


DEFAULT_SCAN_CONFIG = ScanConfig()

COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
)
