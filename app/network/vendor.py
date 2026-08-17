from __future__ import annotations

import csv
import io
import json
import time
import urllib.request
from pathlib import Path

from app.core.config import APP_DIR


class MacVendorResolver:
    """Resolve MAC OUIs from an optional, cached IEEE public assignment CSV."""

    IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
    CACHE_PATH = APP_DIR / "oui.csv"
    META_PATH = APP_DIR / "oui-meta.json"

    def __init__(self) -> None:
        self._mapping: dict[str, str] | None = None

    def resolve(self, mac_address: str | None) -> str | None:
        if not mac_address:
            return None
        mapping = self._load_mapping()
        prefix = "".join(ch for ch in mac_address.upper() if ch.isalnum())[:6]
        return mapping.get(prefix)

    def update_cache(self, *, max_age_days: int = 30) -> bool:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if self.CACHE_PATH.exists() and self._cache_is_fresh(max_age_days):
            return False
        request = urllib.request.Request(
            self.IEEE_OUI_URL,
            headers={"User-Agent": "SurNet-Guardian/0.3"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            payload = response.read()
        self.CACHE_PATH.write_bytes(payload)
        self.META_PATH.write_text(json.dumps({"updated_at": time.time()}), encoding="utf-8")
        self._mapping = None
        return True

    def _load_mapping(self) -> dict[str, str]:
        if self._mapping is not None:
            return self._mapping
        mapping: dict[str, str] = {}
        if not self.CACHE_PATH.exists():
            self._mapping = mapping
            return mapping
        content = self.CACHE_PATH.read_text(encoding="utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            assignment = (row.get("Assignment") or "").replace("-", "").upper()
            organization = (row.get("Organization Name") or "").strip()
            if len(assignment) >= 6 and organization:
                mapping[assignment[:6]] = organization
        self._mapping = mapping
        return mapping

    def _cache_is_fresh(self, max_age_days: int) -> bool:
        try:
            metadata = json.loads(self.META_PATH.read_text(encoding="utf-8"))
            updated_at = float(metadata["updated_at"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False
        return time.time() - updated_at < max_age_days * 86400
