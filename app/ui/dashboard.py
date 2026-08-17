from __future__ import annotations

from collections.abc import Callable

import customtkinter as ctk
import psutil

from app.services.history import HistoryService
from app.ui.lifecycle import LifecycleFrame
from app.ui.theme import UiTheme


class DashboardPage(LifecycleFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        history: HistoryService,
        monitor_status: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._monitor_status = monitor_status or (lambda: "Monitor disabled")
        self._build()
        self.after(500, self.refresh)
        self.after(1000, self._update_system_stats)

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 18))
        ctk.CTkLabel(
            header,
            text="Security & Network Overview",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left")
        self.monitor_label = ctk.CTkLabel(
            header,
            text="",
            font=(self._font, 10, "bold"),
            text_color=UiTheme.MUTED,
        )
        self.monitor_label.pack(side="right")

        first = ctk.CTkFrame(self, fg_color="transparent")
        first.pack(fill="x", padx=24)
        self.total_devices = self._card(first, "Known Devices", 0)
        self.online_devices = self._card(first, "Online", 1)
        self.offline_devices = self._card(first, "Offline", 2)
        self.unknown_devices = self._card(first, "Unknown", 3)
        self.open_alerts = self._card(first, "Open Alerts", 4)
        for index in range(5):
            first.grid_columnconfigure(index, weight=1)

        second = ctk.CTkFrame(self, fg_color="transparent")
        second.pack(fill="x", padx=24, pady=(12, 0))
        self.cpu = self._card(second, "CPU", 0)
        self.ram = self._card(second, "RAM", 1)
        self.listeners = self._card(second, "Local Listeners", 2)
        self.last_scan_hosts = self._card(second, "Latest Scan Hosts", 3)
        self.exposures = self._card(second, "High / Critical", 4)
        for index in range(5):
            second.grid_columnconfigure(index, weight=1)

        panel = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        panel.pack(fill="both", expand=True, padx=24, pady=24)
        ctk.CTkLabel(
            panel,
            text="Guardian workflow",
            font=(self._font, 18, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=20, pady=(20, 8))
        ctk.CTkLabel(
            panel,
            text=(
                "1. Asset Discovery finds responsive devices on an authorized local network.\n"
                "2. Device Inventory tracks identity, online/offline state, trust status and last seen time.\n"
                "3. Alerts highlights new Unknown devices and Blocked devices that become reachable.\n"
                "4. Network Assessment fingerprints reachable services and records evidence.\n"
                "5. Exposure Analysis prioritizes risky services, TLS issues and candidate CVEs.\n"
                "6. Event Log records device discovery and online/offline transitions.\n"
                "7. Local Port Guard correlates local listeners with processes, signatures, Defender and Firewall rules."
            ),
            wraplength=1040,
            justify="left",
            font=(self._font, 11),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=20, pady=(0, 20))

    def _card(self, parent: ctk.CTkFrame, title: str, column: int) -> ctk.CTkLabel:
        card = ctk.CTkFrame(parent, fg_color=UiTheme.PANEL, corner_radius=14)
        card.grid(row=0, column=column, sticky="nsew", padx=5)
        ctk.CTkLabel(
            card,
            text=title,
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=14, pady=(12, 3))
        value = ctk.CTkLabel(
            card,
            text="—",
            font=(self._font, 21, "bold"),
            text_color=UiTheme.TEXT,
        )
        value.pack(anchor="w", padx=14, pady=(0, 12))
        return value

    def refresh(self) -> None:
        counts = self._history.device_counts()
        self.total_devices.configure(text=str(counts["total"]))
        self.online_devices.configure(text=str(counts["online"]), text_color=UiTheme.SUCCESS if counts["online"] else UiTheme.TEXT)
        self.offline_devices.configure(text=str(counts["offline"]))
        self.unknown_devices.configure(text=str(counts["unknown"]), text_color=UiTheme.WARNING if counts["unknown"] else UiTheme.TEXT)
        self.open_alerts.configure(text=str(counts["alerts"]), text_color=UiTheme.DANGER if counts["alerts"] else UiTheme.TEXT)
        self.monitor_label.configure(text=self._monitor_status())

        scans = self._history.list_recent(1)
        if not scans:
            self.exposures.configure(text="0")
            self.last_scan_hosts.configure(text="0")
            return
        scan = scans[0]
        high = sum(
            1
            for host in scan.hosts
            for port in host.ports
            if (port.risk_level or "low") in {"high", "critical"}
        )
        self.exposures.configure(text=str(high), text_color=UiTheme.DANGER if high else UiTheme.TEXT)
        self.last_scan_hosts.configure(text=str(len(scan.hosts)))

    def _update_system_stats(self) -> None:
        self.cpu.configure(text=f"{psutil.cpu_percent(interval=None):.0f}%")
        self.ram.configure(text=f"{psutil.virtual_memory().percent:.0f}%")
        try:
            tcp = psutil.net_connections(kind="tcp")
            listeners = sum(1 for item in tcp if item.status == psutil.CONN_LISTEN)
            self.listeners.configure(text=str(listeners))
        except psutil.AccessDenied:
            self.listeners.configure(text="Admin")
        self.after(3000, self._update_system_stats)
