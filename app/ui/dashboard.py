from __future__ import annotations

import psutil
import customtkinter as ctk

from app.services.history import HistoryService
from app.ui.theme import UiTheme


class DashboardPage(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        history: HistoryService,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._build()
        self.after(500, self.refresh)
        self.after(1000, self._update_system_stats)

    def _build(self) -> None:
        ctk.CTkLabel(
            self,
            text="Security & Network Overview",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=24, pady=(24, 18))

        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", padx=24)
        self.cpu = self._card(cards, "CPU", 0)
        self.ram = self._card(cards, "RAM", 1)
        self.devices = self._card(cards, "Known Devices", 2)
        self.exposures = self._card(cards, "High / Critical", 3)
        for index in range(4):
            cards.grid_columnconfigure(index, weight=1)

        second = ctk.CTkFrame(self, fg_color="transparent")
        second.pack(fill="x", padx=24, pady=(12, 0))
        self.connections = self._card(second, "TCP Connections", 0)
        self.listeners = self._card(second, "Local Listeners", 1)
        self.last_scan_hosts = self._card(second, "Latest Scan Hosts", 2)
        self.last_scan_ports = self._card(second, "Latest Open Ports", 3)
        for index in range(4):
            second.grid_columnconfigure(index, weight=1)

        panel = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        panel.pack(fill="both", expand=True, padx=24, pady=24)
        ctk.CTkLabel(
            panel,
            text="Assessment workflow",
            font=(self._font, 18, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=20, pady=(20, 8))
        ctk.CTkLabel(
            panel,
            text=(
                "1. Asset Discovery builds a persistent device inventory.\n"
                "2. Network Assessment fingerprints reachable services and records evidence.\n"
                "3. Exposure Analysis prioritizes risky services, TLS issues and candidate CVEs.\n"
                "4. Network Changes compares scans to identify new hosts, ports and service changes.\n"
                "5. Local Port Guard correlates listeners with processes, signatures, Defender and Firewall rules."
            ),
            wraplength=980,
            justify="left",
            font=(self._font, 11),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=20, pady=(0, 20))

    def _card(self, parent: ctk.CTkFrame, title: str, column: int) -> ctk.CTkLabel:
        card = ctk.CTkFrame(parent, fg_color=UiTheme.PANEL, corner_radius=14)
        card.grid(row=0, column=column, sticky="nsew", padx=6)
        ctk.CTkLabel(
            card,
            text=title,
            font=(self._font, 10),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=16, pady=(14, 4))
        value = ctk.CTkLabel(
            card,
            text="—",
            font=(self._font, 23, "bold"),
            text_color=UiTheme.TEXT,
        )
        value.pack(anchor="w", padx=16, pady=(0, 14))
        return value

    def refresh(self) -> None:
        devices = self._history.list_devices(1000)
        self.devices.configure(text=str(len(devices)))
        scans = self._history.list_recent(1)
        if not scans:
            self.exposures.configure(text="0")
            self.last_scan_hosts.configure(text="0")
            self.last_scan_ports.configure(text="0")
            return
        scan = scans[0]
        high = 0
        open_ports = 0
        for host in scan.hosts:
            open_ports += len(host.ports)
            for port in host.ports:
                if (port.risk_level or "low") in {"high", "critical"}:
                    high += 1
        self.exposures.configure(text=str(high), text_color=UiTheme.DANGER if high else UiTheme.TEXT)
        self.last_scan_hosts.configure(text=str(len(scan.hosts)))
        self.last_scan_ports.configure(text=str(open_ports))

    def _update_system_stats(self) -> None:
        self.cpu.configure(text=f"{psutil.cpu_percent(interval=None):.0f}%")
        self.ram.configure(text=f"{psutil.virtual_memory().percent:.0f}%")
        try:
            tcp = psutil.net_connections(kind="tcp")
            self.connections.configure(text=str(len(tcp)))
            listeners = sum(1 for item in tcp if item.status == psutil.CONN_LISTEN)
            self.listeners.configure(text=str(listeners))
        except psutil.AccessDenied:
            self.connections.configure(text="Admin")
            self.listeners.configure(text="Admin")
        self.after(3000, self._update_system_stats)
