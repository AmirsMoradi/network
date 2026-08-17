from __future__ import annotations

import psutil
import customtkinter as ctk

from app.ui.theme import UiTheme


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, *, font_family: str) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._build()
        self.after(1000, self._update_stats)

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
        self.connections = self._card(cards, "TCP Connections", 2)
        self.listeners = self._card(cards, "Listening Ports", 3)
        for index in range(4):
            cards.grid_columnconfigure(index, weight=1)

        panel = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        panel.pack(fill="both", expand=True, padx=24, pady=24)
        ctk.CTkLabel(
            panel,
            text="SurNet Guardian",
            font=(self._font, 20, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=20, pady=(20, 8))
        ctk.CTkLabel(
            panel,
            text=(
                "Authorized network discovery, local listener inspection, heuristic exposure scoring, "
                "Windows Firewall control, scan persistence and change-ready architecture."
            ),
            wraplength=880,
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

    def _update_stats(self) -> None:
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
        self.after(2000, self._update_stats)
