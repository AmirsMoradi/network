from __future__ import annotations

import customtkinter as ctk

from app.core.config import APP_NAME, APP_VERSION
from app.database.session import Database
from app.network.local_listeners import LocalListenerInspector
from app.network.scanner import AsyncTcpScanner
from app.security.windows_firewall import WindowsFirewallService
from app.services.history import HistoryService
from app.ui.dashboard import DashboardPage
from app.ui.history_page import HistoryPage
from app.ui.listeners_page import ListenersPage
from app.ui.scan_page import ScanPage
from app.ui.theme import UiTheme, select_font_family


class MainWindow(ctk.CTk):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1280x800")
        self.minsize(1080, 680)
        self.configure(fg_color=UiTheme.BG)
        self._font = select_font_family(self)
        self._database = database
        self._history = HistoryService(database)
        self._pages: dict[str, ctk.CTkFrame] = {}
        self._build()
        self.show_page("dashboard")

    def _build(self) -> None:
        shell = ctk.CTkFrame(self, fg_color=UiTheme.BG)
        shell.pack(fill="both", expand=True)
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)

        sidebar = ctk.CTkFrame(
            shell,
            width=220,
            fg_color=UiTheme.PANEL,
            corner_radius=0,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(
            sidebar,
            text="SurNet\nGuardian",
            justify="left",
            font=(self._font, 21, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=22, pady=(26, 28))

        for label, key in (
            ("Overview", "dashboard"),
            ("Network Scan", "scan"),
            ("Local Port Guard", "listeners"),
            ("Scan History", "history"),
        ):
            ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                height=42,
                corner_radius=9,
                fg_color="transparent",
                hover_color=UiTheme.PANEL_ALT,
                font=(self._font, 11, "bold"),
                command=lambda page=key: self.show_page(page),
            ).pack(fill="x", padx=12, pady=4)

        ctk.CTkLabel(
            sidebar,
            text="Windows-first • Python 3.12",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).pack(side="bottom", anchor="w", padx=22, pady=18)

        self.content = ctk.CTkFrame(shell, fg_color=UiTheme.BG, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")

        scanner = AsyncTcpScanner()
        inspector = LocalListenerInspector()
        firewall = WindowsFirewallService()
        self._pages = {
            "dashboard": DashboardPage(self.content, font_family=self._font),
            "scan": ScanPage(
                self.content,
                font_family=self._font,
                scanner=scanner,
                history=self._history,
            ),
            "listeners": ListenersPage(
                self.content,
                font_family=self._font,
                inspector=inspector,
                firewall=firewall,
            ),
            "history": HistoryPage(
                self.content,
                font_family=self._font,
                history=self._history,
            ),
        }

    def show_page(self, key: str) -> None:
        for page in self._pages.values():
            page.pack_forget()
        page = self._pages[key]
        page.pack(fill="both", expand=True)
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()
