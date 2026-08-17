from __future__ import annotations

import logging
import threading
from queue import Empty, Queue

import customtkinter as ctk

from app.core.config import APP_NAME, APP_VERSION
from app.database.session import Database
from app.network.discovery import HostDiscoveryService
from app.network.local_listeners import LocalListenerInspector
from app.network.ping import PingService
from app.network.scanner import AsyncTcpScanner
from app.network.vendor import MacVendorResolver
from app.security.vulnerability_intel import VulnerabilityIntelService
from app.security.windows_firewall import WindowsFirewallService
from app.services.history import HistoryService
from app.services.monitor import NetworkMonitorService
from app.services.settings import AppSettings, SettingsService
from app.services.startup import StartupService
from app.services.tray import TrayService
from app.ui.alerts_page import AlertsPage
from app.ui.changes_page import ChangesPage
from app.ui.dashboard import DashboardPage
from app.ui.devices_page import DevicesPage
from app.ui.discovery_page import DiscoveryPage
from app.ui.events_page import EventsPage
from app.ui.exposure_page import ExposurePage
from app.ui.history_page import HistoryPage
from app.ui.listeners_page import ListenersPage
from app.ui.scan_page import ScanPage
from app.ui.settings_page import SettingsPage
from app.ui.theme import UiTheme, configure_ctk, select_font_family


LOGGER = logging.getLogger(__name__)


class MainWindow(ctk.CTk):
    def __init__(self, database: Database, settings_service: SettingsService | None = None) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1500x900")
        self.minsize(1180, 720)
        self.configure(fg_color=UiTheme.BG)
        self._font = select_font_family(self)
        self._database = database
        self._history = HistoryService(database)
        self._settings_service = settings_service or SettingsService()
        self._settings = self._settings_service.load()
        self._startup = StartupService()
        self._discovery = HostDiscoveryService()
        self._vendor = MacVendorResolver()
        self._pages: dict[str, ctk.CTkFrame] = {}
        self._page_key = "dashboard"
        self._shell: ctk.CTkFrame | None = None
        self._closing = False
        self._ui_queue: Queue[tuple[str, object]] = Queue()
        self._manual_monitor_lock = threading.Lock()

        self._monitor = NetworkMonitorService(
            self._discovery,
            self._vendor,
            self._history,
            on_cycle=lambda summary: self._ui_queue.put(("monitor_cycle", summary)),
            on_error=lambda exc: self._ui_queue.put(("monitor_error", exc)),
        )
        self._tray = TrayService(
            on_show=lambda: self._ui_queue.put(("tray_show", None)),
            on_exit=lambda: self._ui_queue.put(("tray_exit", None)),
        )

        self.protocol("WM_DELETE_WINDOW", self._exit_application)
        self.bind("<Unmap>", self._on_unmap)
        self._build()
        self.show_page("dashboard")
        self.after(100, self._drain_ui_queue)
        self._apply_runtime_settings(self._settings, allow_rebuild=False)

    def _build(self) -> None:
        if self._shell is not None:
            self._shell.destroy()

        shell = ctk.CTkFrame(self, fg_color=UiTheme.BG)
        shell.pack(fill="both", expand=True)
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)
        self._shell = shell

        sidebar = ctk.CTkFrame(
            shell,
            width=242,
            fg_color=UiTheme.PANEL,
            corner_radius=0,
        )
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(
            sidebar,
            text="SurNet\nGuardian",
            justify="left",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=22, pady=(22, 4))
        ctk.CTkLabel(
            sidebar,
            text=f"Network Security & Asset Intelligence  •  v{APP_VERSION}",
            wraplength=195,
            justify="left",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=22, pady=(0, 14))

        for label, key in (
            ("Overview", "dashboard"),
            ("Asset Discovery", "discovery"),
            ("Device Inventory", "devices"),
            ("Alerts", "alerts"),
            ("Network Assessment", "scan"),
            ("Exposure Analysis", "exposure"),
            ("Network Changes", "changes"),
            ("Local Port Guard", "listeners"),
            ("Event Log", "events"),
            ("Scan History", "history"),
            ("Settings", "settings"),
        ):
            ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                height=37,
                corner_radius=8,
                fg_color="transparent",
                hover_color=UiTheme.PANEL_ALT,
                text_color=UiTheme.TEXT,
                font=(self._font, 10, "bold"),
                command=lambda page=key: self.show_page(page),
            ).pack(fill="x", padx=12, pady=2)

        ctk.CTkLabel(
            sidebar,
            text="Authorized defensive assessment\nPython 3.12 • Local SQLite",
            justify="left",
            font=(self._font, 8),
            text_color=UiTheme.MUTED,
        ).pack(side="bottom", anchor="w", padx=22, pady=16)

        self.content = ctk.CTkFrame(shell, fg_color=UiTheme.BG, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")

        scanner = AsyncTcpScanner()
        inspector = LocalListenerInspector()
        firewall = WindowsFirewallService()
        vulnerability_intel = VulnerabilityIntelService()
        self._pages = {
            "dashboard": DashboardPage(
                self.content,
                font_family=self._font,
                history=self._history,
                monitor_status=self._monitor_status,
            ),
            "discovery": DiscoveryPage(
                self.content,
                font_family=self._font,
                discovery=self._discovery,
                vendor_resolver=self._vendor,
                history=self._history,
            ),
            "devices": DevicesPage(
                self.content,
                font_family=self._font,
                history=self._history,
                ping_service=PingService(),
            ),
            "alerts": AlertsPage(
                self.content,
                font_family=self._font,
                history=self._history,
            ),
            "scan": ScanPage(
                self.content,
                font_family=self._font,
                scanner=scanner,
                history=self._history,
            ),
            "exposure": ExposurePage(
                self.content,
                font_family=self._font,
                history=self._history,
                vulnerability_intel=vulnerability_intel,
            ),
            "changes": ChangesPage(
                self.content,
                font_family=self._font,
                history=self._history,
            ),
            "listeners": ListenersPage(
                self.content,
                font_family=self._font,
                inspector=inspector,
                firewall=firewall,
            ),
            "events": EventsPage(
                self.content,
                font_family=self._font,
                history=self._history,
            ),
            "history": HistoryPage(
                self.content,
                font_family=self._font,
                history=self._history,
            ),
            "settings": SettingsPage(
                self.content,
                font_family=self._font,
                settings_service=self._settings_service,
                startup_service=self._startup,
                discovery=self._discovery,
                on_saved=self._settings_saved,
                on_monitor_now=self._run_monitor_now,
            ),
        }

    def show_page(self, key: str) -> None:
        if key not in self._pages:
            return
        self._page_key = key
        for page in self._pages.values():
            page.pack_forget()
        page = self._pages[key]
        page.pack(fill="both", expand=True)
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()

    def _run_monitor_now(self, target: str) -> None:
        if self._monitor.running and self._monitor.target == target:
            self._monitor.trigger_now()
            return
        if not self._manual_monitor_lock.acquire(blocking=False):
            self._ui_queue.put(("monitor_error", RuntimeError("A manual monitoring scan is already running")))
            return

        def worker() -> None:
            try:
                summary = self._monitor.run_once(target)
                self._ui_queue.put(("monitor_cycle", summary))
            except Exception as exc:
                self._ui_queue.put(("monitor_error", exc))
            finally:
                self._manual_monitor_lock.release()

        threading.Thread(target=worker, daemon=True, name="manual-monitor-scan").start()

    def _settings_saved(self, settings: AppSettings) -> None:
        self._apply_runtime_settings(settings, allow_rebuild=True)

    def _apply_runtime_settings(self, settings: AppSettings, *, allow_rebuild: bool) -> None:
        previous_theme = UiTheme.MODE
        self._settings = settings

        if settings.minimize_to_tray or settings.notifications_enabled:
            self._tray.start()
        else:
            self._tray.stop()

        if settings.auto_monitor and settings.discovery_target:
            should_restart = (
                not self._monitor.running
                or self._monitor.target != settings.discovery_target
                or self._monitor.interval_seconds != settings.monitor_interval_seconds
            )
            if should_restart:
                try:
                    self._monitor.start(settings.discovery_target, settings.monitor_interval_seconds)
                except Exception as exc:
                    LOGGER.exception("Automatic network monitor could not be started")
                    self._ui_queue.put(("monitor_error", exc))
        else:
            self._monitor.stop(wait=False)

        if allow_rebuild and settings.theme != previous_theme:
            current = self._page_key
            configure_ctk(settings.theme)
            self.configure(fg_color=UiTheme.BG)
            self._build()
            self.show_page(current if current in self._pages else "dashboard")
        else:
            self._refresh_live_pages()

    def _monitor_status(self) -> str:
        if not self._monitor.running:
            return "Monitor OFF"
        if self._monitor.last_error:
            return f"Monitor ON • {self._monitor.target} • last error"
        if self._monitor.last_cycle:
            stamp = self._monitor.last_cycle.strftime("%H:%M:%S")
            return f"Monitor ON • {self._monitor.target} • {stamp}"
        return f"Monitor ON • {self._monitor.target} • waiting"

    def _drain_ui_queue(self) -> None:
        if self._closing:
            return
        try:
            while True:
                event, payload = self._ui_queue.get_nowait()
                if event == "monitor_cycle":
                    self._handle_monitor_cycle(payload)
                elif event == "monitor_error":
                    self._handle_monitor_error(payload)
                elif event == "tray_show":
                    self._show_from_tray()
                elif event == "tray_exit":
                    self._exit_application()
                    return
        except Empty:
            pass
        if not self._closing:
            self.after(100, self._drain_ui_queue)

    def _handle_monitor_cycle(self, payload: object) -> None:
        self._refresh_live_pages()
        alerts_created = getattr(payload, "alerts_created", 0)
        discovered = getattr(payload, "discovered", 0)
        settings_page = self._pages.get("settings")
        set_status = getattr(settings_page, "set_monitor_status", None)
        if callable(set_status):
            set_status(f"Monitor cycle complete: {discovered} device(s) reachable.")
        if alerts_created and self._settings.notifications_enabled:
            self._tray.notify(
                "SurNet Guardian alert",
                f"{alerts_created} new alert(s) detected. {discovered} device(s) were reachable.",
            )

    def _handle_monitor_error(self, payload: object) -> None:
        self._refresh_live_pages()
        settings_page = self._pages.get("settings")
        set_status = getattr(settings_page, "set_monitor_status", None)
        if callable(set_status):
            set_status(f"Monitor error: {payload}")
        if self._settings.notifications_enabled:
            self._tray.notify("SurNet Guardian monitor", f"Monitoring cycle failed: {payload}")

    def _refresh_live_pages(self) -> None:
        for key in ("dashboard", "devices", "alerts", "events"):
            page = self._pages.get(key)
            if page is None:
                continue
            refresh = getattr(page, "refresh", None)
            if callable(refresh):
                refresh()

    def _on_unmap(self, _event: object | None = None) -> None:
        if self._closing or not self._settings.minimize_to_tray or not self._tray.running:
            return
        self.after(120, self._hide_if_iconic)

    def _hide_if_iconic(self) -> None:
        if self._closing:
            return
        try:
            if self.state() == "iconic":
                self.withdraw()
                if self._settings.notifications_enabled:
                    self._tray.notify(APP_NAME, "SurNet Guardian is still running in the system tray.")
        except Exception:
            return

    def _show_from_tray(self) -> None:
        if self._closing:
            return
        self.deiconify()
        self.state("normal")
        self.lift()
        self.focus_force()

    def _exit_application(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._monitor.stop(wait=False)
        self._tray.stop()
        self.destroy()
