from __future__ import annotations

from collections.abc import Callable
from tkinter import messagebox

import customtkinter as ctk

from app.network.discovery import HostDiscoveryService
from app.network.targets import validate_private_ipv4_target
from app.services.settings import AppSettings, SettingsService
from app.services.startup import StartupService
from app.ui.theme import UiTheme


class SettingsPage(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        settings_service: SettingsService,
        startup_service: StartupService,
        discovery: HostDiscoveryService,
        on_saved: Callable[[AppSettings], None],
        on_monitor_now: Callable[[str], None],
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._service = settings_service
        self._startup = startup_service
        self._discovery = discovery
        self._on_saved = on_saved
        self._on_monitor_now = on_monitor_now
        self._build()
        self.refresh()

    def _build(self) -> None:
        ctk.CTkLabel(self, text="Settings", font=(self._font, 24, "bold"), text_color=UiTheme.TEXT).pack(anchor="w", padx=24, pady=(24, 6))
        ctk.CTkLabel(
            self,
            text="Configure local network monitoring, notifications, tray behavior and appearance.",
            font=(self._font, 10),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=24, pady=(0, 14))

        panel = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        panel.pack(fill="x", padx=24, pady=(0, 12))
        panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(panel, text="Appearance", font=(self._font, 12, "bold"), text_color=UiTheme.TEXT).grid(row=0, column=0, columnspan=2, padx=16, pady=(16, 8), sticky="w")
        ctk.CTkLabel(panel, text="Theme", font=(self._font, 10)).grid(row=1, column=0, padx=16, pady=8, sticky="w")
        self.theme_menu = ctk.CTkOptionMenu(panel, values=["dark", "light"], width=140, font=(self._font, 10))
        self.theme_menu.grid(row=1, column=1, padx=16, pady=8, sticky="w")

        ctk.CTkLabel(panel, text="Network Monitor", font=(self._font, 12, "bold"), text_color=UiTheme.TEXT).grid(row=2, column=0, columnspan=2, padx=16, pady=(18, 8), sticky="w")
        self.auto_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(panel, text="Enable automatic local-network discovery", variable=self.auto_var, font=(self._font, 10)).grid(row=3, column=0, columnspan=2, padx=16, pady=8, sticky="w")
        ctk.CTkLabel(panel, text="Target", font=(self._font, 10)).grid(row=4, column=0, padx=16, pady=8, sticky="w")
        self.target_entry = ctk.CTkEntry(panel, placeholder_text="192.168.1.0/24", font=(self._font, 10))
        self.target_entry.grid(row=4, column=1, padx=16, pady=8, sticky="ew")
        ctk.CTkLabel(panel, text="Interval (seconds)", font=(self._font, 10)).grid(row=5, column=0, padx=16, pady=8, sticky="w")
        self.interval_entry = ctk.CTkEntry(panel, width=140, font=(self._font, 10))
        self.interval_entry.grid(row=5, column=1, padx=16, pady=8, sticky="w")
        ctk.CTkLabel(
            panel,
            text="Automatic monitoring is restricted to private/local address space and a maximum of 4096 hosts.",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).grid(row=6, column=1, padx=16, pady=(0, 8), sticky="w")

        ctk.CTkLabel(panel, text="Desktop", font=(self._font, 12, "bold"), text_color=UiTheme.TEXT).grid(row=7, column=0, columnspan=2, padx=16, pady=(18, 8), sticky="w")
        self.notifications_var = ctk.BooleanVar(value=True)
        self.tray_var = ctk.BooleanVar(value=True)
        self.startup_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(panel, text="Show tray notifications for new monitor alerts", variable=self.notifications_var, font=(self._font, 10)).grid(row=8, column=0, columnspan=2, padx=16, pady=6, sticky="w")
        ctk.CTkCheckBox(panel, text="Minimize to system tray", variable=self.tray_var, font=(self._font, 10)).grid(row=9, column=0, columnspan=2, padx=16, pady=6, sticky="w")
        ctk.CTkCheckBox(panel, text="Start SurNet Guardian with Windows", variable=self.startup_var, font=(self._font, 10)).grid(row=10, column=0, columnspan=2, padx=16, pady=(6, 16), sticky="w")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", padx=24, pady=(0, 24))
        ctk.CTkButton(
            actions,
            text="Save Settings",
            width=130,
            command=self._save,
            font=(self._font, 10, "bold"),
        ).pack(side="right")
        ctk.CTkButton(
            actions,
            text="Scan Now",
            width=110,
            command=self._scan_now,
            fg_color=UiTheme.PANEL_ALT,
            hover_color=UiTheme.BORDER,
            font=(self._font, 10, "bold"),
        ).pack(side="right", padx=(0, 8))
        self.status = ctk.CTkLabel(actions, text="", font=(self._font, 9), text_color=UiTheme.MUTED)
        self.status.pack(side="left")

    def refresh(self) -> None:
        settings = self._service.load()
        self.theme_menu.set(settings.theme)
        self.auto_var.set(settings.auto_monitor)
        self.target_entry.delete(0, "end")
        target = settings.discovery_target
        if not target:
            networks = self._discovery.local_ipv4_networks()
            target = networks[0] if networks else ""
        if target:
            self.target_entry.insert(0, target)
        self.interval_entry.delete(0, "end")
        self.interval_entry.insert(0, str(settings.monitor_interval_seconds))
        self.notifications_var.set(settings.notifications_enabled)
        self.tray_var.set(settings.minimize_to_tray)
        self.startup_var.set(settings.start_with_windows)

    def _save(self) -> None:
        try:
            interval = int(self.interval_entry.get().strip())
            if not 15 <= interval <= 86_400:
                raise ValueError("Monitor interval must be between 15 and 86400 seconds.")
            target = self.target_entry.get().strip()
            if self.auto_var.get():
                self._validate_private_target(target)
            settings = AppSettings(
                theme=self.theme_menu.get(),
                auto_monitor=self.auto_var.get(),
                discovery_target=target,
                monitor_interval_seconds=interval,
                notifications_enabled=self.notifications_var.get(),
                minimize_to_tray=self.tray_var.get(),
                start_with_windows=self.startup_var.get(),
            )
            success, startup_message = self._startup.set_enabled(settings.start_with_windows)
            if not success:
                # Keep the persisted toggle aligned with the actual registry state.
                requested_startup = settings.start_with_windows
                settings.start_with_windows = self._startup.is_enabled()
                if requested_startup:
                    messagebox.showwarning("Windows startup", startup_message)
            self._service.save(settings)
            self.status.configure(text="Settings saved.")
            self._on_saved(settings)
        except Exception as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def set_monitor_status(self, text: str) -> None:
        self.status.configure(text=text)

    def _scan_now(self) -> None:
        target = self.target_entry.get().strip()
        try:
            self._validate_private_target(target)
        except ValueError as exc:
            messagebox.showerror("Invalid monitoring target", str(exc))
            return
        self.status.configure(text="Monitoring scan requested...")
        self._on_monitor_now(target)

    @staticmethod
    def _validate_private_target(target: str) -> None:
        validate_private_ipv4_target(target, max_hosts=4096)
