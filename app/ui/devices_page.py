from __future__ import annotations

import threading
from pathlib import Path
from queue import Empty, Queue
from tkinter import filedialog, messagebox

import customtkinter as ctk

from app.domain.models import DeviceRecord, DeviceTrust, PingResult
from app.network.ping import PingService
from app.services.exporter import ExportService
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.lifecycle import LifecycleFrame
from app.ui.theme import UiTheme


class DevicesPage(LifecycleFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        history: HistoryService,
        ping_service: PingService,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._ping = ping_service
        self._exporter = ExportService()
        self._rows: dict[str, DeviceRecord] = {}
        self._queue: Queue[tuple[str, object]] = Queue()
        self._build()
        self.after(100, self._drain_queue)

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 12))
        ctk.CTkLabel(
            header,
            text="Device Inventory",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left")
        ctk.CTkButton(
            header,
            text="Export JSON",
            width=105,
            command=lambda: self._export("json"),
            font=(self._font, 10, "bold"),
        ).pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            header,
            text="Export CSV",
            width=105,
            command=lambda: self._export("csv"),
            font=(self._font, 10, "bold"),
        ).pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            header,
            text="Refresh",
            width=90,
            command=self.refresh,
            font=(self._font, 10, "bold"),
        ).pack(side="right")
        ctk.CTkLabel(
            self,
            text=(
                "Trust status is an inventory classification. Marking a remote device Blocked does not "
                "automatically quarantine it from the network."
            ),
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=24, pady=(0, 10))

        filters = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        filters.pack(fill="x", padx=24, pady=(0, 12))
        self.search_entry = ctk.CTkEntry(
            filters,
            height=38,
            placeholder_text="Search IP, hostname, MAC, vendor or custom name",
            font=(self._font, 10),
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(14, 8), pady=12)
        self.search_entry.bind("<Return>", lambda _event: self.refresh())
        self.filter_menu = ctk.CTkOptionMenu(
            filters,
            values=["All", "Online", "Offline", "Trusted", "Unknown", "Blocked"],
            width=125,
            command=lambda _value: self.refresh(),
            font=(self._font, 10),
        )
        self.filter_menu.pack(side="left", padx=8, pady=12)
        ctk.CTkButton(
            filters,
            text="Search",
            width=90,
            command=self.refresh,
            font=(self._font, 10, "bold"),
        ).pack(side="left", padx=(8, 14), pady=12)

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.tree = create_tree(
            frame,
            columns=("status", "trust", "name", "ip", "hostname", "mac", "vendor", "latency", "last_seen"),
            headings=("Status", "Trust", "Name", "IP", "Hostname", "MAC", "Vendor", "Latency ms", "Last Seen"),
            font_family=self._font,
        )
        self.tree.column("status", width=80)
        self.tree.column("trust", width=90)
        self.tree.column("name", width=160)
        self.tree.column("ip", width=120)
        self.tree.column("hostname", width=150)
        self.tree.column("mac", width=145)
        self.tree.column("vendor", width=200)
        self.tree.column("latency", width=90)
        self.tree.column("last_seen", width=155)
        self.tree.tag_configure("online", foreground=UiTheme.SUCCESS)
        self.tree.tag_configure("offline", foreground=UiTheme.MUTED)
        self.tree.tag_configure("blocked", foreground=UiTheme.DANGER)
        self.tree.tag_configure("unknown", foreground=UiTheme.WARNING)
        self.tree.bind("<<TreeviewSelect>>", self._selected_changed)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        detail = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        detail.pack(fill="x", padx=24, pady=(0, 24))
        detail.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(
            detail,
            text="Selected device",
            font=(self._font, 11, "bold"),
            text_color=UiTheme.TEXT,
        ).grid(row=0, column=0, padx=14, pady=(12, 4), sticky="w")
        self.device_meta = ctk.CTkLabel(
            detail,
            text="Select a device to edit trust, name and notes.",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
            anchor="w",
        )
        self.device_meta.grid(row=0, column=1, columnspan=4, padx=8, pady=(12, 4), sticky="ew")

        self.name_entry = ctk.CTkEntry(detail, width=190, placeholder_text="Custom name", font=(self._font, 10))
        self.name_entry.grid(row=1, column=0, padx=(14, 6), pady=8)
        self.trust_menu = ctk.CTkOptionMenu(
            detail,
            values=["unknown", "trusted", "blocked"],
            width=125,
            font=(self._font, 10),
        )
        self.trust_menu.grid(row=1, column=1, padx=6, pady=8)
        self.notes_entry = ctk.CTkEntry(
            detail,
            placeholder_text="Notes",
            font=(self._font, 10),
        )
        self.notes_entry.grid(row=1, column=2, columnspan=2, padx=6, pady=8, sticky="ew")
        ctk.CTkButton(
            detail,
            text="Save Device",
            width=110,
            command=self._save_selected,
            font=(self._font, 10, "bold"),
        ).grid(row=1, column=4, padx=6, pady=8)
        ctk.CTkButton(
            detail,
            text="Ping Test",
            width=100,
            command=self._ping_selected,
            font=(self._font, 10, "bold"),
        ).grid(row=1, column=5, padx=(6, 14), pady=8)
        self.health_label = ctk.CTkLabel(
            detail,
            text="",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        )
        self.health_label.grid(row=2, column=0, columnspan=6, padx=14, pady=(0, 12), sticky="w")

    def refresh(self) -> None:
        selected_id = self._selected_device_id()
        filter_value = self.filter_menu.get() if hasattr(self, "filter_menu") else "All"
        trust: DeviceTrust | None = None
        online: bool | None = None
        if filter_value == "Online":
            online = True
        elif filter_value == "Offline":
            online = False
        elif filter_value in {"Trusted", "Unknown", "Blocked"}:
            trust = DeviceTrust(filter_value.lower())
        devices = self._history.list_devices(
            search=self.search_entry.get() if hasattr(self, "search_entry") else "",
            trust=trust,
            online=online,
        )
        self._rows.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for device in devices:
            iid = f"device-{device.id}"
            self._rows[iid] = device
            tag = "blocked" if device.trust_status == DeviceTrust.BLOCKED else (
                "unknown" if device.trust_status == DeviceTrust.UNKNOWN else (
                    "online" if device.is_online else "offline"
                )
            )
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "ONLINE" if device.is_online else "OFFLINE",
                    device.trust_status.value.upper(),
                    device.display_name,
                    device.ip,
                    device.hostname or "—",
                    device.mac_address or "—",
                    device.vendor or "—",
                    device.last_latency_ms if device.last_latency_ms is not None else "—",
                    self._format_time(device.last_seen_at),
                ),
                tags=(tag,),
            )
        if selected_id is not None:
            iid = f"device-{selected_id}"
            if iid in self._rows:
                self.tree.selection_set(iid)
                self.tree.focus(iid)
                self._populate_detail(self._rows[iid])

    def _selected_device_id(self) -> int | None:
        selection = self.tree.selection() if hasattr(self, "tree") else ()
        if not selection:
            return None
        device = self._rows.get(selection[0])
        return device.id if device else None

    def _selected_changed(self, _event: object | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        device = self._rows.get(selection[0])
        if device:
            self._populate_detail(device)

    def _populate_detail(self, device: DeviceRecord) -> None:
        self.name_entry.delete(0, "end")
        if device.custom_name:
            self.name_entry.insert(0, device.custom_name)
        self.trust_menu.set(device.trust_status.value)
        self.notes_entry.delete(0, "end")
        if device.notes:
            self.notes_entry.insert(0, device.notes)
        self.device_meta.configure(
            text=(
                f"{device.ip}  |  MAC {device.mac_address or '—'}  |  Vendor {device.vendor or '—'}  |  "
                f"First seen {self._format_time(device.first_seen_at)}"
            )
        )
        self.health_label.configure(text="")

    def _save_selected(self) -> None:
        device_id = self._selected_device_id()
        if device_id is None:
            messagebox.showinfo("Select device", "Select a device first.")
            return
        try:
            trust = DeviceTrust(self.trust_menu.get())
            self._history.update_device(
                device_id,
                custom_name=self.name_entry.get(),
                trust_status=trust,
                notes=self.notes_entry.get(),
            )
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.refresh()

    def _ping_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Select device", "Select a device first.")
            return
        device = self._rows[selection[0]]
        self.health_label.configure(text=f"Pinging {device.ip}...")

        def worker() -> None:
            try:
                self._queue.put(("ping", self._ping.ping(device.ip)))
            except Exception as exc:
                self._queue.put(("error", exc))

        threading.Thread(target=worker, daemon=True, name="device-ping-worker").start()

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "ping":
                    result = payload
                    assert isinstance(result, PingResult)
                    average = f"{result.average_latency_ms:.1f} ms" if result.average_latency_ms is not None else "—"
                    self.health_label.configure(
                        text=(
                            f"Ping: {result.received}/{result.transmitted} replies  |  "
                            f"Packet loss {result.packet_loss_percent:.1f}%  |  Average {average}"
                        )
                    )
                elif event == "error":
                    self.health_label.configure(text=f"Ping failed: {payload}")
        except Empty:
            pass
        finally:
            self.after(100, self._drain_queue)

    def _export(self, kind: str) -> None:
        devices = list(self._rows.values())
        if not devices:
            messagebox.showinfo("Nothing to export", "No devices are visible in the current filter.")
            return
        extension = ".json" if kind == "json" else ".csv"
        path = filedialog.asksaveasfilename(
            title="Export device inventory",
            defaultextension=extension,
            filetypes=[(kind.upper(), f"*{extension}")],
            initialfile=f"surnet-devices{extension}",
        )
        if not path:
            return
        if kind == "json":
            self._exporter.export_devices_json(devices, Path(path))
        else:
            self._exporter.export_devices_csv(devices, Path(path))
        messagebox.showinfo("Export complete", f"Saved to:\n{path}")

    @staticmethod
    def _format_time(value: object) -> str:
        try:
            return value.strftime("%Y-%m-%d %H:%M:%S")  # type: ignore[attr-defined]
        except Exception:
            return str(value)
