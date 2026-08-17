from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from app.domain.models import EventRecord
from app.services.exporter import ExportService
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class EventsPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, *, font_family: str, history: HistoryService) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._exporter = ExportService()
        self._rows: dict[str, EventRecord] = {}
        self._build()

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 12))
        ctk.CTkLabel(header, text="Event Log", font=(self._font, 24, "bold"), text_color=UiTheme.TEXT).pack(side="left")
        ctk.CTkButton(header, text="Export JSON", width=100, command=lambda: self._export("json"), font=(self._font, 10, "bold")).pack(side="right", padx=(6, 0))
        ctk.CTkButton(header, text="Export CSV", width=100, command=lambda: self._export("csv"), font=(self._font, 10, "bold")).pack(side="right", padx=(6, 0))
        ctk.CTkButton(header, text="Refresh", width=90, command=self.refresh, font=(self._font, 10, "bold")).pack(side="right")

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.tree = create_tree(
            frame,
            columns=("time", "severity", "type", "device", "ip", "title"),
            headings=("Time", "Severity", "Type", "Device", "IP", "Title"),
            font_family=self._font,
        )
        self.tree.column("time", width=160)
        self.tree.column("severity", width=90)
        self.tree.column("type", width=170)
        self.tree.column("device", width=180)
        self.tree.column("ip", width=120)
        self.tree.column("title", width=340)
        self.tree.tag_configure("high", foreground=UiTheme.DANGER)
        self.tree.tag_configure("critical", foreground=UiTheme.CRITICAL)
        self.tree.tag_configure("medium", foreground=UiTheme.WARNING)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        detail = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        detail.pack(fill="x", padx=24, pady=(0, 24))
        self.detail = ctk.CTkLabel(detail, text="Select an event to view evidence.", wraplength=1050, justify="left", anchor="w", font=(self._font, 10), text_color=UiTheme.TEXT)
        self.detail.pack(fill="x", padx=14, pady=14)

    def refresh(self) -> None:
        events = self._history.list_events(1500)
        self._rows.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for event in events:
            iid = f"event-{event.id}"
            self._rows[iid] = event
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(event.created_at.strftime("%Y-%m-%d %H:%M:%S"), event.severity.value.upper(), event.event_type, event.device_name or "—", event.ip or "—", event.title),
                tags=(event.severity.value,),
            )

    def _show_detail(self, _event: object | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        event = self._rows.get(selection[0])
        if event:
            self.detail.configure(text=f"{event.title}\n{event.message}")

    def _export(self, kind: str) -> None:
        events = list(self._rows.values())
        if not events:
            messagebox.showinfo("Nothing to export", "No events are available.")
            return
        extension = ".json" if kind == "json" else ".csv"
        path = filedialog.asksaveasfilename(defaultextension=extension, filetypes=[(kind.upper(), f"*{extension}")], initialfile=f"surnet-events{extension}")
        if not path:
            return
        if kind == "json":
            self._exporter.export_events_json(events, Path(path))
        else:
            self._exporter.export_events_csv(events, Path(path))
        messagebox.showinfo("Export complete", f"Saved to:\n{path}")
