from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from app.domain.models import AlertRecord
from app.services.exporter import ExportService
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class AlertsPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, *, font_family: str, history: HistoryService) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._exporter = ExportService()
        self._rows: dict[str, AlertRecord] = {}
        self._build()

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 12))
        ctk.CTkLabel(
            header,
            text="Alerts",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left")
        ctk.CTkButton(header, text="Export JSON", width=100, command=lambda: self._export("json"), font=(self._font, 10, "bold")).pack(side="right", padx=(6, 0))
        ctk.CTkButton(header, text="Export CSV", width=100, command=lambda: self._export("csv"), font=(self._font, 10, "bold")).pack(side="right", padx=(6, 0))
        ctk.CTkButton(header, text="Refresh", width=90, command=self.refresh, font=(self._font, 10, "bold")).pack(side="right")

        controls = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        controls.pack(fill="x", padx=24, pady=(0, 12))
        self.show_all = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            controls,
            text="Show acknowledged alerts",
            variable=self.show_all,
            command=self.refresh,
            font=(self._font, 10),
        ).pack(side="left", padx=14, pady=12)
        ctk.CTkButton(controls, text="Acknowledge selected", width=150, command=self._ack_selected, font=(self._font, 10, "bold")).pack(side="right", padx=(6, 14), pady=12)
        ctk.CTkButton(controls, text="Acknowledge all", width=125, command=self._ack_all, font=(self._font, 10, "bold")).pack(side="right", padx=6, pady=12)
        ctk.CTkButton(controls, text="Clear acknowledged", width=135, command=self._clear_ack, fg_color=UiTheme.DANGER, hover_color=UiTheme.CRITICAL, font=(self._font, 10, "bold")).pack(side="right", padx=6, pady=12)

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.tree = create_tree(
            frame,
            columns=("severity", "time", "category", "device", "ip", "title", "status"),
            headings=("Severity", "Time", "Category", "Device", "IP", "Title", "Status"),
            font_family=self._font,
        )
        self.tree.column("severity", width=90)
        self.tree.column("time", width=155)
        self.tree.column("category", width=155)
        self.tree.column("device", width=170)
        self.tree.column("ip", width=120)
        self.tree.column("title", width=300)
        self.tree.column("status", width=105)
        self.tree.tag_configure("high", foreground=UiTheme.DANGER)
        self.tree.tag_configure("critical", foreground=UiTheme.CRITICAL)
        self.tree.tag_configure("medium", foreground=UiTheme.WARNING)
        self.tree.tag_configure("ack", foreground=UiTheme.MUTED)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        detail = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        detail.pack(fill="x", padx=24, pady=(0, 24))
        self.detail_text = ctk.CTkTextbox(detail, height=100, fg_color=UiTheme.PANEL_ALT, font=(self._font, 10))
        self.detail_text.pack(fill="x", padx=12, pady=12)
        self._set_detail("Select an alert to view details.")

    def refresh(self) -> None:
        alerts = self._history.list_alerts(include_acknowledged=self.show_all.get() if hasattr(self, "show_all") else False)
        self._rows.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for alert in alerts:
            iid = f"alert-{alert.id}"
            self._rows[iid] = alert
            tag = "ack" if alert.acknowledged else alert.severity.value
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    alert.severity.value.upper(),
                    alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    alert.category,
                    alert.device_name or "—",
                    alert.ip or "—",
                    alert.title,
                    "ACKNOWLEDGED" if alert.acknowledged else "OPEN",
                ),
                tags=(tag,),
            )

    def _selected(self) -> AlertRecord | None:
        selection = self.tree.selection()
        return self._rows.get(selection[0]) if selection else None

    def _show_detail(self, _event: object | None = None) -> None:
        alert = self._selected()
        if alert:
            self._set_detail(
                f"{alert.title}\n\n{alert.message}\n\nDevice: {alert.device_name or '—'} | IP: {alert.ip or '—'}"
            )

    def _ack_selected(self) -> None:
        alert = self._selected()
        if alert is None:
            messagebox.showinfo("Select alert", "Select an alert first.")
            return
        self._history.acknowledge_alert(alert.id)
        self.refresh()

    def _ack_all(self) -> None:
        count = self._history.acknowledge_all_alerts()
        self.refresh()
        messagebox.showinfo("Alerts", f"Acknowledged {count} alert(s).")

    def _clear_ack(self) -> None:
        if not messagebox.askyesno("Clear acknowledged", "Delete all acknowledged alerts? Event history is not deleted."):
            return
        count = self._history.clear_acknowledged_alerts()
        self.refresh()
        messagebox.showinfo("Alerts", f"Deleted {count} acknowledged alert(s).")

    def _export(self, kind: str) -> None:
        alerts = list(self._rows.values())
        if not alerts:
            messagebox.showinfo("Nothing to export", "No alerts are visible.")
            return
        extension = ".json" if kind == "json" else ".csv"
        path = filedialog.asksaveasfilename(defaultextension=extension, filetypes=[(kind.upper(), f"*{extension}")], initialfile=f"surnet-alerts{extension}")
        if not path:
            return
        if kind == "json":
            self._exporter.export_alerts_json(alerts, Path(path))
        else:
            self._exporter.export_alerts_csv(alerts, Path(path))
        messagebox.showinfo("Export complete", f"Saved to:\n{path}")

    def _set_detail(self, text: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")
