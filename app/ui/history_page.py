from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from app.services.exporter import ExportService
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class HistoryPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, *, font_family: str, history: HistoryService) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._exporter = ExportService()
        self._build()
        self.refresh()

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 14))
        ctk.CTkLabel(
            header,
            text="Scan History",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left")
        ctk.CTkButton(header, text="Export JSON", width=105, command=lambda: self._export_selected("json"), font=(self._font, 10, "bold")).pack(side="right", padx=(6, 0))
        ctk.CTkButton(header, text="Export CSV", width=105, command=lambda: self._export_selected("csv"), font=(self._font, 10, "bold")).pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            header,
            text="Refresh",
            width=90,
            command=self.refresh,
            font=(self._font, 10, "bold"),
        ).pack(side="right")

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        self.tree = create_tree(
            frame,
            columns=("id", "target", "date", "hosts", "ports", "risk"),
            headings=("ID", "Target", "Started", "Hosts", "Open Ports", "High / Critical"),
            font_family=self._font,
        )
        self.tree.column("id", width=70)
        self.tree.column("target", width=240)
        self.tree.column("date", width=210)
        self.tree.tag_configure("risk", foreground=UiTheme.DANGER)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for scan in self._history.list_recent():
            open_ports = sum(len(host.ports) for host in scan.hosts)
            risk_count = sum(
                1
                for host in scan.hosts
                for port in host.ports
                if (port.risk_level or "low") in {"high", "critical"}
            )
            self.tree.insert(
                "",
                "end",
                values=(
                    scan.id,
                    scan.target,
                    scan.started_at,
                    len(scan.hosts),
                    open_ports,
                    risk_count,
                ),
                tags=("risk",) if risk_count else (),
            )

    def _selected_scan_id(self) -> int | None:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        try:
            return int(values[0])
        except (IndexError, TypeError, ValueError):
            return None

    def _export_selected(self, kind: str) -> None:
        scan_id = self._selected_scan_id()
        if scan_id is None:
            messagebox.showinfo("Select scan", "Select a saved scan first.")
            return
        scan = self._history.get_scan(scan_id)
        if scan is None:
            messagebox.showerror("Scan not found", f"Scan #{scan_id} was not found.")
            return
        extension = ".json" if kind == "json" else ".csv"
        path = filedialog.asksaveasfilename(
            title=f"Export scan #{scan_id}",
            defaultextension=extension,
            filetypes=[(kind.upper(), f"*{extension}")],
            initialfile=f"surnet-scan-{scan_id}{extension}",
        )
        if not path:
            return
        if kind == "json":
            self._exporter.export_json(scan, Path(path))
        else:
            self._exporter.export_csv(scan, Path(path))
        messagebox.showinfo("Export complete", f"Saved to:\n{path}")
