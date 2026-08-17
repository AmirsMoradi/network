from __future__ import annotations

from tkinter import messagebox

import customtkinter as ctk

from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class ChangesPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, *, font_family: str, history: HistoryService) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._build()

    def _build(self) -> None:
        ctk.CTkLabel(
            self,
            text="Network Changes",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=24, pady=(24, 14))

        controls = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        controls.pack(fill="x", padx=24, pady=(0, 14))
        ctk.CTkLabel(controls, text="Older", font=(self._font, 10)).pack(side="left", padx=(14, 6), pady=14)
        self.older = ctk.CTkComboBox(controls, values=["No scans"], width=210)
        self.older.pack(side="left", padx=6, pady=14)
        ctk.CTkLabel(controls, text="Newer", font=(self._font, 10)).pack(side="left", padx=(14, 6), pady=14)
        self.newer = ctk.CTkComboBox(controls, values=["No scans"], width=210)
        self.newer.pack(side="left", padx=6, pady=14)
        ctk.CTkButton(
            controls,
            text="Compare",
            command=self._compare,
            font=(self._font, 10, "bold"),
        ).pack(side="left", padx=14, pady=14)

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        self.tree = create_tree(
            frame,
            columns=("change", "value"),
            headings=("Change", "Evidence"),
            font_family=self._font,
        )
        self.tree.column("change", width=180)
        self.tree.column("value", width=760)
        self.tree.tag_configure("new", foreground=UiTheme.WARNING)
        self.tree.tag_configure("closed", foreground=UiTheme.SUCCESS)
        self.tree.tag_configure("removed", foreground=UiTheme.MUTED)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self) -> None:
        scans = self._history.list_recent(100)
        values = [f"#{scan.id}  {scan.target}" for scan in scans]
        display = values or ["No scans"]
        self.older.configure(values=display)
        self.newer.configure(values=display)
        if values:
            self.newer.set(values[0])
            self.older.set(values[1] if len(values) > 1 else values[0])

    def _compare(self) -> None:
        try:
            older_id = int(self.older.get().split()[0][1:])
            newer_id = int(self.newer.get().split()[0][1:])
            if older_id == newer_id:
                raise ValueError("Choose two different scans")
            diff = self._history.compare_scans(older_id, newer_id)
        except (ValueError, IndexError) as exc:
            messagebox.showerror("Comparison failed", str(exc))
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        for value in diff.new_hosts:
            self.tree.insert("", "end", values=("New host", value), tags=("new",))
        for value in diff.removed_hosts:
            self.tree.insert("", "end", values=("Removed host", value), tags=("removed",))
        for value in diff.new_ports:
            self.tree.insert("", "end", values=("New open port", value), tags=("new",))
        for value in diff.closed_ports:
            self.tree.insert("", "end", values=("Closed port", value), tags=("closed",))
        for value in diff.changed_services:
            self.tree.insert("", "end", values=("Service changed", value), tags=("new",))
