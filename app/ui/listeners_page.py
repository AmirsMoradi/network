from __future__ import annotations

import threading
from queue import Empty, Queue
from tkinter import messagebox, ttk

import customtkinter as ctk

from app.domain.models import ListenerRecord, RiskLevel
from app.network.local_listeners import LocalListenerInspector
from app.security.windows_firewall import WindowsFirewallService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class ListenersPage(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        inspector: LocalListenerInspector,
        firewall: WindowsFirewallService,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._inspector = inspector
        self._firewall = firewall
        self._queue: Queue[tuple[str, object]] = Queue()
        self._records: dict[str, ListenerRecord] = {}
        self._build()
        self.after(100, self._drain_queue)
        self.refresh()

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 14))
        ctk.CTkLabel(
            header,
            text="Local Port Guard",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left")
        ctk.CTkButton(
            header,
            text="Refresh",
            width=110,
            command=self.refresh,
            font=(self._font, 10, "bold"),
        ).pack(side="right")

        note = ctk.CTkLabel(
            self,
            text=(
                "Red rows indicate high heuristic risk, not confirmed malware. "
                "Firewall Block prevents inbound traffic but does not stop the owning process."
            ),
            font=(self._font, 10),
            text_color=UiTheme.MUTED,
        )
        note.pack(anchor="w", padx=24, pady=(0, 10))

        firewall_panel = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        firewall_panel.pack(fill="x", padx=24, pady=(0, 12))
        ctk.CTkLabel(
            firewall_panel,
            text="Manual Firewall Rule",
            font=(self._font, 11, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left", padx=(14, 10), pady=12)
        self.manual_port = ctk.CTkEntry(
            firewall_panel,
            width=100,
            height=36,
            placeholder_text="Port",
            font=(self._font, 10),
        )
        self.manual_port.pack(side="left", padx=6, pady=12)
        self.protocol = ctk.CTkOptionMenu(
            firewall_panel,
            values=["TCP", "UDP"],
            width=90,
            height=36,
            font=(self._font, 10),
        )
        self.protocol.pack(side="left", padx=6, pady=12)
        ctk.CTkButton(
            firewall_panel,
            text="Allow",
            width=92,
            height=36,
            command=lambda: self._manual_firewall_action(allow=True),
            fg_color=UiTheme.SUCCESS,
            font=(self._font, 10, "bold"),
        ).pack(side="left", padx=6, pady=12)
        ctk.CTkButton(
            firewall_panel,
            text="Block",
            width=92,
            height=36,
            command=lambda: self._manual_firewall_action(allow=False),
            fg_color=UiTheme.DANGER,
            hover_color=UiTheme.CRITICAL,
            font=(self._font, 10, "bold"),
        ).pack(side="left", padx=6, pady=12)
        ctk.CTkLabel(
            firewall_panel,
            text="Allow/Block controls inbound firewall access; it does not create or terminate a service.",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).pack(side="right", padx=14, pady=12)

        table_frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        table_frame.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.tree = create_tree(
            table_frame,
            columns=("risk", "bind", "port", "pid", "process", "signature", "path"),
            headings=("Risk", "Bind", "Port", "PID", "Process", "Signature", "Executable"),
            font_family=self._font,
        )
        self.tree.column("risk", width=90)
        self.tree.column("bind", width=130)
        self.tree.column("port", width=75)
        self.tree.column("pid", width=75)
        self.tree.column("process", width=145)
        self.tree.column("signature", width=110)
        self.tree.column("path", width=420)
        self.tree.tag_configure("low", foreground=UiTheme.SUCCESS)
        self.tree.tag_configure("medium", foreground=UiTheme.WARNING)
        self.tree.tag_configure("high", foreground=UiTheme.DANGER)
        self.tree.tag_configure("critical", foreground=UiTheme.CRITICAL)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree.bind("<<TreeviewSelect>>", self._show_details)

        action = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        action.pack(fill="x", padx=24, pady=(0, 24))
        self.details = ctk.CTkLabel(
            action,
            text="Select a listener to see its risk evidence.",
            justify="left",
            anchor="w",
            wraplength=760,
            font=(self._font, 10),
            text_color=UiTheme.TEXT,
        )
        self.details.pack(side="left", fill="x", expand=True, padx=14, pady=14)
        ctk.CTkButton(
            action,
            text="Allow Inbound",
            width=125,
            command=lambda: self._firewall_action(allow=True),
            fg_color=UiTheme.SUCCESS,
            font=(self._font, 10, "bold"),
        ).pack(side="right", padx=(6, 14), pady=14)
        ctk.CTkButton(
            action,
            text="Block Inbound",
            width=125,
            command=lambda: self._firewall_action(allow=False),
            fg_color=UiTheme.DANGER,
            hover_color=UiTheme.CRITICAL,
            font=(self._font, 10, "bold"),
        ).pack(side="right", padx=6, pady=14)

    def refresh(self) -> None:
        threading.Thread(target=self._load_worker, daemon=True).start()

    def _load_worker(self) -> None:
        try:
            self._queue.put(("records", self._inspector.list_listeners()))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "records":
                    self._render(payload)  # type: ignore[arg-type]
                elif event == "error":
                    messagebox.showerror("Listener audit failed", str(payload))
        except Empty:
            pass
        finally:
            self.after(100, self._drain_queue)

    def _render(self, records: list[ListenerRecord]) -> None:
        self._records.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for index, record in enumerate(records):
            iid = f"listener-{index}"
            self._records[iid] = record
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    f"{record.risk_level.value.upper()} {record.risk_score}",
                    record.local_ip,
                    record.port,
                    record.pid if record.pid is not None else "—",
                    record.process_name,
                    record.signature_status or "—",
                    record.executable or "—",
                ),
                tags=(record.risk_level.value,),
            )

    def _selected(self) -> ListenerRecord | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return self._records.get(selection[0])

    def _show_details(self, _event: ttk.TreeviewSelect) -> None:
        record = self._selected()
        if record is None:
            return
        reasons = "\n".join(f"• {reason}" for reason in record.risk_reasons)
        if not reasons:
            reasons = "No significant heuristic indicators were detected."
        self.details.configure(
            text=(
                f"{record.process_name} | TCP {record.local_ip}:{record.port} | "
                f"Risk {record.risk_score}/100\n{reasons}"
            )
        )

    def _manual_firewall_action(self, *, allow: bool) -> None:
        try:
            port = int(self.manual_port.get().strip())
            protocol = self.protocol.get().upper()
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be an integer from 1 to 65535")
            return

        verb = "allow" if allow else "block"
        if not messagebox.askyesno(
            "Confirm firewall change",
            f"Do you want to {verb} inbound {protocol} traffic on local port {port}?",
        ):
            return
        result = (
            self._firewall.allow_inbound(port, protocol)
            if allow
            else self._firewall.block_inbound(port, protocol)
        )
        if result.success:
            messagebox.showinfo("Firewall updated", result.message)
        else:
            messagebox.showerror("Firewall update failed", result.message)

    def _firewall_action(self, *, allow: bool) -> None:
        record = self._selected()
        if record is None:
            messagebox.showinfo("Select port", "Select a listener first")
            return
        verb = "allow" if allow else "block"
        if not messagebox.askyesno(
            "Confirm firewall change",
            f"Do you want to {verb} inbound TCP traffic on local port {record.port}?",
        ):
            return
        result = (
            self._firewall.allow_inbound(record.port)
            if allow
            else self._firewall.block_inbound(record.port)
        )
        if result.success:
            messagebox.showinfo("Firewall updated", result.message)
        else:
            messagebox.showerror("Firewall update failed", result.message)
