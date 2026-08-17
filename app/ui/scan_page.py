from __future__ import annotations

import asyncio
import threading
from queue import Empty, Queue
from tkinter import messagebox

import customtkinter as ctk

from app.core.config import COMMON_PORTS
from app.domain.models import RiskLevel, ScanResult
from app.network.ports import parse_ports
from app.network.scanner import AsyncTcpScanner, ScanCancelled
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class ScanPage(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        scanner: AsyncTcpScanner,
        history: HistoryService,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._scanner = scanner
        self._history = history
        self._queue: Queue[tuple[str, object]] = Queue()
        self._running = False
        self._cancel_event: threading.Event | None = None
        self._build()
        self.after(100, self._drain_queue)

    def _build(self) -> None:
        ctk.CTkLabel(
            self,
            text="Network Assessment",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=24, pady=(24, 6))
        ctk.CTkLabel(
            self,
            text="Auditable TCP connect assessment with service fingerprinting, TLS metadata and exposure scoring.",
            font=(self._font, 10),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=24, pady=(0, 14))

        controls = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        controls.pack(fill="x", padx=24, pady=(0, 12))

        self.target_entry = ctk.CTkEntry(
            controls,
            width=270,
            height=40,
            placeholder_text="192.168.1.0/24 or single IP",
            font=(self._font, 11),
        )
        self.target_entry.grid(row=0, column=0, padx=14, pady=14, sticky="ew")

        common = ",".join(str(port) for port in COMMON_PORTS)
        self.ports_entry = ctk.CTkEntry(
            controls,
            width=420,
            height=40,
            placeholder_text="80,443,8000-8100",
            font=(self._font, 11),
        )
        self.ports_entry.insert(0, common)
        self.ports_entry.grid(row=0, column=1, padx=8, pady=14, sticky="ew")

        self.scan_button = ctk.CTkButton(
            controls,
            text="Start Assessment",
            height=40,
            command=self._start_scan,
            fg_color=UiTheme.ACCENT,
            hover_color=UiTheme.ACCENT_HOVER,
            font=(self._font, 11, "bold"),
        )
        self.scan_button.grid(row=0, column=2, padx=(14, 6), pady=14)
        self.cancel_button = ctk.CTkButton(
            controls,
            text="Cancel",
            width=92,
            height=40,
            state="disabled",
            command=self._cancel_scan,
            fg_color=UiTheme.DANGER,
            hover_color=UiTheme.CRITICAL,
            font=(self._font, 11, "bold"),
        )
        self.cancel_button.grid(row=0, column=3, padx=(6, 14), pady=14)
        controls.grid_columnconfigure(0, weight=1)
        controls.grid_columnconfigure(1, weight=2)

        options = ctk.CTkFrame(self, fg_color="transparent")
        options.pack(fill="x", padx=24, pady=(0, 8))
        self.fingerprint_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            options,
            text="Service fingerprint + TLS audit",
            variable=self.fingerprint_var,
            font=(self._font, 10),
        ).pack(side="left")
        ctk.CTkLabel(
            options,
            text="Red = high/critical exposure finding; it is not an automatic malware verdict.",
            font=(self._font, 9),
            text_color=UiTheme.MUTED,
        ).pack(side="right")

        self.progress = ctk.CTkProgressBar(self, progress_color=UiTheme.ACCENT)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=24, pady=(0, 8))
        self.status = ctk.CTkLabel(
            self,
            text="Ready",
            font=(self._font, 10),
            text_color=UiTheme.MUTED,
        )
        self.status.pack(anchor="w", padx=24, pady=(0, 10))

        table_frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        table_frame.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        self.tree = create_tree(
            table_frame,
            columns=(
                "risk",
                "score",
                "ip",
                "hostname",
                "port",
                "service",
                "product",
                "version",
                "tls",
                "latency",
            ),
            headings=(
                "Risk",
                "Score",
                "IP",
                "Hostname",
                "Port",
                "Service",
                "Product",
                "Version",
                "TLS",
                "Latency ms",
            ),
            font_family=self._font,
        )
        self.tree.column("risk", width=90)
        self.tree.column("score", width=70)
        self.tree.column("product", width=160)
        self.tree.column("version", width=110)
        self.tree.tag_configure("critical", foreground=UiTheme.CRITICAL)
        self.tree.tag_configure("high", foreground=UiTheme.DANGER)
        self.tree.tag_configure("medium", foreground=UiTheme.WARNING)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def _start_scan(self) -> None:
        if self._running:
            return
        try:
            target = self.target_entry.get().strip()
            ports = parse_ports(self.ports_entry.get())
            if not target:
                raise ValueError("Target is required")
        except ValueError as exc:
            messagebox.showerror("Invalid scan", str(exc))
            return

        self._running = True
        self._cancel_event = threading.Event()
        self.scan_button.configure(state="disabled", text="Assessing...")
        self.cancel_button.configure(state="normal")
        self.progress.set(0)
        self.status.configure(text="Preparing assessment...")
        for item in self.tree.get_children():
            self.tree.delete(item)

        thread = threading.Thread(
            target=self._worker,
            args=(target, ports, self.fingerprint_var.get()),
            daemon=True,
            name="network-assessment-worker",
        )
        thread.start()

    def _worker(self, target: str, ports: tuple[int, ...], fingerprint_services: bool) -> None:
        def progress(done: int, total: int) -> None:
            self._queue.put(("progress", (done, total)))

        try:
            result = asyncio.run(
                self._scanner.scan(
                    target,
                    ports,
                    progress=progress,
                    cancel_event=self._cancel_event,
                    fingerprint_services=fingerprint_services,
                )
            )
            scan_id = self._history.save_scan(result)
            self._queue.put(("result", (result, scan_id)))
        except ScanCancelled:
            self._queue.put(("cancelled", None))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "progress":
                    done, total = payload  # type: ignore[misc]
                    fraction = done / total if total else 0
                    self.progress.set(fraction)
                    self.status.configure(text=f"Checked {done:,} / {total:,} sockets")
                elif event == "result":
                    result, scan_id = payload  # type: ignore[misc]
                    self._render_result(result, scan_id)
                elif event == "cancelled":
                    self.status.configure(text="Assessment cancelled")
                    self._finish()
                elif event == "error":
                    self._finish()
                    messagebox.showerror("Assessment failed", str(payload))
        except Empty:
            pass
        finally:
            self.after(100, self._drain_queue)

    def _render_result(self, result: ScanResult, scan_id: int) -> None:
        high_findings = 0
        for host in result.hosts:
            for port in host.ports:
                fingerprint = port.fingerprint
                if port.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
                    high_findings += 1
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        port.risk_level.value.upper(),
                        port.risk_score,
                        host.ip,
                        host.hostname or "—",
                        port.port,
                        port.service,
                        fingerprint.product or "—",
                        fingerprint.version or "—",
                        fingerprint.tls_version or "—",
                        port.latency_ms if port.latency_ms is not None else "—",
                    ),
                    tags=(port.risk_level.value,),
                )
        open_ports = sum(len(host.ports) for host in result.hosts)
        self.status.configure(
            text=(
                f"Assessment #{scan_id} complete — {len(result.hosts)} hosts, "
                f"{open_ports} open ports, {high_findings} high/critical exposures"
            )
        )
        self.progress.set(1)
        self._finish()

    def _cancel_scan(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self.status.configure(text="Cancelling assessment...")

    def _finish(self) -> None:
        self._running = False
        self._cancel_event = None
        self.scan_button.configure(state="normal", text="Start Assessment")
        self.cancel_button.configure(state="disabled")
