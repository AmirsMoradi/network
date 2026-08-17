from __future__ import annotations

import asyncio
import threading
from queue import Empty, Queue
from tkinter import messagebox

import customtkinter as ctk

from app.domain.models import DeviceObservation
from app.network.discovery import HostDiscoveryService
from app.network.vendor import MacVendorResolver
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.theme import UiTheme


class DiscoveryPage(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        discovery: HostDiscoveryService,
        vendor_resolver: MacVendorResolver,
        history: HistoryService,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._discovery = discovery
        self._vendor = vendor_resolver
        self._history = history
        self._queue: Queue[tuple[str, object]] = Queue()
        self._cancel_event: threading.Event | None = None
        self._running = False
        self._last_observations: list[DeviceObservation] = []
        self._build()
        self.after(100, self._drain_queue)

    def _build(self) -> None:
        ctk.CTkLabel(
            self,
            text="Asset Discovery",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(anchor="w", padx=24, pady=(24, 6))
        ctk.CTkLabel(
            self,
            text="Discover responsive hosts, enrich local devices with MAC/OUI vendor data, and keep a persistent inventory.",
            font=(self._font, 10),
            text_color=UiTheme.MUTED,
        ).pack(anchor="w", padx=24, pady=(0, 14))

        controls = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        controls.pack(fill="x", padx=24, pady=(0, 14))
        networks = self._discovery.local_ipv4_networks()
        self.target_entry = ctk.CTkEntry(
            controls,
            height=40,
            placeholder_text="192.168.1.0/24",
            font=(self._font, 11),
        )
        if networks:
            self.target_entry.insert(0, networks[0])
        self.target_entry.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        self.scan_button = ctk.CTkButton(
            controls,
            text="Discover",
            height=40,
            command=self._start,
            font=(self._font, 11, "bold"),
        )
        self.scan_button.grid(row=0, column=1, padx=6, pady=14)
        self.cancel_button = ctk.CTkButton(
            controls,
            text="Cancel",
            height=40,
            state="disabled",
            fg_color=UiTheme.DANGER,
            hover_color=UiTheme.CRITICAL,
            command=self._cancel,
            font=(self._font, 11, "bold"),
        )
        self.cancel_button.grid(row=0, column=2, padx=6, pady=14)
        ctk.CTkButton(
            controls,
            text="Update IEEE OUI",
            height=40,
            command=self._update_oui,
            font=(self._font, 10, "bold"),
        ).grid(row=0, column=3, padx=(6, 14), pady=14)
        controls.grid_columnconfigure(0, weight=1)

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

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        self.tree = create_tree(
            frame,
            columns=("ip", "hostname", "mac", "vendor", "methods", "latency"),
            headings=("IP", "Hostname", "MAC", "Vendor", "Discovery", "Latency ms"),
            font_family=self._font,
        )
        self.tree.column("vendor", width=230)
        self.tree.column("methods", width=180)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def _start(self) -> None:
        if self._running:
            return
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Invalid target", "Target is required")
            return
        self._running = True
        self._cancel_event = threading.Event()
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.status.configure(text="Discovering hosts...")
        self.progress.set(0)
        for item in self.tree.get_children():
            self.tree.delete(item)
        threading.Thread(target=self._worker, args=(target,), daemon=True).start()

    def _worker(self, target: str) -> None:
        def progress(done: int, total: int) -> None:
            self._queue.put(("progress", (done, total)))

        try:
            observations = asyncio.run(
                self._discovery.discover(
                    target,
                    progress=progress,
                    cancel_event=self._cancel_event,
                )
            )
            enriched = [
                DeviceObservation(
                    ip=item.ip,
                    hostname=item.hostname,
                    mac_address=item.mac_address,
                    vendor=self._vendor.resolve(item.mac_address),
                    methods=item.methods,
                    latency_ms=item.latency_ms,
                )
                for item in observations
            ]
            self._history.save_discovery(enriched)
            self._queue.put(("result", enriched))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _update_oui(self) -> None:
        self.status.configure(text="Updating IEEE OUI vendor cache...")

        def worker() -> None:
            try:
                changed = self._vendor.update_cache()
                self._queue.put(("oui", changed))
            except Exception as exc:
                self._queue.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "progress":
                    done, total = payload  # type: ignore[misc]
                    self.progress.set(done / total if total else 0)
                    self.status.configure(text=f"Probed {done:,} / {total:,} hosts")
                elif event == "result":
                    observations = payload  # type: ignore[assignment]
                    self._render(observations)
                    self._finish()
                elif event == "oui":
                    changed = bool(payload)
                    self.status.configure(
                        text="IEEE OUI cache updated" if changed else "IEEE OUI cache is already fresh"
                    )
                elif event == "error":
                    self._finish()
                    messagebox.showerror("Operation failed", str(payload))
        except Empty:
            pass
        finally:
            self.after(100, self._drain_queue)

    def _render(self, observations: list[DeviceObservation]) -> None:
        self._last_observations = observations
        for item in observations:
            self.tree.insert(
                "",
                "end",
                values=(
                    item.ip,
                    item.hostname or "—",
                    item.mac_address or "—",
                    item.vendor or "—",
                    ", ".join(item.methods) or "—",
                    item.latency_ms if item.latency_ms is not None else "—",
                ),
            )
        self.progress.set(1)
        self.status.configure(text=f"Discovery complete — {len(observations)} responsive hosts")

    def _cancel(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self.status.configure(text="Cancelling...")

    def _finish(self) -> None:
        self._running = False
        self._cancel_event = None
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
