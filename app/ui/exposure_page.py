from __future__ import annotations

import threading
from queue import Empty, Queue
from tkinter import messagebox

import customtkinter as ctk

from app.domain.models import ExposureFinding, PortResult, RiskLevel
from app.security.vulnerability_intel import VulnerabilityIntelService
from app.services.history import HistoryService
from app.ui.components.tree import create_tree
from app.ui.lifecycle import LifecycleFrame
from app.ui.theme import UiTheme


class ExposurePage(LifecycleFrame):
    def __init__(
        self,
        master: ctk.CTkFrame,
        *,
        font_family: str,
        history: HistoryService,
        vulnerability_intel: VulnerabilityIntelService,
    ) -> None:
        super().__init__(master, fg_color=UiTheme.BG)
        self._font = font_family
        self._history = history
        self._intel = vulnerability_intel
        self._queue: Queue[tuple[str, object]] = Queue()
        self._rows: dict[str, tuple[str, PortResult, ExposureFinding | None]] = {}
        self._build()
        self.after(100, self._drain_queue)

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 14))
        ctk.CTkLabel(
            header,
            text="Exposure Analysis",
            font=(self._font, 24, "bold"),
            text_color=UiTheme.TEXT,
        ).pack(side="left")
        self.scan_selector = ctk.CTkComboBox(header, values=["No scans"], width=220)
        self.scan_selector.pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            header,
            text="Analyze",
            width=110,
            command=self._load_selected_scan,
            font=(self._font, 10, "bold"),
        ).pack(side="right")

        summary = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        summary.pack(fill="x", padx=24, pady=(0, 12))
        self.summary_label = ctk.CTkLabel(
            summary,
            text="Select a saved scan.",
            font=(self._font, 11, "bold"),
            text_color=UiTheme.TEXT,
        )
        self.summary_label.pack(anchor="w", padx=16, pady=14)

        frame = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        frame.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.tree = create_tree(
            frame,
            columns=("severity", "score", "ip", "port", "service", "product", "version", "finding"),
            headings=("Severity", "Score", "IP", "Port", "Service", "Product", "Version", "Finding"),
            font_family=self._font,
        )
        self.tree.column("finding", width=320)
        self.tree.column("product", width=160)
        self.tree.bind("<<TreeviewSelect>>", self._show_details)
        self.tree.tag_configure("high", foreground=UiTheme.DANGER)
        self.tree.tag_configure("critical", foreground=UiTheme.CRITICAL)
        self.tree.tag_configure("medium", foreground=UiTheme.WARNING)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        detail = ctk.CTkFrame(self, fg_color=UiTheme.PANEL, corner_radius=14)
        detail.pack(fill="x", padx=24, pady=(0, 24))
        self.detail_text = ctk.CTkTextbox(
            detail,
            height=120,
            font=(self._font, 10),
            fg_color=UiTheme.PANEL_ALT,
        )
        self.detail_text.pack(fill="x", padx=12, pady=(12, 8))
        self.detail_text.insert("1.0", "Select a finding to view evidence and remediation guidance.")
        self.detail_text.configure(state="disabled")
        self.cve_button = ctk.CTkButton(
            detail,
            text="Check NVD + CISA KEV",
            command=self._lookup_cves,
            font=(self._font, 10, "bold"),
        )
        self.cve_button.pack(anchor="e", padx=12, pady=(0, 12))

    def refresh(self) -> None:
        scans = self._history.list_recent(100)
        values = [f"#{scan.id}  {scan.target}" for scan in scans]
        self.scan_selector.configure(values=values or ["No scans"])
        if values:
            self.scan_selector.set(values[0])

    def _load_selected_scan(self) -> None:
        value = self.scan_selector.get()
        if not value.startswith("#"):
            return
        try:
            scan_id = int(value.split()[0][1:])
        except (ValueError, IndexError):
            return
        scan = self._history.get_scan(scan_id)
        if scan is None:
            messagebox.showerror("Scan not found", f"Scan #{scan_id} was not found")
            return
        self._rows.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        counts = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 0, RiskLevel.LOW: 0}
        for host in scan.hosts:
            for port in host.ports:
                findings = port.findings or (None,)
                for finding in findings:
                    severity = finding.severity if finding else port.risk_level
                    score = finding.score if finding else port.risk_score
                    counts[severity] += 1
                    fingerprint = port.fingerprint
                    iid = self.tree.insert(
                        "",
                        "end",
                        values=(
                            severity.value.upper(),
                            score,
                            host.ip,
                            port.port,
                            port.service,
                            fingerprint.product or "—",
                            fingerprint.version or "—",
                            finding.title if finding else "Open service observed",
                        ),
                        tags=(severity.value,),
                    )
                    self._rows[iid] = (host.ip, port, finding)
        self.summary_label.configure(
            text=(
                f"Scan #{scan_id} — Critical {counts[RiskLevel.CRITICAL]}   |   "
                f"High {counts[RiskLevel.HIGH]}   |   Medium {counts[RiskLevel.MEDIUM]}   |   "
                f"Low {counts[RiskLevel.LOW]}"
            )
        )

    def _show_details(self, _event: object | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        ip, port, finding = self._rows[selection[0]]
        fp = port.fingerprint
        lines = [
            f"Target: {ip}:{port.port}",
            f"Service: {port.service}",
            f"Fingerprint: {fp.product or 'unknown'} {fp.version or ''}".rstrip(),
            f"TLS: {fp.tls_version or '—'} / {fp.tls_cipher or '—'}",
        ]
        if finding:
            lines.extend(
                [
                    f"Finding: {finding.title}",
                    f"Evidence: {finding.evidence}",
                    f"Recommendation: {finding.recommendation}",
                ]
            )
        if fp.banner:
            lines.append(f"Banner: {fp.banner}")
        self._set_details("\n".join(lines))

    def _lookup_cves(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Select service", "Select a service row first")
            return
        _, port, _ = self._rows[selection[0]]
        product = port.fingerprint.product
        version = port.fingerprint.version
        if not product or not version:
            messagebox.showinfo(
                "No product version",
                "A product and version fingerprint is required before candidate CVEs can be searched.",
            )
            return
        self.cve_button.configure(state="disabled", text="Checking...")

        def worker() -> None:
            try:
                results = self._intel.search_candidates(product=product, version=version)
                self._queue.put(("cves", (product, version, results)))
            except Exception as exc:
                self._queue.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "cves":
                    product, version, results = payload  # type: ignore[misc]
                    lines = [
                        f"Candidate vulnerability intelligence for {product} {version}",
                        "Important: keyword correlation is not proof that this host is vulnerable.",
                        "",
                    ]
                    if not results:
                        lines.append("No NVD candidates returned.")
                    for result in results:
                        kev = "  [CISA KEV]" if result.known_exploited else ""
                        lines.append(
                            f"{result.cve_id}  CVSS={result.cvss_score or '—'}  "
                            f"{result.severity or '—'}{kev}\n{result.description}\n"
                        )
                    self._set_details("\n".join(lines))
                    self.cve_button.configure(state="normal", text="Check NVD + CISA KEV")
                elif event == "error":
                    self.cve_button.configure(state="normal", text="Check NVD + CISA KEV")
                    messagebox.showerror("Vulnerability lookup failed", str(payload))
        except Empty:
            pass
        finally:
            self.after(100, self._drain_queue)

    def _set_details(self, text: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")
