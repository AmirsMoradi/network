from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from app.domain.models import ExposureFinding, RiskLevel, ServiceFingerprint


class ExposureAnalyzer:
    _PLAINTEXT_SERVICES: dict[int, tuple[str, str]] = {
        21: ("FTP exposed without transport encryption", "Prefer SFTP/FTPS and restrict network scope."),
        23: ("Telnet service exposed", "Disable Telnet and use SSH with strong authentication."),
        110: ("POP3 exposed without transport encryption", "Prefer POP3S or STARTTLS and restrict access."),
        143: ("IMAP exposed without transport encryption", "Prefer IMAPS or STARTTLS and restrict access."),
    }
    _SENSITIVE_PORTS: dict[int, tuple[str, int, RiskLevel, str]] = {
        135: ("Windows RPC exposed", 55, RiskLevel.MEDIUM, "Restrict RPC to trusted management networks."),
        139: ("NetBIOS exposed", 65, RiskLevel.HIGH, "Restrict legacy NetBIOS exposure to trusted segments."),
        445: ("SMB exposed", 75, RiskLevel.HIGH, "Restrict SMB to trusted segments and require SMB signing where applicable."),
        1433: ("SQL Server exposed", 70, RiskLevel.HIGH, "Restrict database access to application and administration networks."),
        3306: ("MySQL exposed", 70, RiskLevel.HIGH, "Restrict database access to application hosts and management networks."),
        3389: ("RDP exposed", 75, RiskLevel.HIGH, "Restrict RDP, require NLA/MFA and use a hardened management path."),
        5432: ("PostgreSQL exposed", 70, RiskLevel.HIGH, "Restrict database access to application hosts and management networks."),
        5900: ("VNC exposed", 80, RiskLevel.HIGH, "Restrict VNC to trusted management networks or a secure jump host."),
        6379: ("Redis exposed", 80, RiskLevel.HIGH, "Bind Redis to trusted interfaces and enforce authentication/TLS where supported."),
        9200: ("Elasticsearch exposed", 75, RiskLevel.HIGH, "Restrict Elasticsearch network exposure and enable authentication/TLS."),
        27017: ("MongoDB exposed", 75, RiskLevel.HIGH, "Restrict MongoDB network exposure and enforce authentication/TLS."),
    }

    def analyze_port(
        self,
        *,
        ip: str,
        port: int,
        service: str,
        fingerprint: ServiceFingerprint,
    ) -> tuple[ExposureFinding, ...]:
        findings: list[ExposureFinding] = []
        is_public = self._is_public_ip(ip)

        if port in self._PLAINTEXT_SERVICES:
            title, recommendation = self._PLAINTEXT_SERVICES[port]
            findings.append(
                ExposureFinding(
                    finding_type="plaintext_service",
                    title=title,
                    severity=RiskLevel.HIGH if port == 23 else RiskLevel.MEDIUM,
                    score=75 if port == 23 else 55,
                    ip=ip,
                    port=port,
                    evidence=f"TCP/{port} ({service}) accepted a connection.",
                    recommendation=recommendation,
                )
            )

        sensitive = self._SENSITIVE_PORTS.get(port)
        if sensitive:
            title, score, severity, recommendation = sensitive
            if is_public:
                score = min(100, score + 15)
                severity = RiskLevel.CRITICAL if score >= 90 else RiskLevel.HIGH
                title = f"Publicly reachable {title.lower()}"
            findings.append(
                ExposureFinding(
                    finding_type="sensitive_service_exposure",
                    title=title,
                    severity=severity,
                    score=score,
                    ip=ip,
                    port=port,
                    evidence=f"TCP/{port} ({service}) accepted a connection from the assessment host.",
                    recommendation=recommendation,
                )
            )

        if fingerprint.banner and fingerprint.version:
            findings.append(
                ExposureFinding(
                    finding_type="version_disclosure",
                    title="Service version disclosed",
                    severity=RiskLevel.LOW,
                    score=20,
                    ip=ip,
                    port=port,
                    evidence=f"Detected {fingerprint.product or service} {fingerprint.version} from the service response.",
                    recommendation="Confirm the software is supported and fully patched; suppress unnecessary version disclosure where practical.",
                )
            )

        if fingerprint.tls_version in {"TLSv1", "TLSv1.1", "SSLv3"}:
            findings.append(
                ExposureFinding(
                    finding_type="weak_tls",
                    title="Legacy TLS protocol negotiated",
                    severity=RiskLevel.HIGH,
                    score=75,
                    ip=ip,
                    port=port,
                    evidence=f"Negotiated protocol: {fingerprint.tls_version}.",
                    recommendation="Disable legacy TLS versions and require TLS 1.2 or newer.",
                )
            )

        expires_at = fingerprint.certificate_expires_at
        if expires_at is not None:
            now = datetime.now(timezone.utc)
            if expires_at <= now:
                findings.append(
                    ExposureFinding(
                        finding_type="expired_certificate",
                        title="Expired TLS certificate",
                        severity=RiskLevel.HIGH,
                        score=80,
                        ip=ip,
                        port=port,
                        evidence=f"Certificate expired at {expires_at.isoformat()}.",
                        recommendation="Replace the expired certificate and verify automated renewal.",
                    )
                )
            elif (expires_at - now).days <= 30:
                findings.append(
                    ExposureFinding(
                        finding_type="certificate_expiring",
                        title="TLS certificate expires soon",
                        severity=RiskLevel.MEDIUM,
                        score=45,
                        ip=ip,
                        port=port,
                        evidence=f"Certificate expires at {expires_at.isoformat()}.",
                        recommendation="Renew the certificate before expiry and verify renewal automation.",
                    )
                )
        return tuple(findings)

    @staticmethod
    def summarize(findings: tuple[ExposureFinding, ...]) -> tuple[int, RiskLevel]:
        if not findings:
            return 0, RiskLevel.LOW
        score = max(item.score for item in findings)
        if score >= 90:
            return score, RiskLevel.CRITICAL
        if score >= 70:
            return score, RiskLevel.HIGH
        if score >= 40:
            return score, RiskLevel.MEDIUM
        return score, RiskLevel.LOW

    @staticmethod
    def _is_public_ip(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (address.is_private or address.is_loopback or address.is_link_local)
