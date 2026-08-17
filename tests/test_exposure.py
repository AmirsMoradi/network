from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.domain.models import RiskLevel, ServiceFingerprint
from app.security.exposure import ExposureAnalyzer


def test_public_smb_is_critical() -> None:
    analyzer = ExposureAnalyzer()
    findings = analyzer.analyze_port(
        ip="8.8.8.8",
        port=445,
        service="microsoft-ds",
        fingerprint=ServiceFingerprint(),
    )
    assert findings
    score, level = analyzer.summarize(findings)
    assert score >= 90
    assert level is RiskLevel.CRITICAL


def test_private_database_exposure_is_high() -> None:
    analyzer = ExposureAnalyzer()
    findings = analyzer.analyze_port(
        ip="192.168.1.10",
        port=3306,
        service="mysql",
        fingerprint=ServiceFingerprint(),
    )
    assert any(item.finding_type == "sensitive_service_exposure" for item in findings)
    _, level = analyzer.summarize(findings)
    assert level is RiskLevel.HIGH


def test_expired_certificate_is_high() -> None:
    analyzer = ExposureAnalyzer()
    fingerprint = ServiceFingerprint(
        tls_version="TLSv1.3",
        certificate_expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    findings = analyzer.analyze_port(
        ip="192.168.1.20",
        port=443,
        service="https",
        fingerprint=fingerprint,
    )
    assert any(item.finding_type == "expired_certificate" for item in findings)
