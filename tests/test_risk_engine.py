from app.domain.models import RiskLevel
from app.security.risk_engine import ListenerRiskEngine


def test_user_writable_unsigned_listener_is_high_risk() -> None:
    engine = ListenerRiskEngine()
    score, level, reasons = engine.score(
        port=4444,
        local_ip="0.0.0.0",
        process_name="sample.exe",
        executable=r"C:\Users\User\AppData\Local\Temp\sample.exe",
        signature_status="NotSigned",
    )
    assert score >= 70
    assert level is RiskLevel.CRITICAL
    assert reasons


def test_normal_local_listener_is_low_risk() -> None:
    engine = ListenerRiskEngine()
    score, level, _ = engine.score(
        port=8080,
        local_ip="127.0.0.1",
        process_name="python.exe",
        executable=r"C:\Python312\python.exe",
        signature_status="Valid",
    )
    assert score < 20
    assert level is RiskLevel.LOW


def test_defender_detection_forces_critical_risk() -> None:
    engine = ListenerRiskEngine()
    score, level, reasons = engine.score(
        port=8080,
        local_ip="127.0.0.1",
        process_name="sample.exe",
        executable=r"C:\sample.exe",
        signature_status="Valid",
        defender_detected=True,
    )
    assert score == 100
    assert level is RiskLevel.CRITICAL
    assert any("Defender" in reason for reason in reasons)
