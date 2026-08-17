from app.network.ping import PingService


def test_parse_windows_ping_summary() -> None:
    text = "Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),\\nAverage = 12ms"
    sent, received, loss = PingService._parse_counts(text, 4, "windows")
    assert (sent, received, loss) == (4, 3, 25.0)
    assert PingService._parse_average(text, "windows") == 12.0


def test_parse_linux_ping_summary() -> None:
    text = "4 packets transmitted, 4 received, 0% packet loss\\nrtt min/avg/max/mdev = 2.000/3.500/5.000/1.000 ms"
    sent, received, loss = PingService._parse_counts(text, 4, "linux")
    assert (sent, received, loss) == (4, 4, 0.0)
    assert PingService._parse_average(text, "linux") == 3.5
