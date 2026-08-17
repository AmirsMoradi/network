# SurNet Guardian

SurNet Guardian is a Windows-first desktop network discovery and local exposure auditing tool.
It is designed for authorized administration of systems and networks you own or are permitted to test.

## Core capabilities

- CustomTkinter desktop UI with non-blocking scans
- CIDR / single-host TCP connect scanning
- Controlled asyncio concurrency and cancellation
- Hostname and common-service identification
- Local listening socket inventory with PID/process/executable path
- Heuristic risk scoring for suspicious listeners with explicit reasons
- Windows Authenticode status checks with caching
- Windows Firewall inbound allow/block rules with administrator checks
- SQLite scan history through SQLAlchemy
- JSON / CSV export-ready service layer
- Modular architecture and pytest coverage

## Important security semantics

A red listener means **high heuristic risk**, not "confirmed malware". The application explains why the
listener was scored that way. Firewall "Close" blocks inbound traffic; it does not terminate the owning
process or magically remove the listening socket.

## Run

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m app.main
```

For firewall changes and full process inspection, run the terminal as Administrator.
