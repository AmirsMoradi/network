# SurNet Guardian 0.3.0

SurNet Guardian is a Windows-first desktop **network guardian, asset inventory and exposure auditing** application for systems and networks you own or are explicitly authorized to assess.

Version 0.3.0 builds on the v0.2 assessment engine and adds continuous device presence monitoring, trust management, alerts, event history, packet-loss checks, system-tray support and persistent application settings.

## What's new in 0.3.0

### Device inventory & trust
- Persistent device inventory in SQLite
- Online / Offline presence state
- First Seen / Last Seen timestamps
- Custom device names and notes
- Trusted / Unknown / Blocked classification (policy/review state; it does not remotely quarantine a device)
- Search and filtering by state or trust level
- MAC address normalization and IEEE OUI vendor enrichment
- Simple selected-device Ping test with packet-loss and average-latency summary
- CSV / JSON inventory export

### Automatic local-network monitoring
- Configurable private IPv4 target/CIDR
- Configurable interval from 15 seconds to 24 hours
- **Scan Now** action for an immediate private-LAN monitoring cycle
- Maximum 4096 hosts per monitoring target, enforced again in the service layer
- ICMP + ordinary TCP-connect presence discovery
- Two consecutive missed cycles required before an Online device is marked Offline
- Online/offline transition history
- New-device detection
- Blocked-device return detection
- Safe cancellation so application shutdown never converts a partial scan into false Offline events

### Alerts & event log
- Unknown-device alerts
- High-severity alert when a Blocked device is reachable
- Acknowledge selected/all alerts
- Clear acknowledged alerts without deleting the event history
- Dedicated Event Log for device lifecycle changes
- CSV / JSON export for alerts and events

### Desktop experience
- Dark and Light themes
- System tray support on Windows
- Minimize-to-tray option
- Tray notifications for monitor alerts/errors
- Optional Start with Windows using the current user's HKCU Run entry
- Settings persisted to `%USERPROFILE%\.surnet_guardian\settings.json`

### Existing professional capabilities preserved from 0.2
- CustomTkinter desktop UI
- Asset Discovery page
- CIDR / single-host TCP assessment with controlled asyncio concurrency
- Service fingerprinting for HTTP/TLS/common banner protocols
- HTTP server/banner product + version extraction when evidence is available
- TLS protocol/cipher/certificate metadata collection
- Evidence-backed exposure findings with severity and score
- Local listening socket inventory with PID/process/executable path
- Microsoft Defender correlation for suspicious local listeners
- Windows Authenticode status checks with caching
- Windows Firewall inbound allow/block rules with administrator checks
- Persistent scan history and scan-to-scan change comparison
- Candidate CVE enrichment from NVD
- CISA KEV highlighting
- Scan JSON / CSV export
- Additive SQLite upgrades that preserve existing v0.1/v0.2 data

## Security model

SurNet Guardian intentionally does **not** implement stealth scanning, IDS/EDR bypass, exploit automation, payload delivery, persistence, credential attacks, or anti-forensics.

The network assessment and monitoring engines use normal ICMP and TCP connections so the activity remains visible and auditable. Use it only on systems and networks you own or are explicitly authorized to assess.

A red result means **high/critical exposure or local-listener risk**, not automatic proof of malware. Every exposure finding carries evidence and remediation guidance.

CVE results are **candidates** based on observed service fingerprint evidence and NVD search. They must be validated before concluding that a target is vulnerable.

## Requirements

- Windows 10/11 x64 recommended
- Python **3.12** for source execution
- Administrator mode is required only for Windows Firewall changes, some Defender/process inspection, and full local-listener visibility
- Normal device discovery and inventory do not require administrator mode in most environments

## Install development environment

Open PowerShell in the project directory:

```powershell
.\install.ps1
```

Or manually:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Run from source

```powershell
.\run.ps1
```

or:

```powershell
.\.venv\Scripts\python.exe -m app.main
```

## First use

1. Open **Settings**.
2. Choose Dark or Light theme.
3. If you want continuous monitoring, enable **Automatic local-network discovery**.
4. Select a private local target such as `192.168.1.0/24`.
5. Choose the interval; `60` seconds is a good starting point.
6. Use **Scan Now** for an immediate cycle, or save settings to keep automatic monitoring enabled.
7. Open **Device Inventory** and review Unknown devices.
8. Mark known devices as **Trusted** and devices you do not want on the network as **Blocked**.
9. Review **Alerts** and **Event Log** for changes.
10. Use **Network Assessment** only for authorized service/exposure checks.

## Data location

SurNet Guardian keeps local data under:

```text
%USERPROFILE%\.surnet_guardian\
├── surnet.db
├── settings.json
├── surnet.log
├── oui.csv          (after optional IEEE OUI update)
└── oui-meta.json
```

No cloud account is required for the local inventory. NVD/CISA enrichment and IEEE OUI updates use their public online data sources when you explicitly use those features.

## Optional NVD API key

For repeated vulnerability-intelligence queries:

```powershell
$env:NVD_API_KEY = "your-key"
python -m app.main
```

The application works without a key but must respect NVD public API rate limits.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The v0.3 source package currently contains 28 regression tests covering target/port validation, safe target bounding, risk/exposure logic, scan diffs, settings persistence, additive database upgrades, device identity/lifecycle monitoring, alert-state transitions, monitor service behavior and ping-output parsing.

## Build executable

```powershell
.\build.ps1
```

The build script runs the test suite first. The executable will be created at:

```text
dist\SurNetGuardian.exe
```

## Build Windows installer

Install **Inno Setup 6** and run `build.ps1`; when `ISCC.exe` is detected the setup package is compiled automatically. You can also compile this file manually:

```text
installer\SurNetGuardian.iss
```

The installer script outputs:

```text
installer\output\SurNetGuardian-0.3.0-Setup.exe
```

## Version

Current source version: **0.3.0**
