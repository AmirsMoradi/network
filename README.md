# SurNet Guardian 0.2.0

SurNet Guardian is a Windows-first desktop **network security, exposure auditing and asset intelligence** tool for systems and networks you own or are explicitly authorized to assess.

## Professional capabilities

- CustomTkinter desktop UI with Segoe UI Variable / Segoe UI fallback
- Asset Discovery page with ICMP + ordinary TCP connect discovery
- Local ARP-cache MAC enrichment on Windows
- Optional IEEE OUI vendor database download/cache
- CIDR / single-host TCP assessment with controlled asyncio concurrency
- Service fingerprinting for HTTP/TLS/common banner protocols
- HTTP server/banner product + version extraction when evidence is available
- TLS protocol/cipher/certificate metadata collection
- Evidence-backed exposure findings with severity and score
- Red highlighting for high/critical findings
- Local listening socket inventory with PID/process/executable path
- Microsoft Defender correlation for suspicious local listeners
- Windows Authenticode status checks with caching
- Windows Firewall inbound allow/block rules with administrator checks
- Persistent device inventory and scan history in SQLite/SQLAlchemy
- Scan-to-scan diff: new/removed hosts, new/closed ports, service/version changes
- Candidate CVE enrichment from NVD based on observed product/version
- CISA KEV highlighting for CVEs known to be exploited in the wild
- JSON / CSV export service with evidence and fingerprint metadata
- Additive SQLite upgrade path from the v0.1 schema
- Modular architecture and pytest coverage

## Security model

SurNet Guardian intentionally does **not** implement stealth scanning, IDS/EDR bypass, exploit automation, payload delivery, persistence, credential attacks, or anti-forensics. The assessment engine is designed to be auditable and useful for defensive validation without hiding activity from security controls.

A red result means **high/critical exposure or local-listener risk**, not automatic proof of malware. Every finding carries explicit evidence and remediation guidance.

CVE results are **candidates** based on service fingerprint evidence and NVD search. They must be validated before concluding that a target is vulnerable.

## Run on Windows / Python 3.12

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m app.main
```

For firewall changes, Defender correlation and full process inspection, run the terminal as Administrator.

## Build

```powershell
.\build.ps1
```

Then compile `installer/SurNetGuardian.iss` with Inno Setup to produce the Windows installer.

### Optional NVD API key

For repeated vulnerability-intelligence queries, set an NVD API key in the environment before launching:

```powershell
$env:NVD_API_KEY = "your-key"
python -m app.main
```

The application works without a key but must respect NVD public API rate limits.
