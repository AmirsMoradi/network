# SurNet Guardian Architecture — v0.3.0

## Design goals

- Windows-first defensive administration with Python 3.12
- Non-blocking CustomTkinter UI
- Bounded network concurrency and explicit cancellation
- Evidence-first exposure findings
- Persistent asset inventory and temporal state comparison
- Continuous local-network presence monitoring without stealth/evasion
- Additive database evolution with no destructive reset of existing v0.1/v0.2 history
- Clear separation between UI, services, network probes, security analysis and persistence

## Layers

### Core
- `app/core/config.py`: application version, paths, scan bounds and common ports
- `app/core/logging.py`: rotating local log file

### Domain
- `app/domain/models.py`: UI-independent dataclasses/enums for scans, devices, alerts, events, monitoring, listeners and ping results

### Network
- `app/network/targets.py`: IP/CIDR validation and bounded expansion
- `app/network/discovery.py`: ICMP/TCP host discovery + Windows ARP enrichment
- `app/network/vendor.py`: cached IEEE OUI lookup
- `app/network/ping.py`: selected-host packet loss / latency check
- `app/network/scanner.py`: bounded TCP-connect assessment engine
- `app/network/fingerprint.py`: protocol-aware service/TLS fingerprinting
- `app/network/local_listeners.py`: local listening socket/process inspection

### Security
- `app/security/exposure.py`: deterministic exposure rules with evidence/recommendations
- `app/security/vulnerability_intel.py`: NVD candidate CVEs + CISA KEV correlation
- `app/security/risk_engine.py`: local listener heuristic scoring
- `app/security/defender.py`: Microsoft Defender correlation
- `app/security/signatures.py`: Authenticode status checks
- `app/security/windows_firewall.py`: explicit inbound allow/block rules

### Persistence
- `app/database/models.py`: SQLAlchemy models for scans, hosts, ports, findings, devices, events and alerts
- `app/database/session.py`: SQLite setup, WAL/busy-timeout concurrency settings, indexes and additive schema upgrades
- `app/services/history.py`: scan persistence, device inventory, state transitions, event/alert generation and scan comparison

### Background services
- `app/services/monitor.py`: periodic discovery worker with explicit stop/wake events, immediate Scan Now triggering, safe restart and no partial-cycle offline mutation
- `app/services/settings.py`: atomic JSON settings persistence
- `app/services/startup.py`: optional current-user Windows startup registration
- `app/services/tray.py`: lazy Windows system-tray integration and notifications
- `app/services/exporter.py`: scan/device/event/alert CSV+JSON exports

### UI
- `app/ui/main_window.py`: composition root, navigation, monitor/tray lifecycle and runtime settings
- `app/ui/dashboard.py`: inventory/alert/system overview
- `app/ui/discovery_page.py`: manual authorized host discovery
- `app/ui/devices_page.py`: searchable inventory, trust/name/notes editing and ping health test
- `app/ui/alerts_page.py`: alert review/acknowledgement/export
- `app/ui/events_page.py`: device lifecycle event history/export
- `app/ui/scan_page.py`: authorized TCP service assessment
- `app/ui/exposure_page.py`: evidence and candidate vulnerability intelligence
- `app/ui/changes_page.py`: saved-scan comparison
- `app/ui/listeners_page.py`: local listener/process/firewall controls
- `app/ui/history_page.py`: saved assessment history and export
- `app/ui/settings_page.py`: theme, monitoring, notifications, tray and startup options

## Device state model

Each device has an identity key based on MAC address when available, otherwise IP address. When MAC information becomes available later, an existing IP-only record is upgraded to the MAC identity without deleting history.

Trust state is independent from reachability:

- `unknown`: not yet reviewed by the user
- `trusted`: reviewed and expected
- `blocked`: user-classified as not permitted/desired

Presence state:

- observed -> Online
- one missed automatic cycle -> still Online (debounce)
- two consecutive missed cycles -> Offline + event
- observed after Offline -> Online + event

A new Unknown device creates an alert. A Blocked device creates a high-severity alert when it is marked Blocked while online or when it returns online.

## Threading model

Tkinter widgets are only updated from the Tk/main thread. Network assessment, discovery, listener inspection and monitoring run outside the UI thread. Background monitor callbacks write small messages into a queue; `MainWindow` drains that queue via `after()`. `LifecycleFrame` makes page-owned scheduled callbacks inert after a runtime theme rebuild and scan/discovery pages signal their cancellation events when destroyed.

The monitor owns a dedicated `threading.Event` per worker generation. A stopped worker never reuses the next worker's Event object. A cancelled/partial discovery is discarded before inventory state is changed.

## Database migration strategy

`Database.initialize()` performs:

1. `Base.metadata.create_all()` to create brand-new v0.3 tables such as `events` and `alerts`.
2. Additive `ALTER TABLE ... ADD COLUMN` upgrades for columns introduced after v0.1/v0.2.
3. A final `create_all()` pass.
4. Idempotent indexes for v0.3 device-state queries.

SQLite also enables foreign-key enforcement, a busy timeout and WAL mode to reduce contention between UI reads and the background monitor. No migration path drops user scan history or device inventory.

## Safety boundary

The product does not contain stealth/evasion, IDS/EDR bypass, exploit chains, credential attacks, payload execution, persistence or anti-forensics. Network checks use ordinary connections and preserve observable security telemetry.

The automatic monitor is restricted in both the UI and service layer to private IPv4 space and a maximum of 4096 hosts. Manual target expansion rejects oversized IPv4/IPv6 CIDRs before materializing the address list.
