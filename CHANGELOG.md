# Changelog

## 0.3.0

### Added
- Device Inventory page with Online/Offline state
- Trusted / Unknown / Blocked device classification
- Custom device names and notes
- Device search and state/trust filters
- First Seen / Last Seen / last latency tracking
- Selected-device ping test with packet-loss summary
- Periodic automatic private-LAN monitoring
- Immediate **Scan Now** monitor trigger
- Two-cycle offline debounce to reduce false Offline transitions
- Safe monitor cancellation and restart lifecycle
- Unknown-device alerts
- Blocked-device-online high-severity alerts
- Alert acknowledgement and cleanup workflow
- Device Event Log for discovery, online/offline and trust-status changes
- Device / alert / event CSV and JSON exports
- Scan export controls on Scan History page
- Dark / Light theme setting
- Windows system-tray integration
- Optional minimize-to-tray behavior
- Tray notifications for automatic-monitor alerts/errors
- Optional Start with Windows using HKCU (current user)
- Atomic JSON application settings
- Additive v0.2 -> v0.3 SQLite schema upgrade
- 28 regression tests covering settings, migration, target bounds, inventory/alert lifecycle, monitor service and ping parsing

### Improved
- SQLite WAL/busy-timeout configuration for safer UI/background monitor concurrency
- Service-layer enforcement of private IPv4/4096-host bounds for unattended monitoring
- Early rejection of huge IPv4/IPv6 CIDRs before address-list allocation
- Theme-rebuild lifecycle guards for recurring Tk callbacks
- Automatic alert resolution when a Blocked device goes offline or trust state changes
- Dashboard now surfaces known/online/offline/unknown device counts and open alerts
- Sidebar navigation expanded for inventory, alerts, event history and settings
- Build script runs tests before PyInstaller packaging
- Installer updated to v0.3.0 and removes the HKCU startup value on uninstall
- IEEE OUI User-Agent updated for v0.3

### Preserved from 0.2
- Asset discovery
- Service fingerprinting and TLS audit
- Exposure scoring and remediation evidence
- NVD candidate CVE + CISA KEV correlation
- Network change comparison
- Local listener/process inspection
- Microsoft Defender correlation
- Authenticode checks
- Windows Firewall inbound allow/block controls

### Security boundary
- No stealth scanning, IDS/EDR bypass, exploit automation, credential attacks,
  payload delivery, persistence or anti-forensics.
- Automatic background monitoring is enforced in the UI and service layer to private IPv4 targets and 4096 hosts.

## 0.2.0

### Added
- Asset Discovery with ICMP/TCP discovery and Windows ARP enrichment
- Persistent device inventory
- IEEE OUI vendor cache/update support
- Service fingerprinting for common HTTP/TLS/banner protocols
- Product/version extraction from observed banners
- TLS protocol, cipher and certificate metadata collection
- Evidence-backed exposure findings and severity scoring
- Exposure Analysis UI with high/critical highlighting
- NVD CPE resolution and candidate CVE lookup
- CISA Known Exploited Vulnerability correlation
- Network Changes page for host/port/service diffing
- Rich scan history risk summaries
- Dashboard inventory/exposure statistics
- JSON/CSV export with fingerprint and finding metadata
- Additive SQLite schema migration from 0.1.x

### Preserved
- Local listener/process inspection
- Microsoft Defender correlation
- Authenticode signature checks
- Windows Firewall inbound allow/block controls
