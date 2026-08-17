# Changelog

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

### Security boundary
- No stealth scanning, IDS/EDR bypass, exploit automation, credential attacks,
  payload delivery, persistence or anti-forensics.
