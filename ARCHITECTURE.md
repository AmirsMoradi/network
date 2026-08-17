# SurNet Guardian Architecture — v0.2.0

## Design goals

- Windows-first desktop administration with Python 3.12
- Non-blocking CustomTkinter UI
- Bounded network concurrency and explicit cancellation
- Evidence-first security findings
- Persistent asset inventory and temporal scan comparison
- Defensive vulnerability enrichment without exploit execution

## Layers

- `app/network/targets.py`: target/CIDR validation and bounded expansion
- `app/network/discovery.py`: ICMP/TCP host discovery + Windows ARP enrichment
- `app/network/vendor.py`: cached IEEE OUI lookup
- `app/network/scanner.py`: bounded TCP connect assessment engine
- `app/network/fingerprint.py`: minimal protocol-aware service/TLS fingerprinting
- `app/security/exposure.py`: deterministic exposure rules with evidence/recommendations
- `app/security/vulnerability_intel.py`: NVD candidate CVEs + CISA KEV correlation
- `app/security/*`: local process risk, Defender, signatures and firewall control
- `app/database/*`: SQLAlchemy persistence and additive v0.1 -> v0.2 schema upgrades
- `app/services/history.py`: scan persistence, device inventory, reconstruction and diff
- `app/ui/*`: CustomTkinter presentation pages; no network logic in UI widgets

## Safety boundary

The product does not contain stealth/evasion, IDS/EDR bypass, exploit chains, credential attacks,
payload execution, persistence or anti-forensics. Network checks use normal connections and preserve
observable security telemetry. This keeps findings reproducible and suitable for defensive validation.
