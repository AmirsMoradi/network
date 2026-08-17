# SurNet Guardian Architecture

## Boundaries

- `network/`: authorized discovery, TCP connect scanning and local listener inspection.
- `security/`: heuristic scoring, Authenticode/Defender correlation and Windows Firewall actions.
- `database/`: persistence only; no UI or scanning logic.
- `services/`: application workflows such as history and export.
- `ui/`: CustomTkinter presentation and worker-thread bridges.

## Performance model

The TCP scanner uses a bounded `asyncio.Queue` and a fixed worker count. It does not create one
asyncio Task per host/port pair. Memory is therefore bounded primarily by the host-result map and
queue size rather than by the number of requested socket checks.

`ScanConfig.max_operations` protects the desktop application from accidental scans that would
otherwise require an unreasonable number of connection attempts.

## Risk semantics

Risk is explainable and evidence-based. Inputs currently include:

- listener bind scope (`0.0.0.0` / `::` exposure)
- high-attention ports
- user-writable executable locations
- Authenticode status
- suspicious system-process-name/path mismatch
- correlation against Microsoft Defender detection resources

`CRITICAL` means immediate review is warranted. It is not, by itself, a malware verdict.

## Firewall semantics

"Allow" and "Block" create inbound Windows Firewall rules after explicit user confirmation.
Rules are namespaced under `SurNet Guardian`. Opposing SurNet rules for the same protocol/port are
removed before the new rule is created so a stale Block rule cannot silently defeat an Allow rule.

Opening a firewall port does not create a listening service. Blocking a firewall port does not
terminate the process that owns the socket.
