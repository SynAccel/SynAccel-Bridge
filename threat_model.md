# Threat Model — SynAccel-Bridge v0.2

## System Overview
SynAccel-Bridge is a telemetry ingestion gateway that receives signed
events from remote devices, validates integrity and freshness, correlates
events, and generates alerts.

## Assets
- Telemetry integrity
- Device identity
- Alert correctness
- Correlation pipeline

## Threats Considered

### Spoofed Devices
Attackers may attempt to submit fake telemetry.
**Mitigation:** Per-device HMAC secrets and API key verification.

### Replay Attacks
Previously valid telemetry may be resent.
**Mitigation:** Timestamp skew checks and nonce replay protection.

### Payload Tampering
Telemetry may be modified in transit.
**Mitigation:** HMAC signature validation over canonical payloads.

### Event Flooding
High-volume events may attempt to overwhelm the system.
**Mitigation:** Short rolling history and bounded nonce cache.

## Out of Scope
- Compromised device secrets
- Insider threats
- Physical device capture

## Security Assumptions
- Device secrets remain confidential
- TLS protects transport layer
- API keys are not leaked
