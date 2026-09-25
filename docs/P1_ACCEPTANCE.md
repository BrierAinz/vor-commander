# P1 Local Core — acceptance

Accepted: 2026-09-16
Status: PASS

## Core invariants

- [x] Action envelopes are immutable-by-digest and expire.
- [x] Policy defaults unknown actions to DENY.
- [x] AUTO / APPROVAL / DENY and elevated approval exist.
- [x] Audit is SQLite + JSONL with chained hashes and divergence detection.
- [x] Broker verifies request integrity before policy/audit authorization.

## Workers

- [x] Filesystem read/write requires matching AUTO authorization.
- [x] Filesystem writes are content-digest bound, journaled and verified.
- [x] Traversal and reparse-point escapes are rejected.
- [x] Process list/inspect are read-only; terminate requires approval and has no executor yet.
- [x] Git status/diff are read-only and disable external diff helpers.
- [x] ConPTY supports spawn, input, VT output, resize and exit-code inspection.

## Agent boundary

- [x] Bootstrap listener can bind only to loopback.
- [x] Bootstrap exposes only PING/INFO.
- [x] INFO advertises `remote_actions:false`.
- [x] No worker is reachable through network transport in P1.
- [x] No service, scheduled task, firewall rule or startup persistence exists.
