# ADR-0004 — Remote trust boundaries and safe dispatch

Status: Accepted for P4-A/P4-B.

## Decisions
- Public fallback transport is WSS carrying the same Protobuf `RelayFrame` used internally.
- Private transport is bidirectional gRPC over mandatory mTLS.
- Device identity is certificate fingerprint → registered `device_id`; payload identity alone is insufficient.
- Device private keys are generated locally and stored via DPAPI; enrollment sends only a CSR.
- TLS provider is explicitly `ring`; unused `aws-lc` defaults are disabled.
- Protobuf ActionRequest stores canonical JSON parameters as bytes to avoid Struct numeric coercion.
- Replay, expiry and size validation happen before business dispatch.
- Transport success never implies worker authorization.

## Read-only remote execution
P4-B exposes only filesystem read, Git status/diff and process list/inspect. A dedicated remote allowlist is enforced in addition to the normal Policy Engine. Remote writes, terminals, browser-session control, process termination and elevation remain unavailable.

## MCP attribution
The Streamable HTTP adapter carries the authenticated Axum request parts into rmcp request extensions. Tools recover `GrantContext` from that HTTP context and set `actor_id` from the validated grant; actor identity is never accepted from tool arguments.

## Deployment boundary
P4-C will add Tailscale, VPS relay and Cloudflare edge. Those services are transport/exposure layers, not authorization authorities. No external deployment is implied by this ADR.
