# P4 Remote — acceptance

Date: 2026-09-17
Scope: local certification of remote transports and safe read-only dispatch plus staged P4-C deployment.

## P4-A — transport/security foundation
- [x] Protobuf is generated reproducibly with vendored `protoc`.
- [x] `RelayFrame` enforces version, size, expiry, nonce and replay protection.
- [x] Canonical ActionRequest digest is reconstructed and verified on ingress.
- [x] Action parameters preserve exact JSON semantics via `parameters_json` bytes.
- [x] Device WSS client initiates outbound connections; no fallback listener is opened.
- [x] Remote `ws://` is denied; non-loopback relay endpoints require `wss://`.
- [x] Device bearer tokens are redacted and are not accepted in URL/query parameters.
- [x] Windows DPAPI SecretStore encrypts local private material at rest.
- [x] Device key is generated locally; enrollment exports only a CSR.
- [x] Device certificate identity is assigned by the issuer, not trusted from the CSR.
- [x] Private gRPC uses mutual TLS and cert fingerprint → `device_id` binding.
- [x] Approval grants use Ed25519 and bind request digest, policy, capability, nonce and expiry.

## P4-B — safe read-only dispatch
- [x] Remote dispatch has an allowlist independent from local policy.
- [x] Allowed: `filesystem.read`, `git.status`, `git.diff`, `process.list`, `process.inspect`.
- [x] Remote terminal, writes, browser sessions and process termination are not exposed.
- [x] Filesystem reads enforce size limit before loading data.
- [x] Authorization and execution outcome are separate audit events.
- [x] Gateway MCP tools recover the authenticated grant actor from HTTP request context.
- [x] MCP → Gateway → gRPC/mTLS → Device → worker → ActionResult roundtrip is tested.
- [x] RelayHub → WSS/Protobuf → Device → same dispatcher → ActionResult roundtrip is tested.
- [x] The actor from the MCP bearer grant is present in the Device audit ledger.
- [x] Gateway safely encodes arbitrary file bytes as base64.
- [x] `vor-agent private-run` loads the device private key only from DPAPI SecretStore.
- [x] `vor-agent relay-dispatch-run` can load its bearer directly from the DPAPI SecretStore; raw bearer output is avoided in the deployed pilot.
- [x] Device private-key configuration has redacted Debug output and zeroizes on drop.
- [x] Real relay/agent binary smoke passes and does not persist the raw bearer token.

## P4-C — external deployment
- [x] Tailscale route deployed for raw TCP `8790` only.
- [x] VPS relay/control plane deployed as `vor-control-plane.service` with loopback origins.
- [x] Cloudflare DNS/Tunnel/edge configured on the VPS.
- [x] WSS read-only fallback deployed and certified through the external VPS edge.
- [x] Reconnect/failover certified against real external infrastructure with one read-only MCP action.
- [x] Pilot restricted to the owner workstation before any multi-tenant rollout.

P4-C certified on 2026-09-17. Evidence: VPS-only public MCP passed; WSS fallback returned `status=ok`; relay audit advanced by exactly two events while private audit remained unchanged; mTLS then reconnected successfully. The workstation Cloudflare connector is retired as rollback-only.

OAuth/ChatGPT interoperability hardening is tracked separately in `docs/OAUTH_ACCEPTANCE.md`; it does not reopen P4-C transport certification.
