# P3 Gateway — acceptance

Target: authenticated local MCP/REST gateway with pairing and no worker dispatch.

## Identity and grants
- [x] Stable device ID is persisted locally.
- [x] Bearer grants have actor, scopes, TTL and revocation.
- [x] Raw grant tokens are never persisted.
- [x] Pairing codes are random, one-use, TTL-bound and never persisted raw.
- [x] Pairing redemption creates a scoped short-lived grant.

## HTTP surfaces
- [x] Gateway rejects non-loopback binds in P3.
- [x] `/healthz` is non-sensitive and public on loopback.
- [x] `/v1/info` requires `gateway.read`.
- [x] `/v1/admin/*` requires `admin`.
- [x] `/v1/pair` redeems a one-time pairing code.
- [x] `/dashboard` embeds no device identity or secret.

## MCP
- [x] `/mcp` requires `mcp` scope.
- [x] Protocol target is MCP `2026-07-28`.
- [x] Streamable HTTP runs stateless.
- [x] Hostile browser Origin is rejected.
- [x] Only non-sensitive `commander_status` is exposed.
- [x] `remote_worker_dispatch` remains false.