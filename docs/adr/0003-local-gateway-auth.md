# ADR-0003 — Local gateway authentication

Status: Accepted for P3; cloud auth remains P4+.

## Decision

P3 uses short-lived opaque bearer grants stored only as SHA-256 hashes. A stable local device ID is persisted separately from grants.

Bootstrap authority comes from the local CLI. An admin grant can create one-time pairing codes through the REST API. Pairing codes are random secrets, stored only by hash, expire, and can be redeemed once for a scoped grant.

## Scope separation

- `gateway.read`: protected local status.
- `mcp`: MCP endpoint.
- `admin`: pairing creation and grant revocation.

## Browser dashboard

The dashboard is a public loopback shell containing no device identity or secrets. Protected data still requires an Authorization header.

## Deferred

OAuth/OIDC, cloud accounts, organization membership, mTLS device certificates and relay identity are intentionally deferred to the remote/cloud phases. Local bearer grants do not replace those controls.