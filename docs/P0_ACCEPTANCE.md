# P0 acceptance criteria

P0 is complete only when all items below are true.

## Architecture
- [x] Product location follows workspace governance.
- [x] Local/core/cloud boundaries are documented.
- [x] Transport failover never opens a public listener automatically.
- [x] Cloudflare and Tailscale are replaceable dependencies.
- [x] Lilith boundary is explicit.

## Security
- [x] Threat model identifies device, browser, privilege, tenant and audit risks.
- [x] Policy has AUTO / APPROVAL / DENY semantics.
- [x] Secret extraction is denied by default.
- [x] Approval is bound to immutable request material.
- [x] Audit failure is fail-closed for side effects.

## Protocol
- [x] MCP external target is documented.
- [x] Protobuf envelope exists.
- [x] Private and public relay transports are separated from authorization.
- [x] Device, actor, organization and request identities are explicit.

## Product
- [x] Community/Local, Personal Cloud, Teams and Enterprise boundaries exist.
- [x] SaaS tenant invariants exist.
- [x] D25 licensing is approved by Ainz: MPL-2.0 for the local/open core.

P0 accepted on 2026-09-16. P1 Local Core is authorized to begin.
