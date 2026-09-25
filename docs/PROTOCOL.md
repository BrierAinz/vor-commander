# Protocol contract P0

## External surface

Remote clients talk standard MCP over HTTP at `/mcp`. Target revision: `2026-07-28`; compatibility with 2025-era clients may be provided by the chosen official SDK without changing Vör internal semantics.

Authentication uses OAuth/OIDC discovery and Protected Resource Metadata. Client identity is never inferred only from display name or IP.

Long-running commands map to MCP Tasks when the client advertises the extension. Vör execution jobs remain internal resources even when an MCP client disconnects, subject to policy and explicit TTL/cancellation rules.

## Internal contract

Protobuf defines durable message shapes. Two interchangeable transports carry them:

- private: gRPC over mTLS on LAN/Tailscale;
- public fallback: WSS carrying framed Protobuf through the relay/edge.

Transport identity and Vör authorization are separate checks.

Signed approval identity and approval authority are also separate checks. A trusted Ed25519 key is registered with one of three monotonic authorities: `approve < elevated < owner`. The local policy decision determines the minimum authority through `required_capability`; a cryptographically valid signer below that authority is rejected, and an unknown required capability fails closed. No authority tier can override a policy `deny` because approval verification is reachable only after the device policy returns `Approval`.

## Required envelope

Every executable request carries immutable `request_id`, `organization_id`, `actor_id`, `device_id`, `action`, normalized target, material parameters, requested capabilities, expiry and nonce. The policy decision binds to a digest of this envelope.

For `terminal.exec`, the material command contract is structured `parameters.argv`: a non-empty JSON array of strings. Missing, scalar or malformed argv fails policy closed. Vör does not infer terminal policy from an opaque shell string.

Known inline interpreter evaluation is stricter than ordinary terminal execution. Forms such as `python -c`, `node -e/--eval`, `perl/ruby -e`, `osascript -e` and PowerShell `-Command/-EncodedCommand` are classified before execution and routed through the dedicated `terminal.inline_eval` policy. The default is `elevated_approval`; later flags after a positional script path are not treated as interpreter flags.

## Failure semantics

Unknown capability, expired grant, identity mismatch, policy ambiguity or audit-write failure => fail closed. A transport reconnect never replays a side effect unless the request is explicitly idempotent and the ledger proves its disposition.
