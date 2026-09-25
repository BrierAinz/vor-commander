# OAuth / ChatGPT acceptance — P8 M0

Date: 2026-09-18
Status: COMPLETE / LIVE PASS

## Scope

M0 closes the OAuth/Dynamic Client Registration debt without reopening P4-C transport architecture.

## Required properties

- [x] OAuth discovery metadata is served.
- [x] Protected Resource Metadata is served and MCP challenges point to it.
- [x] Dynamic Client Registration accepts supported public clients.
- [x] DCR client records persist in `GrantStore`.
- [x] Reopening `GrantStore` preserves registered client ID, redirect URIs, name and registration timestamp.
- [x] Authorization codes remain ephemeral, one-time and are not added to persisted state.
- [x] Authorization Code flow requires PKCE S256.
- [x] Redirect URIs are exact-match/fail-closed.
- [x] Public client token authentication remains `token_endpoint_auth_method=none`.
- [x] OAuth page renders `Vör Commander` in UTF-8.
- [x] Updated `commander_status.phase` is `P4-C/OAuth`, not the obsolete `P4-B`.

## Local evidence

- `cargo fmt --all -- --check`: PASS.
- `cargo test -p vor-auth -p vor-gateway --locked`: PASS.
  - `vor-auth`: 5 passed.
  - `vor-gateway`: 11 passed.
  - Includes `oauth_client_survives_reopen`.
  - Includes `oauth_dcr_client_persists_across_gateway_reopen`.
  - Existing mTLS MCP read/audit E2E remains PASS.
- `cargo test --workspace --locked`: PASS.
- Four tests are intentionally ignored because they require interactive Firefox/desktop UI.

## Live acceptance gate

M0 is not COMPLETE until all of these are evidenced against `mcp.vorcommander.app`:

- [x] Deploy the updated `vor-control-plane` binary.
- [x] Restart `vor-control-plane.service` successfully.
- [x] Register a DCR client against the live gateway.
- [x] Restart the service again.
- [x] Confirm that the same registered client is still accepted by `/oauth/authorize`.
- [x] Confirm OAuth UI contains `Vör Commander` and no `VÃ¶r`.
- [x] Confirm ChatGPT's existing Vör Commander connection still reaches `commander_status`.
- [x] Confirm live `commander_status.phase == "P4-C/OAuth"`.

Live evidence on 2026-09-18:

- Source archive SHA-256: `e95475fe23adec9923d0fbcafb409d10575992dde52c961f2d4886136a6ebf21`.
- Linux release build: PASS with Rust/Cargo 1.96.0.
- Live binary SHA-256: `f58736832fc5a86fa2ddb7ee0c8f1ffa9195b791360385ef11a20cb05806febb`.
- DCR probe client: `M0 persistence probe`.
- The same live DCR `client_id` was accepted by `/oauth/authorize` before and after a deliberate `vor-control-plane.service` restart.
- UTF-8 page rendered `Vör Commander` before and after restart.
- ChatGPT `commander_status` after restart returned phase `P4-C/OAuth`.

M0 is COMPLETE. M1 certification no longer depends on OAuth M0; its remaining gates are the external signed approval/challenge flow and a dedicated live canary.

## Actor identity of OAuth grants (security sprint 1, 2026-09-25)

Until this change every grant minted by `/oauth/token` carried the fixed actor
`chatgpt-owner`, whatever connector received it. The device audit therefore
recorded ChatGPT, Claude and any other OAuth client as the same actor.

Grants issued through the OAuth flow now carry the actor

```text
<owner actor>:oauth:<DCR client_id>
```

for example `local-pilot:oauth:3q2+...`. The owner part is the actor of the
bootstrap token that approved the consent screen (today always `local-pilot`),
and the client part is the `client_id` issued by Dynamic Client Registration,
which is public and already persisted with the client name and redirect URIs in
`GrantStore`. To see which connector an audit entry belongs to, look the
`client_id` up in the registered OAuth clients.

Compatibility: grants issued before the change keep the actor `chatgpt-owner`
and remain valid until they expire (30 days after issue). No code matches on
that value, so there is no migration; a connector moves to the new actor the
next time it goes through the OAuth flow. Covered by
`sec3_oauth_grants_carry_owner_and_client_specific_actor` and
`sec3_legacy_chatgpt_owner_grants_remain_valid` in `apps/vor-gateway/src/oauth.rs`.

Still open: issuing and redeeming OAuth grants is not written to an audit
ledger. The gateway has no ledger of its own (the audit lives on the device), so
closing that needs a gateway-side audit sink.
