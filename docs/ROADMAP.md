# Roadmap

## P0 — Blueprint — COMPLETE
Architecture, editions, threat model, protocol, policy and acceptance criteria.

## P1 — Local Core — COMPLETE / CERTIFIED
Rust Device Agent; filesystem; ConPTY; processes; Git; policy; audit; broker; tests.

## P2 — Browser — COMPLETE / CERTIFIED
Dedicated Firefox profile; direct WebDriver/BiDi Rust bridge; semantic DOM; screenshots; downloads; no secret extraction API.

## P3 — Gateway — COMPLETE / CERTIFIED
Scoped grants, one-time pairing, MCP `2026-07-28` Streamable HTTP, REST/admin API and local dashboard.

## P4-A/B — Remote transport + safe dispatch — COMPLETE / CERTIFIED LOCALLY
Read-only MCP actions route through private gRPC/mTLS or WSS+Protobuf to the same Device dispatcher. Actor attribution, policy, audit, replay protection and output bounds are mandatory.

## P4-C — External deployment — COMPLETE / CERTIFIED
`vor-control-plane`, hardened systemd, Tailscale TCP Serve and remotely-managed Cloudflare Tunnel are deployed. Public MCP, private gRPC/mTLS, WSS fallback, recovery and no-replay behavior are certified against the real VPS/Cloudflare path.

OAuth interoperability hardening is tracked as M0 under P8 rather than reopening P4-C transport certification.

## P5-A — Desktop read-only — COMPLETE / CERTIFIED LOCALLY
Windows UI Automation semantic tree plus bounded virtual-desktop PNG capture.

## P5-B — Semantic desktop input — COMPLETE LOCALLY
UIA `invoke` and `set_value` require one-use signed ExecutionAuthorization. Password/read-only controls are blocked. Certified only against a self-spawned lab window.

## P5-C — Coordinate input / hotkeys / window activation — NEXT
Add mouse, keyboard, hotkey and focus/window-control primitives behind stricter approval classes and lab-only certification before any remote exposure.

## P6 — Integrations
Generic SDK/adapters first. Lilith integration is blocked until Ainz is notified and explicitly approves touching Lilith.

## P7 — Hardening / Commercial Beta
Signed updates, elevated-worker isolation, tenant isolation tests, abuse controls, recovery, backups, security review, billing/entitlements and external penetration test before broad release.

## P8 — Productization / Hosted Vör — ACTIVE

Goal: evolve the certified owner pilot into a secure, auditable, multi-user hosted product without coupling the core protocol to one edge, billing provider or transport.

Execution order:

- **M0 — OAuth closeout:** persistent DCR clients, ephemeral authorization codes, UTF-8 UI, accurate `commander_status`, regression, deploy, restart-persistence proof and ChatGPT smoke.
- **M1 — Remote filesystem.write:** authorized roots, traversal/reparse defense, atomic write, expected digest/optimistic concurrency, bounded payloads, journal/rollback where applicable, authorization + execution audit and explicit approvals.
- **M2 — Remote terminal:** bounded ConPTY sessions, cwd policy, command/output/time budgets, cancel and explicit approval; never silently elevated.
- **M3 — Self-maintenance:** Vör can safely maintain/develop Vör without Desktop Commander for normal operations.
- **M4 — Tenant/account foundation:** User, Organization, Workspace, Device, OAuthClient, Session, Grant, Approval, Subscription, Entitlement, Usage and Audit with tenant isolation.
- **M5 — Usage + Entitlements:** append-only usage ledger, quotas separate from authorization, central entitlement service.
- **M6 — Web dashboard + onboarding.**
- **M7 — Billing sandbox/test mode only:** Stripe Billing, Checkout, Customer Portal, webhook verification and entitlement mapping in test mode.
- **M8 — Beta security/hardening.**
- **M9 — Pricing validation + product packaging.**
- **M10 — Public staging.**
- **M11 — Current OpenAI/App submission preparation after verifying current requirements.**
- **M12 — Production/cobros gate:** explicit owner approval required before production billing, destructive DNS changes or marketplace submission.

Current M0 state: **COMPLETE / LIVE PASS**. Persistent DCR, UTF-8 OAuth UI, live restart-persistence proof and ChatGPT `commander_status == P4-C/OAuth` are accepted against `mcp.vorcommander.app`.

Current M1 state: **COMPLETE / LIVE CERTIFIED**. Public write is exposed only as the signed two-step `prepare_write` + `commit_write` flow. The live canary proved native owner confirmation, one-use execution, replay rejection, content/precondition integrity, readback and audit completeness under a dedicated approval-only root.

Current M2 state: **COMPLETE / LIVE CERTIFIED**. Live remote terminal uses signed two-step `prepare_terminal` + `commit_terminal`, actor-bound `poll_terminal`/`cancel_terminal`, structured argv, canonical cwd confinement, bounded sessions/time/output and inline-eval elevation classification. Owner-approved live canaries passed completion/replay, cancellation, timeout, cwd rejection and elevated inline-eval classification; M1 signed-write regression and final audit-chain verification also passed.

Current M3 state: **LAB HANDOFF / ROLLBACK / CRASH-RECOVERY PASS / INVOCATION SURFACE NEXT**. `vor-maintenance` and `vor-maintainer` cover digest-bound plans, staged/current mutation detection, root confinement, atomic swap, rollback, prevalidated recovery, short-lived OWNER-signed maintenance approvals and one-use authorization consumption before stop/swap. Disposable Windows E2E now proves committed handoff, rollback after failed staged launch and recovery from an interrupted post-swap transaction. M3 is still not a blanket live self-update authority; controlled invocation/status is the next gate.

Current billing state: **SANDBOX WIRED / CHARGES OFF**. Stripe is the selected billing rail; `vor-gateway` can create test-mode hosted Checkout and Customer Portal sessions behind `billing.manage`, verifies test-mode webhook signatures, records idempotent sandbox subscription state and fails closed for unknown Stripe customers. Live Checkout, live Portal and production entitlement mutation remain blocked until M4/M5 backend authority, cross-tenant canaries and the M12 production/cobros approval gate are complete. See `STRIPE_BILLING.md`.
