# M3 Acceptance — Self-maintenance

Date: 2026-09-19
Status: **LOCAL / LAB CERTIFIED / APPROVAL_PACKAGE_PENDING / LIVE SELF-UPDATE OWNER GATE PENDING**

M3 adds a local self-maintenance path so Vör can prepare and apply its own agent updates without relying on Desktop Commander, while preserving an explicit OWNER approval boundary before process stop or binary replacement.

## Security invariants

- Read-only `check-plan` requires no approval and performs no mutation.
- `prepare-approval` validates the exact plan and emits a canonical signed-action request plus short-lived approval challenge; it does not stop processes or replace binaries.
- `queue-update`, `apply-update` and `recover` require:
  - exact plan SHA-256;
  - canonical request file;
  - signed approval file;
  - trusted approver registry.
- Maintenance policy is fixed to `maintenance-local` with `required_capability=owner`.
- The approval request binds:
  - maintenance action (`maintenance.apply` or `maintenance.recover`);
  - target executable;
  - staged executable;
  - allowed root;
  - current PID;
  - expected current SHA-256;
  - expected staged SHA-256;
  - exact plan SHA-256;
  - expiry and nonce.
- OWNER authority is verified with the same Ed25519 approval infrastructure used by M1/M2.
- A reviewer with ordinary `approve` authority cannot authorize maintenance.
- The approval UI displays the action, target, staged path, allowed root, PID, policy, OWNER capability and all material SHA-256 values before signing.
- Authorization is consumed with an atomic `create_new` marker **before** process termination or binary swap. Replaying the same approval fails closed.
- A different maintenance action cannot reuse the same signed approval.
- Plan mutation after signing is rejected by plan SHA-256 verification.
- Current target and staged executable digests are rechecked before swap.
- Staged mutation after transaction begin is detected before replacement.
- Allowed-root confinement remains canonical-path based.
- Recovery validates the rollback backup digest **before** removing/replacing the current target.
- Rollback and recovery remain conservative and journaled.
- Restart argv/environment counts and byte budgets remain bounded.
- The local lab cleanup does not terminate a process based only on reopening a PID at drop time. Relaunched lab instances are handled with a process handle opened after result validation; when image identity cannot be queried reliably, the guard waits for natural bounded exit instead of killing an unvalidated PID.
- This milestone does not grant remote blanket self-update authority, unattended OWNER approval or live service restart authority.

## Local CLI flow

1. Validate plan:
   `vor-maintainer check-plan --plan FILE --plan-sha256 SHA256`
2. Inspect material/journal/result state without mutation:
   `vor-maintainer status --plan FILE --plan-sha256 SHA256`
3. Prepare OWNER approval:
   `vor-maintainer prepare-approval --plan FILE --plan-sha256 SHA256 --action apply|recover --actor ID --device ID --request-out REQUEST.b64 --challenge-out CHALLENGE.json`
3. Sign with the existing native `vor-approver`.
4. Queue/apply/recover with the request, approval and trusted approver registry.
5. The updater consumes the exact approval before any stop/swap and records transaction state/results.

## Local evidence

- `vor-approver`: **8 passed / 0 failed**.
  - existing M1/M2 summaries remain valid;
  - maintenance OWNER summary exposes plan material;
  - missing maintenance material is rejected.
- `vor-maintainer`: **8 passed / 0 failed**.
  - exact OWNER approval verifies;
  - non-owner authority rejected;
  - plan mutation after approval rejected;
  - cross-action reuse rejected;
  - consumed approval cannot replay;
  - stale process identity is rejected;
  - already exited verified process is rejected.
- `vor-maintenance`: **10 passed / 0 failed**.
  - atomic swap/commit;
  - rollback;
  - stale current digest rejection;
  - staged mutation rejection;
  - root confinement;
  - conservative recovery;
  - mutated backup rejected before target replacement;
  - plan-file digest enforcement;
  - status inspection across ready, validated, swapped, committed and rolled_back states;
  - inconsistent material and tampered journal rejection.
- Targeted command:
  `cargo test -p vor-maintenance -p vor-maintainer -p vor-approver --locked --offline`: PASS.
- Disposable Windows lab E2E: **4 passed / 0 failed**.
  - owner-approved handoff: running temp `cmd.exe` copy is stopped, staged digest is committed, new disposable process is healthy, journal = `validated -> swapped -> committed`;
  - failed staged launch: invalid staged image fails after swap, exact old digest is restored and relaunched, result = `rolled_back`, journal = `validated -> swapped -> rolled_back`;
  - interrupted-swap recovery: transaction is deliberately dropped after `swap()` and before commit; a separate OWNER-signed `maintenance.recover` restores the verified backup, removes the backup, relaunches the old image and records `rolled_back`.
  - abandoned swapped status inspection: transaction is deliberately dropped after `swap()`; `vor-maintainer status` reports `observed_state=swapped`, `journal_state=swapped`, staged target digest and current backup digest without changing target, backup, journal or result material.
  - every process/path is created under a temporary directory; the real Vör agent is never opened, stopped, replaced or restarted.
  - lab approvals use an ephemeral Ed25519 OWNER key generated inside the test, never the real owner key.
- Lab command:
  `cargo test -p vor-maintainer --locked --offline -- --nocapture`: PASS (6 unit + 3 Windows E2E).
- Updated targeted command:
  `cargo test --locked --offline -p vor-maintenance -p vor-maintainer -p vor-approver -- --nocapture`: PASS on 2026-09-19 in local Work after cleanup hardening. Results: `vor-approver` 8/8, `vor-maintainer` unit 8/8, Windows `lab_e2e` 4/4, `vor-maintenance` 10/10, doc-tests 0.

## Live state

M2 remains the certified live runtime. M3 changes are source/local only.

No M3 self-update was applied to the live Windows agent. No M3 restart, binary replacement, automatic approval, or service mutation was performed.

## Remaining M3 gates

1. Decide and implement the eventual invocation surface for maintenance (local CLI / controlled MCP action) without granting raw updater authority. The surface must expose preparation/status separately from the OWNER-approved apply/recover boundary.
2. Prepare an exact approval package before asking for G-LIVE/OWNER: candidate path, target hash, staged hash, plan SHA-256, scope, health checks, rollback path and recovery command.
3. Require a fresh explicit OWNER confirmation before any M3 live self-update/restart test against the real agent.
4. Only after the controlled invocation surface, exact approval package and live gates pass may M3 be marked COMPLETE / LIVE CERTIFIED.

## Final local checks

- `cargo fmt --all -- --check`: **PASS** on 2026-09-19 after abandoned-journal status regression.
- `git diff --check -- .`: **PASS** on 2026-09-19 after abandoned-journal status regression.
- `cargo test --workspace --locked --offline`: **PASS** on 2026-09-19 after abandoned-journal status regression. Ignored by design: 1 Firefox/WebDriver test and 3 interactive desktop/UIA tests.
