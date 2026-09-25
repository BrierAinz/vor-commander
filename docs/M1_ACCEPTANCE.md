# M1 Acceptance — Remote filesystem.write

Status: **COMPLETE / LIVE CERTIFIED**

M1 adds an approved remote write execution path without weakening the default read-only remote surface.

## Security invariants

- Normal remote dispatch remains limited to `filesystem.read`, `git.status`, `git.diff`, `process.list` and `process.inspect`.
- `filesystem.write` is accepted only inside `ApprovedActionRequest`.
- The device re-evaluates local policy and requires the resulting decision to be `Approval`; a local `Auto` rule is not sufficient for remote approved execution.
- Approval is Ed25519 signed and bound to request id, canonical envelope digest, policy id, required capability, expiry and approval nonce.
- Approval consumption is one-shot through `ExecutionAuthorization`; replay is rejected.
- Only configured authorized filesystem roots are writable.
- Parent traversal and Windows reparse-point components are rejected.
- The requested content SHA-256 is part of the authorized envelope and is verified before writing.
- Approved writes require `expected_target_sha256`: either the current 64-hex SHA-256 or the literal `absent` for create-if-absent.
- Target precondition is checked before staging and immediately before replacement.
- Write payload is bounded to 1 MiB decoded content.
- Replacement is journaled and uses a temp file, flush, backup when replacing, atomic replacement and post-write digest verification.
- Authorization, approval verification/consumption, worker failure and successful execution are audit events.
- Agent trusted-approver configuration contains only public Ed25519 keys, a bounded explicit authority (`approve`, `elevated`, `owner`) and no private key material.
- Approver authority is monotonic: normal approval requires `approve`, an `elevated` policy capability requires `elevated` or `owner`, and `owner`/`full_owner` requires `owner`. Unknown required capabilities fail closed.
- A valid signature from a trusted key is insufficient when that identity lacks the policy-required authority.

## Transport coverage

Both private mTLS/gRPC and WSS+Protobuf can carry `ApprovedActionRequest`. The transport does not itself grant write authority; execution remains device-policy + signature gated.

## Local evidence

- `cargo test -p vor-private-grpc --offline`: **5 passed / 0 failed**, including signed approved write over mTLS.
- `cargo test -p vor-remote -p vor-relay -p vor-dispatch -p vor-fs --offline`: **PASS**.
  - vor-dispatch: 10/10 at the first integration pass.
  - vor-fs: 5/5.
  - vor-relay: 2/2.
  - vor-remote: 6/6.
- Additional dispatch regressions:
  - signed, preconditioned, one-shot write;
  - approval replay rejection;
  - stale target digest rejection;
  - create only when target is absent;
  - payload over 1 MiB rejection.
- `cargo test -p vor-dispatch --offline`: **12 passed / 0 failed** after those regressions.
- `cargo fmt --all -- --check`: **PASS** after applying the single mechanical formatting change reported by the first check.
- Post-authority `cargo test --workspace --locked --offline`: **PASS / exit 0**. The four pre-existing interactive Firefox/UIA tests remain intentionally ignored.
- Authority hardening targeted suite (`vor-approval`, `vor-dispatch`, `vor-approver`, `vor-agent`): **PASS / exit 0**. It proves `approve < elevated < owner`, owner satisfies lower approval requirements, elevated cannot satisfy owner, and unknown required capabilities fail closed.
- `cargo fmt --all -- --check`: **PASS** after the authority change.
- `git diff --check -- .`: **PASS** after the authority change.
- Hardened Windows release builds: `vor-agent.exe` SHA-256 `0eba67b1d9511f782cc6a90bd7d5651cced8738524f2f3cec70e61627432a7dc`; `vor-approver.exe` SHA-256 `55a9b5b1e05b3c975412800bceced9c53914367e31b6aad8be356b02b30a6199`.
- The hardened private agent is live and registered (`vor-agent.exe`, PID observed via device process inspection). Read-only remote `git.status` succeeded after the restart.

## Live certification evidence

- M1 Linux `vor-control-plane` clean release build: **PASS** using an isolated Cargo target. Reusing the M0 target was rejected after stale generated/interface artifacts caused a false compile failure.
- Live M1 binary SHA-256: `7a484259d8120ed2d6f02481776518235cb594aaacd2a08b48ae48de777bd94b`.
- Pre-M1 rollback binary is preserved at `/opt/vor-commander/bin/vor-control-plane.pre-m1-20260918-1804`, SHA-256 `f58736832fc5a86fa2ddb7ee0c8f1ffa9195b791360385ef11a20cb05806febb`.
- `vor-control-plane.service` restarted successfully and remains active after the M1 deploy.
- Live `commander_status` advertises `remote_approved_scope=["filesystem.write"]` while normal `remote_scope` remains read-only (`filesystem.read`, `git.status`, `git.diff`, `process.list`, `process.inspect`).
- The current ChatGPT connector schema remains read-only and does not expose `prepare_write` / `commit_write` as typed tools in this session; that client limitation is not treated as M1 acceptance evidence.

## Post-stage source hardening — not deployed

The working tree contains an additional terminal-policy hardening that is intentionally **not** part of the live M1 binary yet:

- `terminal.exec` requires structured `parameters.argv` as a non-empty array of strings; missing or malformed argv fails policy closed.
- Known interpreter inline-eval forms are classified separately and use `terminal.inline_eval`.
- `terminal.inline_eval` defaults to `elevated_approval`, including `python -c`, `node -e/--eval`, `perl/ruby -e`, `osascript -e` and PowerShell `-Command/-EncodedCommand`.
- Interpreter parsing stops at a positional script/input boundary, so script arguments such as `python script.py -c value` do not falsely escalate.
- Older YAML without an explicit `inline_eval` field defaults to `elevated_approval` for fail-safe compatibility.
- This hardening must not be treated as live evidence until a later controlled build/deploy. It does not widen normal `remote_scope` or expose terminal through public MCP.

## Live canary evidence

- Public MCP exposed `prepare_write` and `commit_write`; unsafe direct tools `write_file`, `terminal_exec` and `process_terminate` were absent.
- The dedicated canary root `D:\\Proyectos\\10_Active\\vor-commander\\state\\local\\m1-canary` matched the more-specific `write: approval` rule while ordinary `D:\\Proyectos` behavior remained unchanged.
- `prepare_write` returned `approval_required` and did not create the target.
- Native Windows owner confirmation produced an Ed25519 approval from `owner-local`; the private signing key remained DPAPI-protected and only the public key was loaded by `vor-agent`.
- `commit_write` returned `ok`; readback matched the committed bytes and reported content SHA-256 `e24eb36ae6666bea05393a044c77ed849b03b1d1a5a08428b4421a6c13a13400`.
- Reusing the exact same approval returned `approval_replayed`.
- Live audit for request `mcp-write-5ab8fb59e4e86f9a25451389a28008d6` recorded sequences 57–63, including `approval_challenge_issued`, `approval_verified`, `approval_consumed` and `executed`.
- Live readback recorded sequences 64–65 as `auto` then `executed`.
- Temporary live bearer/canary transport files were removed after the run.
- Post-canary `cargo test --workspace --locked --offline`, `cargo fmt --all -- --check` and `git diff --check -- .` passed.

## Certification result

M1 is **COMPLETE / LIVE CERTIFIED** as of 2026-09-18. The public write surface remains two-step and signed; no boolean approval shortcut exists. Normal remote scope remains read-only, while approved remote scope is limited to `filesystem.write`.

The next productization gate is M2 remote terminal. Terminal remains unexposed remotely until its bounded session, cwd, timeout/output budget, cancellation, policy classification and signed-approval gates are implemented and certified.
