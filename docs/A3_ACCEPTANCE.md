# A3 Acceptance — Controlled Process Termination

Date: 2026-09-19
Status: **PASS_LOCAL_HARDENED / NOT EXPOSED LIVE**

A3 adds a local approved execution path for terminating a specific synthetic process instance. It does not expose process termination through the public MCP surface and does not grant terminal cancellation authority over arbitrary processes.

## Security Invariants

- `process.list` and `process.inspect` remain read-only auto actions.
- `process.terminate` is accepted only through the approved-action path after broker authorization and approval consumption.
- The execution request binds actor, device, action and target PID through the sealed `ActionRequest`.
- The process instance identity is additionally bound to `pid`, `executable_name`, full `image_path` and native `created_at_windows_filetime_100ns`.
- Identity inspection opens only query/synchronize rights; approved execution opens terminate rights only for the already authorized effect path.
- The worker verifies running state, re-reads identity, checks process criticality and rejects protected control-channel/Vör component identities before termination.
- The same verified handle is held through `TerminateProcess` and bounded wait; no PID-only reopen is used between validation and effect.
- `WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_FAILED` and unexpected wait status are distinguished. `terminated=true` is returned only for confirmed `WAIT_OBJECT_0`; post-effect uncertainty is reported without a success receipt.
- Old/incomplete identity contracts are rejected as missing identity.
- Stale identity, native same-millisecond creation-time mismatch, expired approval, approval replay, already exited targets, access/open denial, identity query failure, critical/indeterminate criticality, termination failure, wait timeout, wait failure and current control process are rejected or reported deterministically.
- Synthetic tests use copied `cmd.exe` instances under temporary lab directories only.
- No live process, service, Vör agent, control plane or user process was terminated.

## Local Evidence

- `cargo test --locked --offline -p vor-process -p vor-dispatch -- --nocapture`: **PASS** via local MSVC `vcvars64.bat`.
  - `vor-dispatch`: 25/25.
  - `vor-process`: 15/15.
- A3-specific cases in `vor-dispatch`:
  - approved exact synthetic process termination succeeds once;
  - exact approval replay is rejected;
  - stale native creation-time identity is rejected without killing the process;
  - already finished process is rejected;
  - expired approval is rejected without killing the process;
  - current control process is rejected as protected.
- A3-specific cases in `vor-process`:
  - identity query uses query rights only;
  - OpenProcess/access denial and identity query failure are pre-effect rejections;
  - critical process and criticality query failure reject before terminate;
  - native FILETIME mismatch inside the same Unix millisecond rejects before terminate;
  - TerminateProcess failure is distinct from accepted-effect wait uncertainty;
  - wait timeout, wait failed and unexpected wait status after terminate are unconfirmed outcomes;
  - target already exited between validation and effect rejects before terminate;
  - control-channel identity rejects before terminate.
- M3 regression after cleanup hardening:
  `cargo test --locked --offline -p vor-maintainer -p vor-maintenance -p vor-approver -- --nocapture`: **PASS**.
- Full workspace regression:
  `cargo test --workspace --locked --offline`: **PASS**.
- Explicit untracked/new text verifier:
  `scripts/local/check-worktree-text.ps1`: **PASS**, selected/read 135 files; no disappeared files.

## Limits

- No MCP tool exposure was added for A3.
- Live exposure remains blocked by `G-ACCESS`; no real non-lab process termination is authorized.
- The current protected component check covers the current control process, Vör component executable/path identities and Codex control-channel path/name identity. Any future live exposure must first add an exact deployed-component inventory for the target host and an owner-approved tool contract.
