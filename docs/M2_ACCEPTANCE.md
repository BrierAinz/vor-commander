# M2 Acceptance — Remote terminal

Date: 2026-09-19
Status: **COMPLETE / LIVE CERTIFIED**

M2 adds a bounded remote terminal path without exposing an unrestricted shell or implicit elevation.

## Security invariants

- Remote process creation is accepted only as `terminal.exec` inside the signed approved-action path.
- There is no direct `terminal_exec` MCP tool. Public/local-source MCP uses the two-step `prepare_terminal` + `commit_terminal` flow.
- Command input is structured `argv: Vec<String>`; remote execution does not accept an opaque shell command string.
- The approval challenge is bound to the exact canonical request, including cwd, argv, timeout, output budget, terminal dimensions, policy id, capability, expiry and nonce.
- A normal terminal command requires local policy `Approval`.
- Known interpreter/shell inline-eval forms are classified separately and require `elevated` approval authority. Missing or malformed argv fails policy closed.
- The approver UI displays cwd, structured argv, actor, device, policy, required capability, request id, timeout and output budget before signing.
- The owner signing key remains DPAPI-protected and separate from gateway/agent execution authority.
- Cwd is canonicalized and must remain under a configured allowed root before process creation.
- Timeout is bounded; the local worker maximum is 120 seconds.
- Output is bounded; the worker maximum is 1 MiB and the MCP request path uses a stricter JSON-safe cap.
- Terminal dimensions and argv count/bytes are bounded.
- A timeout, cancellation or output-limit violation terminates the spawned process.
- Sessions are asynchronous. `commit_terminal` starts one approved process and returns an opaque random session id.
- A terminal session is bound to organization + actor + device. A different actor cannot poll or cancel it.
- `terminal.poll` and `terminal.cancel` are policy-auto only for an already-existing owned session. They cannot authorize or start a new process.
- Finished sessions are returned once through poll and then removed by the dispatcher.
- At most 4 remote terminal sessions are retained by one dispatcher.
- Approval remains one-use; replaying the same signed `commit_terminal` request is rejected.
- No terminal path grants elevation. An elevated approval classification authorizes the exact request only; it does not create an elevated Windows token.

## MCP surface in local source

Approved start:
- `prepare_terminal`
- `commit_terminal`

Owned session control:
- `poll_terminal`
- `cancel_terminal`

The local `tools/list` regression requires all four names above and continues to reject direct `terminal_exec`, direct `write_file`, `process_terminate` and browser-use shortcuts.

## Transport coverage

- Private gRPC/mTLS advertises `terminal.exec.approval`, `terminal.poll` and `terminal.cancel`.
- WSS/Protobuf advertises the same capabilities.
- Gateway mTLS E2E covers prepare → signed commit → session poll → completed result plus approval replay rejection.
- WSS E2E specifically covers:
  - approved `terminal.exec` using structured `where.exe cmd.exe`;
  - remote poll until `completed`;
  - a second approved long-running session;
  - remote cancel;
  - poll until `cancelled`.

Transport only carries the request. Device policy, approval verification, budgets, cwd confinement and session ownership remain enforced at the worker.

## Local evidence

- `vor-policy`: **13 passed / 0 failed**.
  - structured argv required;
  - inline evaluation elevated;
  - positional script arguments do not falsely escalate;
  - legacy policy without `inline_eval` defaults fail-safe to elevated approval.
- `vor-terminal`: **12 passed / 0 failed**.
  - structured Windows argv encoding;
  - cwd confinement;
  - timeout;
  - output limit;
  - external cancellation;
  - ConPTY execution;
  - session start/poll/remove;
  - owner-bound cancel and session limit.
- `vor-dispatch`: **20 passed / 0 failed** in the final workspace suite.
  - signed terminal preparation/start;
  - approval authority checks;
  - cwd rejection;
  - timeout/output-limit state mapping;
  - actor-bound cancel observed through poll;
  - existing M1 filesystem-write regressions remain green.
- `vor-approver`: **6 passed / 0 failed**.
  - terminal summary shows structured command and budgets;
  - malformed/missing argv rejected;
  - approver refuses actions outside filesystem.write and terminal.exec.
- `vor-gateway`: **11 passed / 0 failed**.
  - mTLS MCP E2E exercises terminal prepare/commit/poll;
  - tools/list remains authenticated and explicitly checks the controlled terminal surface.
- `vor-private-grpc`: **6 passed / 0 failed**.
- `vor-relay`: **2 passed / 0 failed**.
- `vor-remote`: **6 passed / 0 failed**; the WSS dispatch E2E now includes terminal start/poll/cancel.
- `cargo test --workspace --locked --offline`: **PASS** on the final frozen M2 source tree.
- `cargo fmt --all -- --check`: **PASS** on the final frozen M2 source tree.
- `git diff --check -- .`: **PASS** on the final frozen M2 source tree.

The four pre-existing interactive Firefox/UIA tests remain intentionally ignored.

## Live certification

M2 was deployed to the live owner pilot after fresh explicit OWNER authorization on 2026-09-19. Windows promotion completed in `job_a9a38f9942e24e9e`; VPS atomic promotion/restart completed in `job_908552222c9346b1` with the pre-M2 binaries retained for rollback.

Live identities after promotion and cleanup:

- VPS `vor-control-plane` SHA-256:
  `e57989d9087e8a7594820920a25c542f79a80893881d6d61d9a987440495bb2c`
- Windows `vor-agent.exe` SHA-256:
  `df4e28ae075daec7d86ba71d1d03eeb663ca77fcf8856825656e911208138ce2`
- Windows `vor-approver.exe` SHA-256:
  `ce661a89674dc7a055336c78da2e979f292fa6429c1aa1a785da380ad92222f4`

Rollback was preserved before promotion:

- VPS pre-M2 control plane SHA-256:
  `7a484259d8120ed2d6f02481776518235cb594aaacd2a08b48ae48de777bd94b`
- Windows pre-M2 agent SHA-256:
  `0eba67b1d9511f782cc6a90bd7d5651cced8738524f2f3cec70e61627432a7dc`
- Windows pre-M2 approver SHA-256:
  `3be1cd69404420254d7c12cc25591538dbbfdd65eea8c87e715eb4a4ad8b94c1`

Post-cleanup `commander_status` is:

- `remote_approved_scope`: `filesystem.write`, `terminal.exec`
- `remote_scope`: `filesystem.read`, `git.status`, `git.diff`, `process.list`, `process.inspect`, `terminal.poll`, `terminal.cancel`
- direct `terminal_exec` remains absent from the public MCP tool surface.

## Live canary evidence

All M2 live canaries used exact request-bound native `owner-local` approval where execution was required.

1. Safe bounded terminal:
   - `cmd.exe /D /Q /C "echo VOR_M2_LIVE_OK"`
   - commit: `ok`
   - final state: `completed`
   - exit code: `0`
   - expected output observed
   - exact approval replay: `approval_replayed`
2. Cancellation:
   - long-running `ping.exe 127.0.0.1 -n 10`
   - owner-bound `terminal.cancel`
   - final state: `cancelled`
   - error code: `terminal_cancelled`
   - replay rejected.
3. Timeout:
   - same bounded ping with `timeout_ms=50`
   - final state: `timed_out`
   - error code: `terminal_timeout`
   - replay rejected.
4. Cwd confinement:
   - request used cwd `C:\Windows`, outside the authorized `D:\Proyectos` root
   - signed commit returned `terminal_error`
   - audit outcome was `worker_failed` before process start
   - replay rejected.
5. Inline evaluation:
   - `python.exe -c ...`
   - prepare returned `required_capability=elevated`
   - no commit was performed, proving classification without silently creating an elevated process.
6. M1 regression after M2:
   - signed `filesystem.write` commit: `ok`
   - exact readback: `ok`
   - exact approval replay: `approval_replayed`.

## Live audit and cleanup

Final device audit verification after the M1 regression:

- records: **199**
- last sequence: **199**
- last record hash: `80e0af7561b439c8196df438da68252abddfbac907af14368299b9d85e86bdb4`
- SHA-256 audit chain: **valid**
- SQLite representation == JSONL representation: **exact**
- approval challenge, approval verification, approval consumption, terminal start/poll/cancel and filesystem-write events are present in the live ledger.

The temporary canary grant and the temporary cleanup-admin grant were both explicitly revoked. Remote canary grant/request/approval scratch files and the temporary canary gateway helper were removed. `vor-control-plane.service` remained active, the M2 agent remained connected over private mTLS and remote `git.status` remained healthy after cleanup.

M2 is therefore **COMPLETE / LIVE CERTIFIED**.
