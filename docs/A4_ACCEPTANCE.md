# A4 Acceptance — Local Browser Session Lab

Date: 2026-09-19
Status: **PASS_LOCAL_DISPATCH_E2E / NOT EXPOSED LIVE**

A4 delivers a local laboratory browser path using the existing Firefox/WebDriver/BiDi bridge and a canonical local dispatch path through policy, approval broker, dispatcher and audit. It does not expose browser control through MCP/live tools and does not use a personal browser profile.

## Environment

- Firefox: `C:\Program Files\Mozilla Firefox\firefox.exe`, version `156.0`.
- geckodriver: `D:\Proyectos\10_Active\vor-commander\state\drivers\geckodriver\0.37.1\geckodriver.exe`, version `0.37.1`.
- Lab root: `D:\Proyectos\10_Active\vor-commander\state\local\a4-lab`.
- Bridge harness: `scripts/local/invoke-a4-browser-lab.ps1`.
- Dispatch harness: `cargo test --locked --offline -p vor-dispatch a4_browser_session_enters_through_dispatcher_approval_and_audit -- --ignored --nocapture`.

## Security Invariants

- Sessions use disposable Firefox profile/download roots under the lab root.
- The client cannot choose arbitrary WebDriver/BiDi endpoints, profiles or download directories.
- Session operations are bound in the local harness to actor, device, session identity, element identity and document generation.
- Canonical dispatch operations are bound to signed approval challenge material and then revalidated by the browser worker against organization, actor, device and session owner.
- Cross-actor approvals, stale element references and out-of-scope navigation are rejected before effects.
- Approval replay is rejected by the broker before repeating the browser effect.
- `driver_ready` accepts only valid WebDriver status responses with `value.ready == true`.
- `close` only reports closed after confirmation and blocks further interactions after close/closing begins.
- Download evidence is operation-bound and includes size, SHA-256 and confined canonical path.
- Existing files, dangerous Windows names, traversal, alternate stream syntax and incomplete downloads are rejected.
- The semantic snapshot path is bounded and does not expose input `value` secrets.

## Evidence

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\local\invoke-a4-browser-lab.ps1`: **PASS**.
  - Preflight recorded Firefox/geckodriver paths and versions.
  - Real E2E: create two sessions, navigate fixture, observe, reject unapproved action, execute approved click, reject wrong actor, reject stale element, reject out-of-scope navigation, reject preexisting/dangerous/incomplete downloads, verify download hash/size/path, close and reject post-close interaction.
- `cargo test --locked --offline -p vor-dispatch a4_browser_session_enters_through_dispatcher_approval_and_audit -- --ignored --nocapture`: **PASS**.
  - Canonical E2E: `dispatch_proto_at` returns `approval_required`; signed approval executes `browser.session.use`; approved navigate/click/observe/download/close pass through dispatcher, broker and audit; replay returns `approval_replayed`; wrong actor returns `browser_approval_mismatch`; downloaded content hash is verified; disposable session root is removed after close.
- `cargo test --locked --offline -p vor-browser -- --nocapture`: **PASS**, 3 passed, 2 ignored by design.
- `cargo test --locked --offline -p vor-browser firefox_webdriver_and_bidi_roundtrip -- --ignored --nocapture`: **PASS**.
- `cargo test --locked --offline -p vor-process -- --nocapture`: **PASS**, including the corrected same-millisecond FILETIME identity fixture.
- `cargo test --locked --offline -p vor-dispatch -- --nocapture`: **PASS**, 25 passed, 1 ignored by design.
- `cargo test --workspace --locked --offline -- --nocapture`: **PASS**. Ignored by design: A4 explicit browser bridge/dispatch E2E, Firefox/BiDi roundtrip and 3 interactive desktop/UIA tests.
- `cargo fmt --all -- --check`: **PASS**.
- `git diff --check -- .`: **PASS**.
- `scripts/local/check-worktree-text.ps1`: **PASS**, selected/read 140 files, no disappeared files.
- `python -m unittest tests.test_check_worktree_text -v`: **PASS**.

## Limits

- A4 remains local-only. No live MCP/browser remote exposure was added.
- The dispatch E2E uses the canonical local policy/approval/broker/audit route, but it is still a lab route, not a deployed/live MCP browser tool.
- Network isolation is limited to explicit lab origin checks for primary navigation. Broader redirect/subresource containment remains a prerequisite before live exposure.
