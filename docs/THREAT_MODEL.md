# Threat model P0

## Assets

- control de la workstation;
- filesystem y código fuente;
- identidad de dispositivo y claves privadas;
- sesiones autenticadas del navegador;
- secretos del sistema y del usuario;
- audit ledger;
- identidad, políticas y datos de tenants cloud.

## Trust boundaries

1. AI/MCP client -> Cloud Gateway.
2. Cloud Gateway -> Relay transport.
3. Relay -> Device Agent broker.
4. Broker -> normal workers.
5. Broker -> elevated worker.
6. Browser Bridge -> authenticated websites.
7. Tenant A -> shared cloud infrastructure -> Tenant B.

Ninguna frontera confía implícitamente en la anterior. Cloudflare/Tailscale pueden transportar identidad, pero no conceden capacidades Vör por sí mismos.## Primary threats

- T1: token or device credential theft.
- T2: malicious/compromised MCP client requests excessive capabilities.
- T3: prompt injection from files, web pages, terminal output or repositories.
- T4: command injection through tool arguments.
- T5: privilege escalation from normal worker to elevated execution.
- T6: browser session abuse for irreversible/public actions.
- T7: direct extraction of cookies, passwords or bearer tokens.
- T8: cross-tenant authorization or object-reference failure.
- T9: compromised Gateway attempting actions outside a session grant.
- T10: Device Agent self-update supply-chain compromise.
- T11: audit deletion/tampering to hide actions.
- T12: path traversal, symlink/junction/reparse-point escape.
- T13: reconnect/failover accidentally exposes a public listener.
- T14: denial of service through commands, process spawning or storage.
- T15: confused-deputy approval where UI description differs from executed action.
- T16: sensitive output copied into telemetry, logs or AI context.
- T17: billing webhook spoofing or cross-tenant subscription mapping grants hosted capacity to the wrong organization.

## Required mitigations before remote beta

- Device keys non-exportable where platform support permits; revocation must be immediate.
- Short-lived scoped session grants; audience and device binding checked server-side and locally.
- Policy evaluation again on the Device Agent: cloud approval alone is insufficient.
- `terminal.exec` requires structured argv; opaque shell-command strings fail policy closed.
- Known interpreter inline-eval flags are classified before execution and require elevated approval rather than inheriting ordinary terminal approval.
- In policy mode, `terminal.exec` may bypass a signature only when the executable is one of the configured absolute canonical `safe_executable_paths` and every argument matches exactly. Bare names resolve against that pinned list, never against `PATH`. Shell/control tokens (`;`, `|`, `&`, `<`, `>`, newlines), shell wrappers, `cmd /c`, and interpreter inline-eval forms never qualify. Strict mode disables the safe list.
- Safe-listed terminal work still runs through the bounded terminal worker: cwd must canonicalize inside an allowed root, reparse/network escape checks remain active, and timeout/output/session limits do not change. Audit records identify both `authority: "safe-list"` and `approval: "safe-list"`.
- Safe-listed Git commands receive the shared `vor-git` hardening: system/global/XDG configuration, inherited `GIT_*` variables and prompts are disabled; attributes, external diffs, text conversion, hooks, pager, fsmonitor and untracked cache are neutralized; and an alias for the requested subcommand from any remaining configuration source or include rejects execution. The same hardening is used by the dedicated `git.*` actions.
- The default safe list excludes `cargo check/test/clippy`, `npm test`, and `python|python3|py -m pytest`. Adding any of them manually is equivalent to authorizing arbitrary project-controlled code: Cargo can execute `build.rs`, wrappers and runners; npm executes package scripts and configuration; pytest imports `conftest.py` and plugins. Exact argv matching does not make these commands safe.
- Public reading and exploration tools reuse `vor-fs` and `vor-path`; they do not follow reparse points, do not expose sensitive paths, reject files whose Win32 handle reports `nNumberOfLinks > 1`, reject paths outside configured roots (including canonical/8.3 aliases), and enforce depth, result-count, file-size and elapsed-time ceilings. Treating observed hardlinks as sensitive deliberately trades availability for preventing a benign-looking in-root name from aliasing protected content. This is a best-effort application control: bypasses based on removing the other hardlink or racing validation require a pre-existing capability to create hardlinks in the allowed root, which Vör Commander does not grant. These controls are not an OS sandbox.
- Elevated worker has a separate IPC boundary and no ambient permanent admin token.
- Reparse points and canonical paths are resolved before filesystem policy decisions.
- Browser secret APIs are absent from the public tool surface by default.
- Approval payload includes exact actor, device, action, target and material parameters; execution binds to its digest.
- Tenant queries enforce organization scope at the persistence layer and service layer.
- Agent updates are signed and rollback-capable.
- Ledger events chain hashes; signed checkpoints are stored outside the mutable event stream.
- Logs use field-level redaction and secret-classification tests.
- Network failover is closed-by-default and never opens an inbound public port.
- Stripe webhook signatures are verified, billing events are idempotent and external billing IDs map to one organization before entitlements change.

## Security claim boundary

Application policy is a guardrail, not a sandbox. Security claims about containment require OS-enforced process/token/ACL boundaries and adversarial testing. P0 makes no claim that such containment already exists.
