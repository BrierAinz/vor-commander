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
