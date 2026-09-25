# P2 Browser Bridge — acceptance

Target: Firefox local automation without access to existing user profiles.

## Runtime

- [x] Firefox 156.0 detected from official installation.
- [x] geckodriver 0.37.1 cached under ignored `state/`.
- [x] Win64 archive SHA-256 verified before extraction.
- [x] geckodriver binds to an ephemeral 127.0.0.1 port.
- [x] Dedicated `state/browser/profiles/Vor-Automation` exists.
- [x] Dedicated profile is not registered in Firefox `profiles.ini`.

## Capabilities

- [x] WebDriver session requests and receives `webSocketUrl`.
- [x] Navigate, title and page-source/DOM retrieval.
- [x] CSS find, click, text input and element text.
- [x] Fixed semantic snapshot for interactive/accessibility-relevant elements.
- [x] Screenshot returned as validated PNG bytes.
- [x] Download directory is isolated and completion can be awaited safely.
- [x] BiDi `session.status` roundtrip succeeds.

## Security

- [x] Semantic snapshot does not read form `value`.
- [x] No arbitrary JavaScript API is public.
- [x] No cookie/password/localStorage/sessionStorage extraction API exists.
- [x] Policy still marks `browser.session.use` as APPROVAL.
- [x] Policy still marks `browser.secret.extract` as DENY.
- [x] Browser operations are not exposed by the Device Agent network listener.
