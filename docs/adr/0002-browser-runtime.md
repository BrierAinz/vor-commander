# ADR-0002 — Browser runtime

Status: Accepted for P2; reversible before public API freeze.
Decision: D27C.

## Options

A. Python Selenium sidecar. Mature, but adds Python runtime/package lifecycle.
B. Node Selenium sidecar. Mature enough, but adds Node runtime/package lifecycle.
C. **Selected:** Rust bridge + pinned geckodriver + WebDriver Classic/BiDi directly.
D. Direct Firefox internal remote protocol without geckodriver. Too coupled to browser internals.

## Rationale

- Keeps the shipped Device Agent primarily Rust.
- geckodriver is Mozilla's W3C WebDriver proxy and is independently replaceable.
- Classic WebDriver covers deterministic request/response operations.
- The negotiated `webSocketUrl` provides WebDriver BiDi events/commands.
- Selenium remains a compatibility/reference implementation, not a runtime dependency.

## Security boundary

- geckodriver binds only to 127.0.0.1.
- Browser profile and downloads live under ignored local `state/`.
- No arbitrary JavaScript API is exposed in P2.
- No cookies, password store, localStorage or sessionStorage extraction API exists.
- Browser worker dispatch remains disconnected from the Agent listener until grants exist.
