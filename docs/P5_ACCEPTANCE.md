# P5 Desktop Computer Use — acceptance

## P5-A read-only
- UI Automation is the primary semantic source.
- Tree traversal has hard depth/node limits.
- Virtual-desktop PNG capture has a hard pixel limit and RAII GDI cleanup.
- No read-only desktop data is remotely exposed by default.

## P5-B semantic input
- Every mutating desktop operation requires `ExecutionAuthorization`, never plain `Authorization`.
- `ExecutionAuthorization` is non-clonable, has private fields and is consumed by one operation.
- Broker requires a prior audited `APPROVAL`, verifies Ed25519 binding, and persists `approval_consumed` before execution.
- Consumption is keyed by request ID plus envelope digest and survives ledger reopen.
- `desktop.invoke` uses UIA InvokePattern.
- `desktop.set_value` uses UIA ValuePattern.
- PID, AutomationId and value come only from the signed envelope parameters.
- Password elements and read-only values are rejected.
- UIA target search is bounded.

## Live certification
- Bounded interactive UIA snapshot: PASS.
- Virtual-desktop PNG: PASS.
- Self-spawned WinForms lab `set_value` + `invoke` with separate signed approvals: PASS.

## Still blocked
- Coordinate mouse input.
- Keyboard/SendInput and global hotkeys.
- Window focus/activation mutations.
- Remote MCP exposure of any P5 capability.
