# Capability Matrix

Mission: `VOR-COMMANDER-CLOSEOUT-20260919`
Updated: 2026-09-25

| Capability | Implemented in source | Local tests | Deployed/live evidence | Visible in this client | Approval state | Certification state |
|---|---|---|---|---|---|---|
| `commander_status` | Yes; tenant mode filters remote device IDs/count/recommendation by grant + device/workspace authority | Gateway tools/list regression; `mcp_status_filters_connected_devices_by_tenant_authority` | Live response observed previously; new tenant filter not deployed | Yes | Read-only | PASS_LOCAL_STATUS_FILTER / NOT_DEPLOYED |
| `filesystem.read` / `read_file` | Yes | Existing gateway/dispatch coverage | Live remote read documented previously | Yes | Read-only | PASS for inspection |
| `filesystem.list` / `list_directory` | Yes; bounded depth/entries and links/junctions skipped | Filesystem worker + gateway tool-list/E2E coverage | Not deployed | Source only | Read-only, audited | PASS_LOCAL / NOT_DEPLOYED |
| `filesystem.search_files` / `search_files` | Yes; bounded glob search | Filesystem worker coverage | Not deployed | Source only | Read-only, audited | PASS_LOCAL / NOT_DEPLOYED |
| `filesystem.search_content` / `search_content` | Yes; literal/regex; UTF-8, BOM-tagged UTF-16, Windows-1252; binary/size skip counters; file/result/time/line limits. Match columns are one-based byte offsets in decoded UTF-8, including for UTF-16 sources. | Filesystem worker + private transport E2E coverage | Not deployed | Source only | Read-only, audited | PASS_LOCAL / NOT_DEPLOYED |
| `filesystem.info` / `file_info` | Yes; metadata only | Filesystem worker coverage | Not deployed | Source only | Read-only, audited | PASS_LOCAL / NOT_DEPLOYED |
| `git.status` | Yes | Existing dispatch/gateway coverage | Live git status observed for repo | Yes | Read-only | PASS for inspection |
| `git.diff` | Yes | Existing dispatch/gateway coverage | Tool visible; not used for mutation | Yes | Read-only | PASS for visibility |
| `process.list` | Yes | Existing dispatch/gateway coverage | Live process list observed | Yes | Read-only | PASS for inspection |
| `process.inspect` | Yes | Existing dispatch/gateway coverage | Tool visible; individual inspect available | Yes | Read-only | PASS for visibility |
| `filesystem.write` via `prepare_write`/`commit_write` | Yes in local source | 2026-09-19 M1 regression passed locally | M1 acceptance says live certified | No | Requires signed approval | DISCREPANCY: not client-certified here |
| Diff-based `filesystem.write` via `prepare_edit`/`commit_write` | Yes; device-side ordered exact replacements (max 20), occurrence guard, bounded unified diff, original encoding/newlines and device-observed hash precondition; same root/reparse/policy boundary | Worker single/multiple/count/CRLF/1252/root/junction coverage plus real router/private-mTLS race E2E | Not deployed | Source only | Same signed `filesystem.write` approval | PASS_LOCAL / NOT_DEPLOYED |
| `terminal.exec` via `prepare_terminal`/`commit_terminal` | Yes in local source | 2026-09-19 M2 regression passed locally | M2 acceptance says live certified | No | Requires signed approval | DISCREPANCY: not client-certified here |
| `terminal.poll` | Yes in source/live status | Existing M2 docs | Live status advertises scope | No | Owned session only | DISCREPANCY: status advertises but client tool absent |
| `terminal.cancel` | Yes in source/live status | Existing M2 docs | Live status advertises scope | No | Owned session only | DISCREPANCY: status advertises but client tool absent |
| Self-maintenance status | Yes | New E2E regression passed this run | Not live-applied | CLI local only | Read-only status | PASS_LOCAL |
| Self-maintenance apply/recover | Yes | Existing M3 lab E2E passed | No live M3 update applied | Not visible | OWNER approval required | APPROVAL_PACKAGE_PENDING |
| Process terminate | Yes in local source via approved dispatch path | A3 hardened local suite passed: exact image path + native FILETIME identity, split query/terminate rights, criticality/protected identity checks, deterministic failure doubles | Not deployed/exposed | No public MCP tool | Requires signed approval | PASS_LOCAL_HARDENED / NOT_EXPOSED_LIVE |
| Browser remote | Existing local `vor-browser` bridge plus canonical `browser.session.use` dispatch path | A4 bridge E2E and A4 dispatcher/broker/audit E2E passed with real Firefox/geckodriver; workspace keeps E2E ignored by default and runners execute them explicitly | Not exposed | No | Effects require signed approval | PASS_LOCAL_DISPATCH_E2E / NOT_EXPOSED_LIVE |
| Desktop gradual remote | Local P5 docs only | Not assessed | Not exposed | No | Requires scoped policy | NOT_ASSESSED |
| Multi-tenant hosted product | Persisted local tenant model, scoped grants, tenant audit reader, durable approval claims, authenticated HTTP tenant checks, tenant-scoped admin revoke, signed workspace binding, tenant-required signer mode, HTTP/MCP + private mTLS post-prepare authority revalidation, workspace-bound terminal sessions and tenant-filtered status projection exist | M4 C04/C13 slice passed focal tests: status visibility by tenant over HTTP/MCP + private mTLS with two simultaneous devices; dispatcher terminal precondition now observes manager `Completed` before wrong-workspace poll. C08-C10 and C17/C18 regressions re-ran green. Browser/session/receipt/audit disclosure, full HTTP/MCP terminal/session object matrix, relay parity and persistence-fault matrix remain pending | Not deployed | N/A | Server-side auth required; no OWNER/global tenant fallback | IN_PROGRESS_LOCAL / NOT_DEPLOYED |
| Billing sandbox | Sandbox billing store plus authenticated-org checkout and portal tenant boundary | Gateway billing tests passed; live charges off and cross-tenant checkout rejects before provider call | Charges off | N/A | Sandbox only; commercial state is not authority | PASS_LOCAL_HTTP_BOUNDARY / M5_PENDING |

Notes:

- A live advertised scope is not treated as a visible client tool.
- A local PASS is not treated as live certification.
- Any mutation of the real agent, services, public exposure or billing remains gated by explicit owner approval.
