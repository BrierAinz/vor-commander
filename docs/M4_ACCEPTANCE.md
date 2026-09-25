# M4 Acceptance - Local Tenant Isolation

Date: 2026-09-20
Status: **IN_PROGRESS_LOCAL / NOT_DEPLOYED**

M4 now has hardened local tenant/account primitives, authenticated HTTP gateway enforcement, signed workspace binding for tenant prepare/commit, tenant-scoped signer revocation/rotation primitives and one integrated HTTP/MCP + private transport E2E path with tenant/workspace authority. It is not yet a full `PASS_LOCAL_TENANT_ISOLATION`: revocation between prepare/commit through the full HTTP/MCP path, tenant-scoped session/receipt/audit readers and broader cross-tenant negative coverage remain open.

## Entity Map

| Entity | Store/type | Current relationship |
|---|---|---|
| User | `vor_auth::TenantStore` / `UserRecord` | Global user identity, tenant rights only through membership. |
| Organization | `TenantStore` / `OrganizationRecord` | Security and billing tenant. |
| Membership | `TenantStore` / `MembershipRecord` | User role per organization; revocable and persisted. |
| Workspace | `TenantStore` / `WorkspaceRecord` | Belongs to one organization. |
| Device | `TenantStore` / `TenantDeviceRecord` | Belongs to one organization and explicit workspaces; revocable. |
| OAuthClient | `GrantStore` / `OAuthClientRecord` | Public client metadata; not tenant membership. |
| Session/Grant | `GrantStore` / `GrantRecord` | Persisted token authority now includes `organization_id` and optional workspace set. |
| Approval | `vor-approval` + `vor-core` | Signed request digest; broker consumption now has a durable SQLite claim. |
| Audit | `vor-audit::Ledger` | Events carry organization/actor/device/request/action/outcome; tenant-scoped reader added. |
| Subscription/Entitlement/Usage | `TenantStore` records plus gateway billing sandbox | Commercial state remains non-authority; checkout rejects body org outside authenticated grant. |

## Role Matrix

| Role | Tenant operation | Device/workspace effect | Global OWNER/elevation |
|---|---|---|---|
| Viewer | Read-only tenant context where explicitly allowed | No implicit device effect | No |
| Operator | May operate assigned workspace/device when grant and policy allow | Only assigned workspace/device | No |
| Admin | Tenant administration in its organization | Still bounded by device/workspace and policy | No |

## Gate Matrix G1-G6

| Gate | Status | Evidence | Remaining limitation |
|---|---|---|---|
| G1 persisted authority coherence | PASS_LOCAL | `vor-auth` 13/13 covers stale grant/tenant writers, prune/pairing paths, missing state and invalid JSON fail-closed. | Fault injection is file-level; no OS-level forced partial write harness. |
| G2 concurrent ledger/claims | PASS_LOCAL | `vor-audit` 6/6 includes 8 concurrent independent ledger writers with barrier, unique chain after reopen; `vor-core` claim replay regressions still pass. | JSONL remains a serialized mirror, not a SQLite-atomic projection; divergence detection remains the recovery boundary. |
| G3 router tenants + transport | PARTIAL_PASS_LOCAL | `vor-gateway::mcp_read_file_reaches_mtls_device_and_audits_grant_actor` uses `build_router_with_tenants_and_hub`, real bearer auth and private mTLS transport. `mcp_status_filters_connected_devices_by_tenant_authority` now filters `commander_status` device IDs, counts, connectivity and recommendations by the authenticated grant plus tenant device/workspace authority across two simultaneous tenants and revocation without restart. | Relay path and mode-missing startup policy are not fully matrixed. |
| G4 device/workspace/resource authority | PARTIAL_PASS_LOCAL | HTTP/MCP + private mTLS commit revalidates authority without server restart: revoked/expired grant, Operator-to-Viewer downgrade, membership revoke, device revoke, device workspace removal and grant workspace removal after prepare are rejected with zero file effect. Terminal ownership carries workspace identity; the dispatcher regression now waits for `TerminalSessionManager::poll` to observe `Completed` without consuming before proving a wrong-workspace poll cannot consume the legitimate result. | Browser/receipt/audit readers, full HTTP/MCP terminal/session matrix and relay parity remain open. |
| G5 signer authority by tenant | PARTIAL_PASS_LOCAL | HTTP/MCP + private mTLS commit rejects revoked signer authority and rotated old-key approvals with zero effect; the same prepared operation succeeds only with the current signer key. C21 attribution was corrected: signer authority evidence stays in G5 and does not stand in for claim-persistence fault injection. | Alias/namespace policy, relay signer coverage and persistence-fault cases remain open. |
| G6 integrated acceptance | PARTIAL_PASS_LOCAL | HTTP/MCP real router -> private transport -> dispatcher/broker -> worker fixture covers the positive path and authority/signature mutations. Feature-gated deterministic seams now cover C21-C24: failed claim before authority, crash after durable claim but before effect, post-effect audit failure, and stale audit-lock recovery. | Full two-tenant browser/session/receipt/audit disclosure matrix, relay local path and C20 remain incomplete. |

## Executed Matrix

| Test family | Status | Evidence |
|---|---|---|
| Positive controls | PASS_LOCAL_UNIT | `tenant_context_enforces_org_workspace_device_role_and_persists` verifies org/workspace/device context. |
| Organization spoofing | PASS_LOCAL_UNIT | Grant for `org-a` fails against `org-b`. Gateway requests derive org from grant instead of client body. |
| Workspace substitution | PASS_LOCAL_UNIT | `ws-a2` is rejected when grant/device only permit `ws-a1`. |
| Foreign device/session | PARTIAL | Device pairing rejects wrong tenant device in `TenantStore`; protected HTTP routes refresh device/membership revocation, but MCP session/receipt routes remain pending. |
| Foreign download/receipt | NOT_COVERED | No tenant-scoped browser/download receipt reader yet. |
| Foreign signing authority | PARTIAL | Broker approval is digest-bound and concurrent one-shot; approver registration can be tenant-scoped; revocation/rotation timing remains pending. |
| Read/list/count/audit | PARTIAL | `records_for_organization` returns only requested org audit rows; no gateway audit-query route yet. |
| Role separation | PASS_LOCAL_UNIT | Viewer in `org-b` cannot satisfy Operator requirement while same user is Operator in `org-a`. |
| Cross-tenant key reuse | PASS_LOCAL_UNIT | Same usage key records separate units for `org-a` and `org-b`. |
| Revocation before execution | PASS_LOCAL_HTTP | Revoked membership blocks previously issued grant context, including through a router-authenticated `/v1/info` request after revocation by another `TenantStore` instance. |
| Reopen/restart | PASS_LOCAL_UNIT | Tenant context and grant survive reopen. |
| Concurrent consume | PASS_LOCAL_BROKER | Two independent brokers race one approval; exactly one accepts, one returns replay. Audit ledger now also migrates legacy `approval_consumed` events into the durable claim table and supports distinct concurrent appends from independent ledger instances. |
| Storage failures | PARTIAL_PASS_LOCAL | Grant and tenant mutators reload under a file lock and fail closed if opened state disappears or is invalid. C21 leaves an approval reusable only after a synchronous pre-effect claim failure. C22 atomically records `not_executed` with the consumed claim and proves reopening cannot reuse it. Before worker invocation the state becomes `effect_uncertain`; after worker return it becomes `effect_applied`. C23 turns a failed post-effect audit write into durable `post_effect_uncertain` and rejects retry without repeating the write. C24 reclaims only parseable audit locks at least 30 seconds old; live/recent or malformed locks retain exclusion and time out. |
| Commercial non-escalation | PASS_LOCAL_HTTP_BOUNDARY | Billing checkout rejects body organization outside authenticated grant through the real router before provider boundary; portal now checks authenticated organization before customer lookup/provider call. Entitlement authority remains M5. |
| A4 storage prerequisite | PASS_LOCAL | Hostile request IDs cannot create/delete outside disposable browser lab roots. |
| Regression | PASS_LOCAL | Workspace, A4 bridge and A4 dispatch E2E passed. |
| C01-C26 report | PARTIAL | `docs/M4_G3_G6_CASE_REPORT_20260924_G6_FAULTS.json` records local C21-C24 fault evidence. C04 is `PASS_LOCAL`, C13 is `PARTIAL_PASS`, C08-C10 and C17/C18 are preserved regressions, and C11/C12/C14/C15-C16/C19-C20 remain open in this report. |

## Evidence

- Source manifest: `docs/SOURCE_MANIFEST_20260919_M4_LOCAL.json`, 133 files, SHA-256 `ff7507752c9b70d6eaae2fc7bcd4e21d70adc3cb00ef0397b1dfcc25b2f8a275`; operational status/acceptance docs are excluded from the manifest to avoid self-reference.
- Source manifest: `docs/SOURCE_MANIFEST_20260919_M4_AUTHORITY_CLOSEOUT.json`, 107 files, SHA-256 `46a6276ae2535f3ea83d08e9d9ad468e3b976793aedf2193d92fc7664f5936d0`.
- Source manifest: `docs/SOURCE_MANIFEST_20260920_M4_AUTHORITY_E2E_V2.json`, 107 files, SHA-256 `36cb34eb52edbbc449b433d7200ee3d12fe8d1dd96762ade8fa7ac2ce4ac0d9a`.
- Source manifest: `docs/SOURCE_MANIFEST_20260920_M4_G3_G6_CLOSEOUT_V3.json`, 2943 files, SHA-256 `8f03472cfdc511915d34a4a5c89625e1e0f9b5dc58de9be161c098deb0f01d99`, git HEAD `c8b2318476591118ec6f198fc7e897755bc52e74`.
- Source manifest: `docs/SOURCE_MANIFEST_20260920_M4_CONTINUE_EXISTING_V3.json`, 2945 files, SHA-256 `f22ed4a20a9491e6104af06507026bc09f43c9a134f7a24b18fb298106094e41`, git HEAD `c8b2318476591118ec6f198fc7e897755bc52e74`.
- Source manifest: `docs/SOURCE_MANIFEST_20260920_M4_NEXT_RUN.json`, 131 source/config/test files, SHA-256 `3e3c4028e2e2ed91aa89b54170cbdc04a23efefda16732267e4f060ccb06536c`, git HEAD `c8b2318476591118ec6f198fc7e897755bc52e74`.
- Source manifest: `docs/SOURCE_MANIFEST_20260920_M4_C04_C11_C14_WORK_ORDER.json`, SHA-256 `1be238d3acea7283aa17d514566f7bb013b183662549487da96228f9d800635e`, git HEAD `c8b2318476591118ec6f198fc7e897755bc52e74`.
- Case report: `docs/M4_G3_G6_CASE_REPORT_20260920_V3.json`.
- Successor case report: `docs/M4_G3_G6_CASE_REPORT_20260920_CONTINUE_EXISTING_V3.json`, SHA-256 `2c781c912debdf483e39b0561997f66dcc0c2bba7fb9b005d3ba3b75944f87f2`.
- Successor case report: `docs/M4_G3_G6_CASE_REPORT_20260920_NEXT_RUN.json`, SHA-256 `e75eb6b7d329c88979ecbc833a8a7ddaf3f01aa1e77558fcae3226f15cac120f`.
- Successor case report: `docs/M4_G3_G6_CASE_REPORT_20260920_C04_C11_C14_WORK_ORDER.json`, SHA-256 `4b44e9b0c4fd958fa76947eb6aafe144b70d932e90b3c9d179c5ff10153b398c`.
- `cargo test --locked --offline -p vor-auth -- --nocapture`: PASS, 13 passed.
- `cargo test --locked --offline -p vor-audit -- --nocapture`: PASS, 6 passed.
- `cargo test --locked --offline -p vor-core -- --nocapture`: PASS, 5 passed.
- `cargo test --locked --offline -p vor-auth -p vor-gateway -- --nocapture`: PASS, auth 10, gateway 23.
- `cargo test --locked --offline -p vor-approval -p vor-dispatch -p vor-gateway -- --nocapture`: PASS, approval 12, dispatch 27 passed plus 1 ignored by design, gateway 24.
- `cargo test --locked --offline -p vor-auth -p vor-audit -p vor-core -p vor-approval -p vor-dispatch -p vor-gateway -- --nocapture`: PASS, auth 13, audit 6, core 5, approval 12, dispatch 27 passed plus 1 ignored by design, gateway 24.
- `cargo test --locked --offline -p vor-auth -p vor-audit -p vor-core -p vor-approval -p vor-dispatch -p vor-gateway -p vor-terminal -- --nocapture`: PASS, auth 13, audit 6, core 5, approval 12, dispatch 28 passed plus 1 ignored by design, gateway 25, terminal 12.
- `cargo test --locked --offline -p vor-auth -p vor-audit -p vor-core -p vor-approval -p vor-dispatch -p vor-gateway -p vor-terminal -- --nocapture`: PASS, auth 15, audit 6, core 5, approval 12, dispatch 28 passed plus 1 ignored by design, gateway 25, terminal 12.
- `cargo test --locked --offline -p vor-dispatch a4_browser_session_enters_through_dispatcher_approval_and_audit -- --ignored --nocapture`: PASS with Firefox 156.0 and geckodriver 0.37.1.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\local\invoke-a4-browser-lab.ps1`: PASS.
- `cargo test --workspace --locked --offline -- --nocapture`: PASS. Browser/desktop live tests remain ignored by design and were run separately where applicable.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check -- .`: PASS.
- `scripts/local/check-worktree-text.ps1`: PASS, selected/read 150 files.
- `python -m unittest tests.test_check_worktree_text -v`: PASS, 4 tests.

## Remaining Gates Before PASS

- Complete the two-tenant MCP/session/receipt/audit negative matrix, browser/receipt disclosure readers, relay-local parity and HTTP/MCP terminal/session object isolation.
- Extend revoked/rotated signer coverage to relay-local parity and alias/namespace edge cases.
- Add tenant-scoped browser/download receipt lookup and negative disclosure tests.
- Add C20 coverage; C21-C24 fault-injection tests now distinguish pre-effect rejection, known not-executed claims, effect uncertainty and post-effect uncertainty.
- C21 policy: `SAAS_TENANCY.md` requires failures to close authority but does not prescribe retry state. Because claim failure is synchronously returned before `ExecutionAuthorization` exists and therefore before worker invocation, the approval remains reusable after repair. The repaired attempt must persist the claim before execution; later attempts fail as replay. The `fault-injection` feature has no default or production dependency and exists only to arm the deterministic storage seam in tests.
- Add M5 usage/entitlement service work only after the gateway authority path uses tenant context end to end.
