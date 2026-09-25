# SaaS tenancy P0

## Canonical entities

- User: human account.
- Organization: security/billing tenant.
- Membership: user role inside organization.
- Device: paired workstation/server owned by one organization.
- Client: MCP/OAuth client identity.
- SessionGrant: short-lived scoped authority.
- Request: immutable attempted action.
- Approval: authorization bound to a request digest.
- AuditEvent: append-only evidence.
- Subscription: commercial entitlements, never an authorization shortcut.
- BillingAccount: external billing identity mapped to exactly one organization.

## Isolation invariants

1. Every device, client, grant, request, approval and cloud audit row is scoped to `organization_id`.
2. Authorization loads organization scope from trusted identity, never from an unchecked request parameter.
3. Cross-organization device lookup returns indistinguishable not-found/unauthorized behavior.
4. Billing entitlement may remove features but can never expand OS capabilities.
5. Support/admin access is separately identified, time-bounded, audited and never ambient.
6. Tenant data encryption keys must be rotatable without changing device identity.
7. External billing IDs must resolve to exactly one `organization_id`; ambiguous or missing mappings fail closed.
8. Browser-returned Checkout or Portal state is advisory until verified webhook state is persisted.

## Future database rule

Prefer composite constraints and row-level enforcement where practical: `organization_id + resource_id` is the normal lookup boundary. Application checks alone are not sufficient for commercial multi-tenancy.

See `STRIPE_BILLING.md` for the hosted billing boundary and launch gates.
