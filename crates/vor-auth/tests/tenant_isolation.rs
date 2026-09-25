// SPDX-License-Identifier: MPL-2.0

use std::collections::BTreeSet;
use std::path::PathBuf;
use tempfile::{TempDir, tempdir};
use vor_auth::{AuthError, GrantRecord, TenantRole, TenantStore};

const ORG_A: &str = "org-a";
const ORG_B: &str = "org-b";
const USER_A: &str = "user-a";
const USER_B: &str = "user-b";
const WORKSPACE_A: &str = "workspace-a";
const WORKSPACE_B: &str = "workspace-b";
const DEVICE_A: &str = "device-a";
const DEVICE_B: &str = "device-b";
const SHARED_DEVICE_ID: &str = "shared-device";

struct TenantFixture {
    _dir: TempDir,
    path: PathBuf,
    store: TenantStore,
    grant_a: GrantRecord,
    grant_b: GrantRecord,
}

impl TenantFixture {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tenants.json");
        let store = TenantStore::open(&path).unwrap();

        store.upsert_user(USER_A, "User A").unwrap();
        store.upsert_user(USER_B, "User B").unwrap();
        store.upsert_organization(ORG_A, "Organization A").unwrap();
        store.upsert_organization(ORG_B, "Organization B").unwrap();
        store
            .upsert_workspace(ORG_A, WORKSPACE_A, "Workspace A")
            .unwrap();
        store
            .upsert_workspace(ORG_B, WORKSPACE_B, "Workspace B")
            .unwrap();

        store
            .set_membership(ORG_A, USER_A, TenantRole::Viewer)
            .unwrap();
        store
            .set_membership(ORG_B, USER_B, TenantRole::Operator)
            .unwrap();
        // The same real user has a stronger role in org-b. This makes role bleed
        // observable instead of relying on an actor identifier that does not exist.
        store
            .set_membership(ORG_B, USER_A, TenantRole::Admin)
            .unwrap();

        store.pair_device(ORG_A, DEVICE_A, [WORKSPACE_A]).unwrap();
        store.pair_device(ORG_B, DEVICE_B, [WORKSPACE_B]).unwrap();

        Self {
            _dir: dir,
            path,
            store,
            grant_a: grant_for(ORG_A, USER_A, WORKSPACE_A),
            grant_b: grant_for(ORG_B, USER_B, WORKSPACE_B),
        }
    }

    fn pair_shared_device_in_both_organizations(&self) {
        self.store
            .pair_device(ORG_A, SHARED_DEVICE_ID, [WORKSPACE_A])
            .unwrap();
        self.store
            .pair_device(ORG_B, SHARED_DEVICE_ID, [WORKSPACE_B])
            .unwrap();
    }
}

fn grant_for(organization_id: &str, actor_id: &str, workspace_id: &str) -> GrantRecord {
    GrantRecord {
        grant_id: format!("grant-{organization_id}"),
        organization_id: organization_id.to_owned(),
        actor_id: actor_id.to_owned(),
        workspace_ids: BTreeSet::from([workspace_id.to_owned()]),
        scopes: BTreeSet::from(["remote.execute".to_owned()]),
        issued_at_unix_ms: 1,
        expires_at_unix_ms: u64::MAX,
        revoked: false,
    }
}

#[track_caller]
fn assert_unauthorized<T>(result: Result<T, AuthError>) {
    assert!(matches!(result, Err(AuthError::Unauthorized)));
}

#[test]
fn grant_cannot_select_another_organization_from_request_context() {
    let fixture = TenantFixture::new();

    assert_unauthorized(fixture.store.verify_context(
        &fixture.grant_a,
        ORG_B,
        DEVICE_B,
        Some(WORKSPACE_B),
        TenantRole::Viewer,
    ));
}

#[test]
fn valid_device_identifier_from_another_organization_is_rejected() {
    let fixture = TenantFixture::new();

    assert_unauthorized(fixture.store.verify_context(
        &fixture.grant_a,
        ORG_A,
        DEVICE_B,
        None,
        TenantRole::Viewer,
    ));
}

#[test]
fn valid_workspace_identifier_from_another_organization_is_rejected() {
    let fixture = TenantFixture::new();

    assert_unauthorized(fixture.store.verify_context(
        &fixture.grant_a,
        ORG_A,
        DEVICE_A,
        Some(WORKSPACE_B),
        TenantRole::Viewer,
    ));
}

#[test]
fn elevated_role_is_not_borrowed_from_another_organization() {
    let fixture = TenantFixture::new();

    fixture
        .store
        .verify_context(
            &fixture.grant_a,
            ORG_A,
            DEVICE_A,
            Some(WORKSPACE_A),
            TenantRole::Viewer,
        )
        .unwrap();
    assert_unauthorized(fixture.store.verify_context(
        &fixture.grant_a,
        ORG_A,
        DEVICE_A,
        Some(WORKSPACE_A),
        TenantRole::Admin,
    ));
}

#[test]
fn usage_listing_stays_scoped_when_tenants_share_resource_identifiers() {
    let fixture = TenantFixture::new();
    fixture.pair_shared_device_in_both_organizations();

    // UsageRecord has no device_id field, so the shared valid device identifier is
    // also used as the usage key to exercise the closest representable collision.
    fixture
        .store
        .record_usage(ORG_A, Some(WORKSPACE_A), SHARED_DEVICE_ID, 3)
        .unwrap();
    fixture
        .store
        .record_usage(ORG_B, Some(WORKSPACE_B), SHARED_DEVICE_ID, 7)
        .unwrap();

    let usage_a = fixture.store.list_usage_for_org(ORG_A).unwrap();
    let usage_b = fixture.store.list_usage_for_org(ORG_B).unwrap();
    assert_eq!(usage_a.len(), 1);
    assert_eq!(usage_b.len(), 1);
    assert!(usage_a.iter().all(|record| record.organization_id == ORG_A));
    assert!(usage_b.iter().all(|record| record.organization_id == ORG_B));
    assert_eq!(usage_a[0].units, 3);
    assert_eq!(usage_b[0].units, 7);
}

#[test]
fn usage_recorded_for_one_organization_is_absent_from_the_other() {
    let fixture = TenantFixture::new();

    fixture
        .store
        .record_usage(ORG_A, Some(WORKSPACE_A), "org-a-only", 11)
        .unwrap();

    assert_eq!(fixture.store.list_usage_for_org(ORG_A).unwrap().len(), 1);
    assert!(fixture.store.list_usage_for_org(ORG_B).unwrap().is_empty());
}

#[test]
fn identical_device_ids_in_different_organizations_do_not_overwrite_each_other() {
    let fixture = TenantFixture::new();
    fixture.pair_shared_device_in_both_organizations();

    let context_a = fixture
        .store
        .verify_context(
            &fixture.grant_a,
            ORG_A,
            SHARED_DEVICE_ID,
            Some(WORKSPACE_A),
            TenantRole::Viewer,
        )
        .unwrap();
    let context_b = fixture
        .store
        .verify_context(
            &fixture.grant_b,
            ORG_B,
            SHARED_DEVICE_ID,
            Some(WORKSPACE_B),
            TenantRole::Operator,
        )
        .unwrap();

    assert_eq!(context_a.organization_id, ORG_A);
    assert_eq!(context_b.organization_id, ORG_B);

    fixture
        .store
        .revoke_device(ORG_B, SHARED_DEVICE_ID)
        .unwrap();
    fixture
        .store
        .verify_context(
            &fixture.grant_a,
            ORG_A,
            SHARED_DEVICE_ID,
            Some(WORKSPACE_A),
            TenantRole::Viewer,
        )
        .unwrap();
    assert_unauthorized(fixture.store.verify_context(
        &fixture.grant_b,
        ORG_B,
        SHARED_DEVICE_ID,
        Some(WORKSPACE_B),
        TenantRole::Operator,
    ));
}

#[test]
fn cross_organization_revoke_does_not_revoke_the_owning_device() {
    let fixture = TenantFixture::new();

    fixture.store.revoke_device(ORG_B, DEVICE_A).unwrap();

    let context = fixture
        .store
        .verify_context(
            &fixture.grant_a,
            ORG_A,
            DEVICE_A,
            Some(WORKSPACE_A),
            TenantRole::Viewer,
        )
        .unwrap();
    assert_eq!(context.organization_id, ORG_A);
    assert_eq!(context.device_id, DEVICE_A);
}

#[test]
fn revoke_device_is_indistinguishable_for_cross_tenant_and_missing_devices() {
    let fixture = TenantFixture::new();

    let cross_tenant = fixture.store.revoke_device(ORG_B, DEVICE_A);
    let missing = fixture.store.revoke_device(ORG_B, "missing-device");

    assert!(cross_tenant.is_ok());
    assert!(missing.is_ok());
    // DECISION PENDIENTE: Keep Ok(()) for both cases. Idempotent revocation avoids
    // a cross-tenant existence oracle; operator assurance should come from an
    // authorized tenant-scoped status or audit view, not a distinguishable error.
}

#[test]
fn tenant_isolation_survives_store_reopen() {
    let fixture = TenantFixture::new();
    fixture.pair_shared_device_in_both_organizations();
    fixture
        .store
        .record_usage(ORG_A, Some(WORKSPACE_A), "same-usage", 13)
        .unwrap();
    fixture
        .store
        .record_usage(ORG_B, Some(WORKSPACE_B), "same-usage", 17)
        .unwrap();

    let TenantFixture {
        _dir,
        path,
        store,
        grant_a,
        grant_b,
    } = fixture;
    drop(store);
    let reopened = TenantStore::open(&path).unwrap();

    reopened
        .verify_context(
            &grant_a,
            ORG_A,
            SHARED_DEVICE_ID,
            Some(WORKSPACE_A),
            TenantRole::Viewer,
        )
        .unwrap();
    reopened
        .verify_context(
            &grant_b,
            ORG_B,
            SHARED_DEVICE_ID,
            Some(WORKSPACE_B),
            TenantRole::Operator,
        )
        .unwrap();
    assert_unauthorized(reopened.verify_context(
        &grant_a,
        ORG_A,
        SHARED_DEVICE_ID,
        Some(WORKSPACE_B),
        TenantRole::Viewer,
    ));

    let usage_a = reopened.list_usage_for_org(ORG_A).unwrap();
    let usage_b = reopened.list_usage_for_org(ORG_B).unwrap();
    assert_eq!(usage_a.len(), 1);
    assert_eq!(usage_b.len(), 1);
    assert_eq!(usage_a[0].organization_id, ORG_A);
    assert_eq!(usage_a[0].units, 13);
    assert_eq!(usage_b[0].organization_id, ORG_B);
    assert_eq!(usage_b[0].units, 17);
}
