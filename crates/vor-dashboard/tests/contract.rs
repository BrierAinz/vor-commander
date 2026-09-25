// SPDX-License-Identifier: MPL-2.0

use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::PathBuf;
use vor_auth::{
    OrganizationRecord, SubscriptionRecord, TenantDeviceRecord, TenantRole, UsageRecord,
};
use vor_dashboard::{
    ContractError, DashboardSnapshot, DeviceKey, DeviceStatus, Observed, Provenance, SnapshotMode,
    SubscriptionView, TenantProjectionInput, UnknownReason, UsageEntry, ViewerRole,
    project_live_snapshot, simulated_preview_snapshot, snapshot_json_schema,
};

const NOW: u64 = 1_790_000_000_000;

fn org(id: &str) -> OrganizationRecord {
    OrganizationRecord {
        organization_id: id.into(),
        name: format!("{id} name"),
    }
}

fn device(org: &str, id: &str, revoked: bool) -> TenantDeviceRecord {
    TenantDeviceRecord {
        organization_id: org.into(),
        device_id: id.into(),
        workspace_ids: BTreeSet::from(["ws-1".to_owned()]),
        revoked,
    }
}

fn keys(pairs: &[(&str, &str)]) -> BTreeSet<DeviceKey> {
    pairs
        .iter()
        .map(|(org, device)| DeviceKey::new(*org, *device))
        .collect()
}

fn input<'a>(
    organization: &'a OrganizationRecord,
    devices: &'a [TenantDeviceRecord],
    connected: &'a BTreeSet<DeviceKey>,
) -> TenantProjectionInput<'a> {
    TenantProjectionInput {
        organization,
        viewer_role: TenantRole::Operator,
        devices,
        connected_devices: connected,
        subscription: None,
        usage: None,
        now_unix_ms: NOW,
    }
}

/// A valid live snapshot with one connected, one idle and one revoked device.
fn live_three() -> DashboardSnapshot {
    let organization = org("org-a");
    let devices = [
        device("org-a", "dev-connected", false),
        device("org-a", "dev-idle", false),
        device("org-a", "dev-revoked", true),
    ];
    let connected = keys(&[("org-a", "dev-connected")]);
    project_live_snapshot(&input(&organization, &devices, &connected)).unwrap()
}

fn provenances(snapshot: &DashboardSnapshot) -> Vec<(String, Provenance)> {
    let mut out = Vec::new();
    snapshot.visit_fields(&mut |field, provenance, _| out.push((field.to_owned(), provenance)));
    out
}

// Provenance

#[test]
fn simulated_preview_is_valid_and_never_claims_live_data() {
    let snapshot = simulated_preview_snapshot(NOW);
    snapshot.validate().unwrap();
    assert_eq!(snapshot.mode, SnapshotMode::Simulated);
    for (field, provenance) in provenances(&snapshot) {
        assert_ne!(provenance, Provenance::Live, "{field} claims live data");
    }
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("\"live\""));
}

#[test]
fn bundled_simulated_fixture_uses_example_identifiers() {
    // Guarantee of this fixture/producer only; `validate()` does not classify
    // identifier content (see the next test).
    let snapshot = simulated_preview_snapshot(NOW);
    assert!(snapshot.organization.organization_id.contains("example"));
    for device in &snapshot.devices {
        assert!(device.device_id.contains("example"));
        assert!(device.workspace_ids.iter().all(|id| id.contains("example")));
    }
}

#[test]
fn validate_does_not_classify_identifier_content() {
    // Documents the limit of the contract: a simulated snapshot whose
    // identifiers do not follow the example convention is still structurally
    // valid. Synthetic identifiers are the producer's responsibility.
    let mut snapshot = simulated_preview_snapshot(NOW);
    snapshot.organization.organization_id = "org-7f3a".into();
    snapshot.devices[0].device_id = "dev-7f3a".into();
    snapshot.devices[0].workspace_ids = vec!["ws-7f3a".into()];
    snapshot.validate().unwrap();
}

#[test]
fn simulated_snapshot_with_a_live_value_is_rejected() {
    let mut snapshot = simulated_preview_snapshot(NOW);
    snapshot.devices[0].os = Observed::live("Linux".into(), NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::MixedProvenance {
            mode: SnapshotMode::Simulated,
            provenance: Provenance::Live,
            field: "devices[0].os".into(),
        })
    );
}

#[test]
fn live_snapshot_with_a_simulated_value_is_rejected() {
    let mut snapshot = live_three();
    snapshot.devices[0].display_name = Observed::simulated("Preview".into());
    assert!(matches!(
        snapshot.validate(),
        Err(ContractError::MixedProvenance {
            mode: SnapshotMode::Live,
            provenance: Provenance::Simulated,
            ..
        })
    ));
}

#[test]
fn live_value_observed_after_snapshot_time_is_rejected() {
    let mut snapshot = live_three();
    snapshot.organization.name = Observed::live("later".into(), NOW + 1);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::ObservedInFuture("organization.name".into()))
    );
}

#[test]
fn unsupported_version_is_rejected() {
    let mut snapshot = simulated_preview_snapshot(NOW);
    snapshot.schema_version = 2;
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::UnsupportedVersion(2))
    );
}

// Identifiers

#[test]
fn blank_organization_id_is_rejected() {
    for value in ["", "   "] {
        let mut snapshot = live_three();
        snapshot.organization.organization_id = value.into();
        assert_eq!(snapshot.validate(), Err(ContractError::MissingOrganization));
    }
}

#[test]
fn blank_device_id_is_rejected() {
    for value in ["", " \t"] {
        let mut snapshot = live_three();
        snapshot.devices[1].device_id = value.into();
        assert_eq!(snapshot.validate(), Err(ContractError::BlankDeviceId));
    }
}

#[test]
fn blank_device_workspace_id_is_rejected() {
    for value in ["", "  "] {
        let mut snapshot = live_three();
        snapshot.devices[0].workspace_ids.push(value.into());
        assert_eq!(
            snapshot.validate(),
            Err(ContractError::BlankWorkspaceId(
                "devices[0].workspace_ids".into()
            ))
        );
    }
}

#[test]
fn blank_usage_workspace_id_is_rejected() {
    let mut snapshot = live_three();
    snapshot.usage = Observed::live(
        vec![UsageEntry {
            workspace_id: Some(" ".into()),
            usage_key: "calls".into(),
            units: 1,
        }],
        NOW,
    );
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::BlankWorkspaceId("usage".into()))
    );
}

#[test]
fn duplicate_device_id_is_rejected() {
    let mut snapshot = live_three();
    snapshot.devices[1].device_id = snapshot.devices[0].device_id.clone();
    assert_eq!(snapshot.validate(), Err(ContractError::DuplicateDevice));
}

#[test]
fn duplicate_workspace_id_is_rejected() {
    let mut snapshot = live_three();
    snapshot.devices[2].workspace_ids = vec!["ws-1".into(), "ws-1".into()];
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::DuplicateWorkspace(
            "devices[2].workspace_ids".into()
        ))
    );
}

#[test]
fn blank_usage_key_is_rejected() {
    let mut snapshot = live_three();
    snapshot.usage = Observed::live(
        vec![UsageEntry {
            workspace_id: None,
            usage_key: "".into(),
            units: 1,
        }],
        NOW,
    );
    assert_eq!(snapshot.validate(), Err(ContractError::BlankUsageKey));
}

#[test]
fn blank_subscription_plan_is_rejected() {
    let mut snapshot = live_three();
    snapshot.subscription = Observed::live(
        SubscriptionView {
            plan: " ".into(),
            active: true,
        },
        NOW,
    );
    assert_eq!(snapshot.validate(), Err(ContractError::BlankPlan));
}

// Summary counts

#[test]
fn total_devices_must_match_device_list() {
    let mut snapshot = live_three();
    snapshot.summary.total_devices = Observed::live(4, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount("total_devices"))
    );
}

#[test]
fn connected_devices_must_match_known_statuses() {
    let mut snapshot = live_three();
    snapshot.summary.connected_devices = Observed::live(2, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount("connected_devices"))
    );
}

#[test]
fn revoked_devices_must_match_known_statuses() {
    let mut snapshot = live_three();
    snapshot.summary.revoked_devices = Observed::live(0, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount("revoked_devices"))
    );
}

#[test]
fn connected_devices_greater_than_total_is_rejected() {
    let mut snapshot = live_three();
    for device in &mut snapshot.devices {
        device.status = Observed::unknown(UnknownReason::Unavailable);
    }
    snapshot.summary.revoked_devices = Observed::unknown(UnknownReason::Unavailable);
    snapshot.summary.connected_devices = Observed::live(4, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount("connected_devices"))
    );
}

#[test]
fn revoked_devices_greater_than_total_is_rejected() {
    let mut snapshot = live_three();
    for device in &mut snapshot.devices {
        device.status = Observed::unknown(UnknownReason::Unavailable);
    }
    snapshot.summary.connected_devices = Observed::unknown(UnknownReason::Unavailable);
    snapshot.summary.revoked_devices = Observed::live(4, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount("revoked_devices"))
    );
}

#[test]
fn connected_plus_revoked_greater_than_total_is_rejected() {
    let mut snapshot = live_three();
    for device in &mut snapshot.devices {
        device.status = Observed::unknown(UnknownReason::Unavailable);
    }
    snapshot.summary.connected_devices = Observed::live(2, NOW);
    snapshot.summary.revoked_devices = Observed::live(2, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount(
            "connected_devices + revoked_devices"
        ))
    );
}

#[test]
fn known_count_cannot_contradict_known_statuses_when_some_are_unknown() {
    // dev-connected stays live Connected; the other two become unknown, so the
    // connected count may be 1..=3 but never 0.
    let mut snapshot = live_three();
    snapshot.devices[1].status = Observed::unknown(UnknownReason::Unavailable);
    snapshot.devices[2].status = Observed::unknown(UnknownReason::Unavailable);
    snapshot.summary.revoked_devices = Observed::unknown(UnknownReason::Unavailable);
    snapshot.summary.connected_devices = Observed::live(0, NOW);
    assert_eq!(
        snapshot.validate(),
        Err(ContractError::InconsistentCount("connected_devices"))
    );
    snapshot.summary.connected_devices = Observed::live(3, NOW);
    snapshot.validate().unwrap();
}

#[test]
fn unknown_counts_are_never_compared() {
    let mut snapshot = live_three();
    snapshot.summary.total_devices = Observed::unknown(UnknownReason::Unavailable);
    snapshot.summary.connected_devices = Observed::unknown(UnknownReason::Unavailable);
    snapshot.summary.revoked_devices = Observed::unknown(UnknownReason::NotImplemented);
    snapshot.validate().unwrap();
}

// Undeclared fields

fn with_extra(path: &[&str]) -> Vec<u8> {
    let mut value = serde_json::to_value(simulated_preview_snapshot(NOW)).unwrap();
    let mut target = &mut value;
    for segment in path {
        target = match segment.parse::<usize>() {
            Ok(index) => &mut target[index],
            Err(_) => &mut target[*segment],
        };
    }
    target
        .as_object_mut()
        .expect("path points to an object")
        .insert("token".into(), json!("not-a-real-value"));
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn undeclared_field_is_rejected_at_root() {
    assert_eq!(
        DashboardSnapshot::from_json(&with_extra(&[])),
        Err(ContractError::InvalidJson)
    );
}

#[test]
fn undeclared_field_is_rejected_in_nested_objects() {
    for path in [
        &["organization"][..],
        &["summary"][..],
        &["summary", "total_devices"][..],
        &["devices", "0"][..],
        &["devices", "0", "status"][..],
        &["devices", "0", "last_seen_unix_ms"][..],
        &["subscription"][..],
        &["subscription", "value"][..],
        &["usage"][..],
    ] {
        assert_eq!(
            DashboardSnapshot::from_json(&with_extra(path)),
            Err(ContractError::InvalidJson),
            "undeclared field accepted at {path:?}"
        );
    }
}

#[test]
fn undeclared_field_is_rejected_in_usage_entries() {
    let mut snapshot = live_three();
    snapshot.usage = Observed::live(
        vec![UsageEntry {
            workspace_id: None,
            usage_key: "calls".into(),
            units: 1,
        }],
        NOW,
    );
    let mut value = serde_json::to_value(&snapshot).unwrap();
    value["usage"]["value"][0]["token"] = json!("not-a-real-value");
    assert_eq!(
        DashboardSnapshot::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(ContractError::InvalidJson)
    );
}

#[test]
fn from_json_validates_before_returning() {
    let mut value = serde_json::to_value(simulated_preview_snapshot(NOW)).unwrap();
    value["summary"]["total_devices"] =
        json!({"provenance": "live", "value": 3, "observed_at_unix_ms": NOW});
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        DashboardSnapshot::from_json(&bytes),
        Err(ContractError::MixedProvenance { .. })
    ));
    assert_eq!(
        DashboardSnapshot::from_json(b"{not json"),
        Err(ContractError::InvalidJson)
    );
}

#[test]
fn schema_forbids_additional_properties_on_every_object() {
    fn check(value: &Value, path: &str) {
        match value {
            Value::Object(map) => {
                if map.contains_key("properties") {
                    assert_eq!(
                        map.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "object schema at {path} allows undeclared fields"
                    );
                }
                for (key, child) in map {
                    check(child, &format!("{path}/{key}"));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    check(item, &format!("{path}/{index}"));
                }
            }
            _ => {}
        }
    }
    check(&snapshot_json_schema(), "#");
}

#[test]
fn declared_field_names_exclude_sensitive_names() {
    // Scope: field names declared by this contract. Combined with the
    // undeclared-field rejection above, a valid snapshot cannot carry a field
    // with these names. It says nothing about the content of declared strings.
    const SENSITIVE: &[&str] = &[
        "token",
        "secret",
        "password",
        "cookie",
        "private_key",
        "certificate",
        "fingerprint",
        "email",
        "api_key",
    ];
    fn property_names(value: &Value, out: &mut HashSet<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::Object(properties)) = map.get("properties") {
                    out.extend(properties.keys().map(|key| key.to_ascii_lowercase()));
                }
                map.values().for_each(|child| property_names(child, out));
            }
            Value::Array(items) => items.iter().for_each(|item| property_names(item, out)),
            _ => {}
        }
    }
    let mut names = HashSet::new();
    property_names(&snapshot_json_schema(), &mut names);
    assert!(
        names.contains("device_id"),
        "schema walk found no properties"
    );
    for name in names {
        for word in SENSITIVE {
            assert!(
                !name.contains(word),
                "declared field {name} looks sensitive"
            );
        }
    }
}

// Projection

#[test]
fn projection_reports_real_status_and_leaves_untracked_fields_unknown() {
    let organization = org("org-a");
    let devices = [
        device("org-a", "dev-connected", false),
        device("org-a", "dev-idle", false),
        device("org-a", "dev-revoked", true),
    ];
    // A revoked device that still holds a transport link must show as revoked.
    let connected = keys(&[("org-a", "dev-connected"), ("org-a", "dev-revoked")]);
    let snapshot = project_live_snapshot(&input(&organization, &devices, &connected)).unwrap();

    assert_eq!(snapshot.mode, SnapshotMode::Live);
    assert_eq!(
        snapshot.organization.viewer_role,
        Observed::live(ViewerRole::Operator, NOW)
    );
    let status: Vec<_> = snapshot
        .devices
        .iter()
        .map(|device| (device.device_id.as_str(), device.status.clone()))
        .collect();
    assert_eq!(
        status,
        vec![
            (
                "dev-connected",
                Observed::live(DeviceStatus::Connected, NOW)
            ),
            ("dev-idle", Observed::live(DeviceStatus::NotConnected, NOW)),
            ("dev-revoked", Observed::live(DeviceStatus::Revoked, NOW)),
        ]
    );
    assert_eq!(snapshot.summary.total_devices, Observed::live(3, NOW));
    assert_eq!(snapshot.summary.connected_devices, Observed::live(1, NOW));
    assert_eq!(snapshot.summary.revoked_devices, Observed::live(1, NOW));
    for device in &snapshot.devices {
        assert_eq!(device.os, Observed::unknown(UnknownReason::NotReported));
        assert_eq!(
            device.agent_version,
            Observed::unknown(UnknownReason::NotReported)
        );
        assert_eq!(
            device.last_seen_unix_ms,
            Observed::unknown(UnknownReason::NotImplemented)
        );
    }
    assert_eq!(
        snapshot.subscription,
        Observed::unknown(UnknownReason::NotReported)
    );
    assert_eq!(
        snapshot.usage,
        Observed::unknown(UnknownReason::NotImplemented)
    );
}

#[test]
fn same_device_id_connected_in_another_organization_does_not_mark_connected() {
    let organization = org("org-a");
    let devices = [device("org-a", "dev-shared", false)];
    // org-b owns its own device with the same id, and that one is connected.
    let connected = keys(&[("org-b", "dev-shared")]);
    let snapshot = project_live_snapshot(&input(&organization, &devices, &connected)).unwrap();
    assert_eq!(
        snapshot.devices[0].status,
        Observed::live(DeviceStatus::NotConnected, NOW)
    );
    assert_eq!(snapshot.summary.connected_devices, Observed::live(0, NOW));

    let organization_b = org("org-b");
    let devices_b = [device("org-b", "dev-shared", false)];
    let snapshot_b =
        project_live_snapshot(&input(&organization_b, &devices_b, &connected)).unwrap();
    assert_eq!(
        snapshot_b.devices[0].status,
        Observed::live(DeviceStatus::Connected, NOW)
    );
}

#[test]
fn projection_ignores_other_tenants_connected_devices() {
    let organization = org("org-a");
    let devices = [device("org-a", "dev-a", false)];
    let connected = keys(&[("org-b", "dev-b"), ("org-c", "dev-c")]);
    let snapshot = project_live_snapshot(&input(&organization, &devices, &connected)).unwrap();
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.summary.connected_devices, Observed::live(0, NOW));
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("dev-b") && !json.contains("dev-c") && !json.contains("org-b"));
}

#[test]
fn projection_fails_closed_on_records_from_another_tenant() {
    let organization = org("org-a");
    let connected = BTreeSet::new();

    let devices = [
        device("org-a", "dev-a", false),
        device("org-b", "dev-b", false),
    ];
    assert_eq!(
        project_live_snapshot(&input(&organization, &devices, &connected)),
        Err(ContractError::CrossTenantRecord)
    );

    let subscription = SubscriptionRecord {
        organization_id: "org-b".into(),
        plan: "teams".into(),
        active: true,
    };
    let mut foreign_subscription = input(&organization, &[], &connected);
    foreign_subscription.subscription = Some(&subscription);
    assert_eq!(
        project_live_snapshot(&foreign_subscription),
        Err(ContractError::CrossTenantRecord)
    );

    let usage = [UsageRecord {
        organization_id: "org-b".into(),
        workspace_id: None,
        usage_key: "calls".into(),
        units: 1,
    }];
    let mut foreign_usage = input(&organization, &[], &connected);
    foreign_usage.usage = Some(&usage);
    assert_eq!(
        project_live_snapshot(&foreign_usage),
        Err(ContractError::CrossTenantRecord)
    );
}

#[test]
fn projection_rejects_blank_identifiers_from_records() {
    let organization = org("org-a");
    let connected = BTreeSet::new();
    let devices = [device("org-a", " ", false)];
    assert_eq!(
        project_live_snapshot(&input(&organization, &devices, &connected)),
        Err(ContractError::BlankDeviceId)
    );
}

#[test]
fn projection_marks_supplied_subscription_and_usage_as_live() {
    let organization = org("org-a");
    let connected = BTreeSet::new();
    let subscription = SubscriptionRecord {
        organization_id: "org-a".into(),
        plan: "personal".into(),
        active: false,
    };
    let usage = [UsageRecord {
        organization_id: "org-a".into(),
        workspace_id: Some("ws-1".into()),
        usage_key: "calls".into(),
        units: 4,
    }];
    let mut request = input(&organization, &[], &connected);
    request.subscription = Some(&subscription);
    request.usage = Some(&usage);
    let snapshot = project_live_snapshot(&request).unwrap();
    assert_eq!(snapshot.subscription.provenance(), Provenance::Live);
    let Observed::Live { value, .. } = &snapshot.usage else {
        panic!("usage should be live");
    };
    assert_eq!(value.len(), 1);
    assert_eq!(value[0].units, 4);
}

// Committed contract artefacts

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts")
}

fn assert_golden(file: &str, value: &Value) {
    let path = contracts_dir().join(file);
    let rendered = serde_json::to_string_pretty(value).unwrap() + "\n";
    if std::env::var_os("VOR_UPDATE_CONTRACTS").is_some() {
        fs::create_dir_all(contracts_dir()).unwrap();
        fs::write(&path, &rendered).unwrap();
    }
    let committed = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert_eq!(
        committed, rendered,
        "{file} is out of date; regenerate with VOR_UPDATE_CONTRACTS=1 cargo test -p vor-dashboard"
    );
}

#[test]
fn committed_json_schema_matches_contract() {
    assert_golden("dashboard-snapshot.v1.schema.json", &snapshot_json_schema());
}

#[test]
fn committed_simulated_example_matches_fixture_and_validates() {
    let snapshot = simulated_preview_snapshot(NOW);
    assert_golden(
        "dashboard-snapshot.v1.simulated.example.json",
        &serde_json::to_value(&snapshot).unwrap(),
    );
    let bytes =
        fs::read(contracts_dir().join("dashboard-snapshot.v1.simulated.example.json")).unwrap();
    assert_eq!(DashboardSnapshot::from_json(&bytes).unwrap(), snapshot);
}
