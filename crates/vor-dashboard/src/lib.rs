// SPDX-License-Identifier: MPL-2.0

//! Read-model contract between the Vör backend and the web dashboard.
//!
//! Provenance guarantee: every *observable* value (state, metric or derived
//! information) is an [`Observed`] tagged `live` (observed by the backend at a
//! known time), `unknown` (the backend cannot say) or `simulated` (synthetic
//! preview data). Identifiers (`organization_id`, `device_id`,
//! `workspace_ids`, `workspace_id`, `usage_key`) are structural keys, not
//! observations: they carry no per-field provenance and inherit the snapshot
//! `mode`. The contract does not inspect identifier content: `validate()`
//! checks that identifiers are non-blank and unique, but cannot tell whether a
//! string names a real organization, device or workspace. Keeping identifiers
//! synthetic in simulated snapshots is the producer's responsibility; the
//! bundled [`simulated_preview_snapshot`] fixture uses reserved example names.
//!
//! A snapshot is either live-or-unknown or simulated-or-unknown; mixing live
//! and simulated values fails validation. Deserialization rejects fields the
//! contract does not declare.
//!
//! This crate is a pure data contract. It grants no authority, performs no I/O
//! and is not wired to any HTTP route.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use vor_auth::{
    OrganizationRecord, SubscriptionRecord, TenantDeviceRecord, TenantRole, UsageRecord,
};

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMode {
    Live,
    Simulated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Live,
    Unknown,
    Simulated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// The device or backend does not report this value yet.
    NotReported,
    /// The backend feature that would produce this value does not exist yet.
    NotImplemented,
    /// The source exists but could not be read for this snapshot.
    Unavailable,
}

/// An observable value together with its provenance.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "provenance", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observed<T> {
    Live { value: T, observed_at_unix_ms: u64 },
    Unknown { reason: UnknownReason },
    Simulated { value: T },
}

impl<T> Observed<T> {
    pub fn live(value: T, observed_at_unix_ms: u64) -> Self {
        Self::Live {
            value,
            observed_at_unix_ms,
        }
    }

    pub fn unknown(reason: UnknownReason) -> Self {
        Self::Unknown { reason }
    }

    pub fn simulated(value: T) -> Self {
        Self::Simulated { value }
    }

    pub fn provenance(&self) -> Provenance {
        match self {
            Self::Live { .. } => Provenance::Live,
            Self::Unknown { .. } => Provenance::Unknown,
            Self::Simulated { .. } => Provenance::Simulated,
        }
    }

    /// The value when it is known (`live` or `simulated`).
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Live { value, .. } | Self::Simulated { value } => Some(value),
            Self::Unknown { .. } => None,
        }
    }

    fn observed_at(&self) -> Option<u64> {
        match self {
            Self::Live {
                observed_at_unix_ms,
                ..
            } => Some(*observed_at_unix_ms),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViewerRole {
    Viewer,
    Operator,
    Admin,
}

impl From<TenantRole> for ViewerRole {
    fn from(role: TenantRole) -> Self {
        match role {
            TenantRole::Viewer => Self::Viewer,
            TenantRole::Operator => Self::Operator,
            TenantRole::Admin => Self::Admin,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Holds an authenticated transport link to this gateway right now.
    Connected,
    /// Paired and not revoked, but no transport link to this gateway right now.
    NotConnected,
    /// Revoked in the tenant store. Takes precedence over any transport state.
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DashboardSnapshot {
    pub schema_version: u32,
    /// Snapshot mode. Identifiers carry no per-field provenance and inherit
    /// this mode; their content is not inspected by validation.
    pub mode: SnapshotMode,
    pub generated_at_unix_ms: u64,
    pub organization: OrganizationView,
    pub summary: SummaryView,
    pub devices: Vec<DeviceView>,
    pub subscription: Observed<SubscriptionView>,
    pub usage: Observed<Vec<UsageEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrganizationView {
    /// Structural key; provenance follows the snapshot `mode`.
    pub organization_id: String,
    pub name: Observed<String>,
    pub viewer_role: Observed<ViewerRole>,
}

/// Counts derived from `devices` of the same snapshot. v1 has no other source
/// for them, so a known count must agree with the device list.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SummaryView {
    pub total_devices: Observed<u32>,
    pub connected_devices: Observed<u32>,
    pub revoked_devices: Observed<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceView {
    /// Structural key; provenance follows the snapshot `mode`.
    pub device_id: String,
    /// Structural keys; provenance follows the snapshot `mode`.
    pub workspace_ids: Vec<String>,
    pub status: Observed<DeviceStatus>,
    pub display_name: Observed<String>,
    pub os: Observed<String>,
    pub agent_version: Observed<String>,
    pub capabilities: Observed<Vec<String>>,
    pub last_seen_unix_ms: Observed<u64>,
}

/// Commercial state for display only. It is never an authorization input.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionView {
    pub plan: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsageEntry {
    /// Structural key; provenance follows the enclosing `usage` value.
    pub workspace_id: Option<String>,
    /// Structural key; provenance follows the enclosing `usage` value.
    pub usage_key: String,
    pub units: u64,
}

/// Composite identity of a device: the persistent model keys devices by
/// organization, so the same `device_id` may exist in several organizations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceKey {
    pub organization_id: String,
    pub device_id: String,
}

impl DeviceKey {
    pub fn new(organization_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            organization_id: organization_id.into(),
            device_id: device_id.into(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported dashboard schema version: {0}")]
    UnsupportedVersion(u32),
    #[error("organization id must not be blank")]
    MissingOrganization,
    #[error("device id must not be blank")]
    BlankDeviceId,
    #[error("workspace id must not be blank at {0}")]
    BlankWorkspaceId(String),
    #[error("duplicate device id in snapshot")]
    DuplicateDevice,
    #[error("duplicate workspace id at {0}")]
    DuplicateWorkspace(String),
    #[error("usage key must not be blank")]
    BlankUsageKey,
    #[error("subscription plan must not be blank")]
    BlankPlan,
    #[error("{mode:?} snapshot contains a {provenance:?} value at {field}")]
    MixedProvenance {
        mode: SnapshotMode,
        provenance: Provenance,
        field: String,
    },
    #[error("live value at {0} is newer than the snapshot")]
    ObservedInFuture(String),
    #[error("summary count {0} contradicts the device list")]
    InconsistentCount(&'static str),
    #[error("record for another organization was passed to the projection")]
    CrossTenantRecord,
    #[error("device count does not fit the contract")]
    TooManyDevices,
    #[error("dashboard snapshot JSON is invalid or has undeclared fields")]
    InvalidJson,
}

fn blank(value: &str) -> bool {
    value.trim().is_empty()
}

impl DashboardSnapshot {
    /// Parses and validates a snapshot. Undeclared fields are rejected.
    /// Consumers should never render an unvalidated snapshot.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ContractError> {
        let snapshot: Self =
            serde_json::from_slice(bytes).map_err(|_| ContractError::InvalidJson)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedVersion(self.schema_version));
        }
        if blank(&self.organization.organization_id) {
            return Err(ContractError::MissingOrganization);
        }
        self.validate_identifiers()?;
        self.validate_provenance()?;
        self.validate_summary()
    }

    fn validate_identifiers(&self) -> Result<(), ContractError> {
        let mut device_ids = BTreeSet::new();
        for (index, device) in self.devices.iter().enumerate() {
            if blank(&device.device_id) {
                return Err(ContractError::BlankDeviceId);
            }
            if !device_ids.insert(device.device_id.as_str()) {
                return Err(ContractError::DuplicateDevice);
            }
            let field = format!("devices[{index}].workspace_ids");
            let mut workspace_ids = BTreeSet::new();
            for workspace_id in &device.workspace_ids {
                if blank(workspace_id) {
                    return Err(ContractError::BlankWorkspaceId(field));
                }
                if !workspace_ids.insert(workspace_id.as_str()) {
                    return Err(ContractError::DuplicateWorkspace(field));
                }
            }
        }
        if let Some(entries) = self.usage.known() {
            for entry in entries {
                if blank(&entry.usage_key) {
                    return Err(ContractError::BlankUsageKey);
                }
                if entry.workspace_id.as_deref().is_some_and(blank) {
                    return Err(ContractError::BlankWorkspaceId("usage".into()));
                }
            }
        }
        if self
            .subscription
            .known()
            .is_some_and(|subscription| blank(&subscription.plan))
        {
            return Err(ContractError::BlankPlan);
        }
        Ok(())
    }

    fn validate_provenance(&self) -> Result<(), ContractError> {
        let forbidden = match self.mode {
            SnapshotMode::Live => Provenance::Simulated,
            SnapshotMode::Simulated => Provenance::Live,
        };
        let mut result = Ok(());
        self.visit_fields(&mut |field, provenance, observed_at| {
            if result.is_err() {
                return;
            }
            if provenance == forbidden {
                result = Err(ContractError::MixedProvenance {
                    mode: self.mode,
                    provenance,
                    field: field.to_owned(),
                });
            } else if observed_at.is_some_and(|at| at > self.generated_at_unix_ms) {
                result = Err(ContractError::ObservedInFuture(field.to_owned()));
            }
        });
        result
    }

    /// Summary counts are derived from `devices`. A known count must match the
    /// list; when some device status is unknown only upper bounds apply. An
    /// unknown count is never compared.
    fn validate_summary(&self) -> Result<(), ContractError> {
        let listed =
            u32::try_from(self.devices.len()).map_err(|_| ContractError::TooManyDevices)?;
        let statuses: Vec<Option<&DeviceStatus>> = self
            .devices
            .iter()
            .map(|device| device.status.known())
            .collect();
        let all_known = statuses.iter().all(Option::is_some);
        let with_status = |status: DeviceStatus| {
            statuses
                .iter()
                .filter(|known| **known == Some(&status))
                .count() as u64
        };
        let unknown_statuses = statuses.iter().filter(|known| known.is_none()).count() as u64;

        let total = self.summary.total_devices.known().copied();
        if total.is_some_and(|total| total != listed) {
            return Err(ContractError::InconsistentCount("total_devices"));
        }
        for (name, count, status) in [
            (
                "connected_devices",
                self.summary.connected_devices.known().copied(),
                DeviceStatus::Connected,
            ),
            (
                "revoked_devices",
                self.summary.revoked_devices.known().copied(),
                DeviceStatus::Revoked,
            ),
        ] {
            let Some(count) = count else { continue };
            let count = u64::from(count);
            let matching = with_status(status);
            let consistent = if all_known {
                count == matching
            } else {
                count >= matching && count <= matching + unknown_statuses
            };
            if count > u64::from(listed) || !consistent {
                return Err(ContractError::InconsistentCount(name));
            }
        }
        if let (Some(connected), Some(revoked)) = (
            self.summary.connected_devices.known(),
            self.summary.revoked_devices.known(),
        ) && u64::from(*connected) + u64::from(*revoked) > u64::from(listed)
        {
            return Err(ContractError::InconsistentCount(
                "connected_devices + revoked_devices",
            ));
        }
        Ok(())
    }

    /// Visits every provenance-carrying field with a stable path label.
    pub fn visit_fields(&self, visit: &mut impl FnMut(&str, Provenance, Option<u64>)) {
        fn field<T>(
            visit: &mut impl FnMut(&str, Provenance, Option<u64>),
            path: &str,
            value: &Observed<T>,
        ) {
            visit(path, value.provenance(), value.observed_at());
        }
        field(visit, "organization.name", &self.organization.name);
        field(
            visit,
            "organization.viewer_role",
            &self.organization.viewer_role,
        );
        field(visit, "summary.total_devices", &self.summary.total_devices);
        field(
            visit,
            "summary.connected_devices",
            &self.summary.connected_devices,
        );
        field(
            visit,
            "summary.revoked_devices",
            &self.summary.revoked_devices,
        );
        for (index, device) in self.devices.iter().enumerate() {
            let prefix = format!("devices[{index}]");
            field(visit, &format!("{prefix}.status"), &device.status);
            field(
                visit,
                &format!("{prefix}.display_name"),
                &device.display_name,
            );
            field(visit, &format!("{prefix}.os"), &device.os);
            field(
                visit,
                &format!("{prefix}.agent_version"),
                &device.agent_version,
            );
            field(
                visit,
                &format!("{prefix}.capabilities"),
                &device.capabilities,
            );
            field(
                visit,
                &format!("{prefix}.last_seen_unix_ms"),
                &device.last_seen_unix_ms,
            );
        }
        field(visit, "subscription", &self.subscription);
        field(visit, "usage", &self.usage);
    }
}

/// Backend state for one authenticated organization. The caller must load it
/// from trusted identity; every record must belong to `organization`.
pub struct TenantProjectionInput<'a> {
    pub organization: &'a OrganizationRecord,
    pub viewer_role: TenantRole,
    pub devices: &'a [TenantDeviceRecord],
    /// Devices with a live transport link to this gateway, keyed by
    /// organization and device. The caller resolves each link to its owning
    /// organization through the trusted device registry. Keys of other
    /// organizations may be present and never match.
    pub connected_devices: &'a BTreeSet<DeviceKey>,
    /// `None` when no subscription record exists for the organization.
    pub subscription: Option<&'a SubscriptionRecord>,
    /// `None` while usage metering is not wired to the request path.
    pub usage: Option<&'a [UsageRecord]>,
    pub now_unix_ms: u64,
}

/// Projects real tenant records into a live snapshot. Values the backend does
/// not track are reported as `unknown`, never guessed.
pub fn project_live_snapshot(
    input: &TenantProjectionInput<'_>,
) -> Result<DashboardSnapshot, ContractError> {
    let organization_id = input.organization.organization_id.as_str();
    let now = input.now_unix_ms;
    if input
        .devices
        .iter()
        .any(|device| device.organization_id != organization_id)
        || input
            .subscription
            .is_some_and(|subscription| subscription.organization_id != organization_id)
        || input.usage.is_some_and(|usage| {
            usage
                .iter()
                .any(|row| row.organization_id != organization_id)
        })
    {
        return Err(ContractError::CrossTenantRecord);
    }

    let mut devices: Vec<DeviceView> = input
        .devices
        .iter()
        .map(|device| {
            let key = DeviceKey::new(organization_id, device.device_id.as_str());
            let status = if device.revoked {
                DeviceStatus::Revoked
            } else if input.connected_devices.contains(&key) {
                DeviceStatus::Connected
            } else {
                DeviceStatus::NotConnected
            };
            DeviceView {
                device_id: device.device_id.clone(),
                workspace_ids: device.workspace_ids.iter().cloned().collect(),
                status: Observed::live(status, now),
                display_name: Observed::unknown(UnknownReason::NotReported),
                os: Observed::unknown(UnknownReason::NotReported),
                agent_version: Observed::unknown(UnknownReason::NotReported),
                capabilities: Observed::unknown(UnknownReason::NotReported),
                last_seen_unix_ms: Observed::unknown(UnknownReason::NotImplemented),
            }
        })
        .collect();
    devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));

    let count = |status: DeviceStatus| -> Result<u32, ContractError> {
        let matching = devices
            .iter()
            .filter(|device| device.status.known() == Some(&status))
            .count();
        u32::try_from(matching).map_err(|_| ContractError::TooManyDevices)
    };
    let total = u32::try_from(devices.len()).map_err(|_| ContractError::TooManyDevices)?;
    let summary = SummaryView {
        total_devices: Observed::live(total, now),
        connected_devices: Observed::live(count(DeviceStatus::Connected)?, now),
        revoked_devices: Observed::live(count(DeviceStatus::Revoked)?, now),
    };

    let subscription = match input.subscription {
        Some(record) => Observed::live(
            SubscriptionView {
                plan: record.plan.clone(),
                active: record.active,
            },
            now,
        ),
        None => Observed::unknown(UnknownReason::NotReported),
    };
    let usage = match input.usage {
        Some(rows) => Observed::live(
            rows.iter()
                .map(|row| UsageEntry {
                    workspace_id: row.workspace_id.clone(),
                    usage_key: row.usage_key.clone(),
                    units: row.units,
                })
                .collect(),
            now,
        ),
        None => Observed::unknown(UnknownReason::NotImplemented),
    };

    let snapshot = DashboardSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        mode: SnapshotMode::Live,
        generated_at_unix_ms: now,
        organization: OrganizationView {
            organization_id: organization_id.to_owned(),
            name: Observed::live(input.organization.name.clone(), now),
            viewer_role: Observed::live(input.viewer_role.into(), now),
        },
        summary,
        devices,
        subscription,
        usage,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

/// Synthetic preview data for UI development. Every observable value is
/// `simulated` or `unknown`, and this fixture uses reserved example names for
/// every identifier; nothing here describes a real operator, device or
/// network. That is a property of this producer, not a rule `validate()`
/// enforces on arbitrary simulated snapshots.
pub fn simulated_preview_snapshot(generated_at_unix_ms: u64) -> DashboardSnapshot {
    let device = |device_id: &str, name: &str, status: DeviceStatus, os: &str| DeviceView {
        device_id: device_id.to_owned(),
        workspace_ids: vec!["ws_example".to_owned()],
        status: Observed::simulated(status),
        display_name: Observed::simulated(name.to_owned()),
        os: Observed::simulated(os.to_owned()),
        agent_version: Observed::simulated("0.0.0-preview".to_owned()),
        capabilities: Observed::simulated(vec![
            "filesystem.read".to_owned(),
            "git.status".to_owned(),
        ]),
        last_seen_unix_ms: Observed::unknown(UnknownReason::NotImplemented),
    };
    DashboardSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        mode: SnapshotMode::Simulated,
        generated_at_unix_ms,
        organization: OrganizationView {
            organization_id: "org_example".to_owned(),
            name: Observed::simulated("Example Organization".to_owned()),
            viewer_role: Observed::simulated(ViewerRole::Admin),
        },
        summary: SummaryView {
            total_devices: Observed::simulated(3),
            connected_devices: Observed::simulated(1),
            revoked_devices: Observed::simulated(1),
        },
        devices: vec![
            device(
                "dev_example_laptop",
                "Example laptop",
                DeviceStatus::NotConnected,
                "Linux",
            ),
            device(
                "dev_example_retired",
                "Example retired device",
                DeviceStatus::Revoked,
                "Windows",
            ),
            device(
                "dev_example_workstation",
                "Example workstation",
                DeviceStatus::Connected,
                "Windows",
            ),
        ],
        subscription: Observed::simulated(SubscriptionView {
            plan: "preview".to_owned(),
            active: false,
        }),
        usage: Observed::unknown(UnknownReason::NotImplemented),
    }
}

pub fn snapshot_json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(DashboardSnapshot))
        .expect("generated JSON Schema is always serializable")
}
