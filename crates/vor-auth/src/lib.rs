// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

pub const TOKEN_BYTES: usize = 32;
pub const PAIRING_CODE_BYTES: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRecord {
    pub grant_id: String,
    #[serde(default = "default_local_id")]
    pub organization_id: String,
    pub actor_id: String,
    #[serde(default)]
    pub workspace_ids: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revoked: bool,
}

#[derive(Clone)]
pub struct IssuedGrant {
    token: String,
    pub record: GrantRecord,
}

impl IssuedGrant {
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for IssuedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedGrant")
            .field("token", &"<redacted>")
            .field("record", &self.record)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingRecord {
    pub pairing_id: String,
    pub scopes: BTreeSet<String>,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub grant_ttl_ms: u64,
}

#[derive(Clone)]
pub struct IssuedPairing {
    code: String,
    pub record: PairingRecord,
}

impl IssuedPairing {
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Debug for IssuedPairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedPairing")
            .field("code", &"<redacted>")
            .field("record", &self.record)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthClientRecord {
    pub redirect_uris: Vec<String>,
    pub client_name: String,
    pub registered_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Viewer,
    Operator,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub user_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationRecord {
    pub organization_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipRecord {
    pub organization_id: String,
    pub user_id: String,
    pub role: TenantRole,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRecord {
    pub organization_id: String,
    pub workspace_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantDeviceRecord {
    pub organization_id: String,
    pub device_id: String,
    pub workspace_ids: BTreeSet<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionRecord {
    pub organization_id: String,
    pub plan: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementRecord {
    pub organization_id: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageRecord {
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub usage_key: String,
    pub units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantContext {
    pub organization_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub workspace_id: Option<String>,
    pub role: TenantRole,
    pub scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    device_id: String,
    grants: BTreeMap<String, GrantRecord>,
    #[serde(default)]
    pairings: BTreeMap<String, PairingRecord>,
    #[serde(default)]
    oauth_clients: BTreeMap<String, OAuthClientRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TenantPersistedState {
    version: u32,
    users: BTreeMap<String, UserRecord>,
    organizations: BTreeMap<String, OrganizationRecord>,
    memberships: BTreeMap<String, MembershipRecord>,
    workspaces: BTreeMap<String, WorkspaceRecord>,
    devices: BTreeMap<String, TenantDeviceRecord>,
    subscriptions: BTreeMap<String, SubscriptionRecord>,
    entitlements: BTreeMap<String, EntitlementRecord>,
    usage: BTreeMap<String, UsageRecord>,
}

#[derive(Clone)]
pub struct GrantStore {
    path: Arc<PathBuf>,
    state: Arc<Mutex<PersistedState>>,
}

impl GrantStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state = if path.exists() {
            let bytes = fs::read(&path)?;
            let state: PersistedState = serde_json::from_slice(&bytes)?;
            validate_persisted_state(&state)?;
            if state.version != 1 || state.device_id.is_empty() {
                return Err(AuthError::InvalidState);
            }
            state
        } else {
            let state = PersistedState {
                version: 1,
                device_id: random_hex::<16>(),
                grants: BTreeMap::new(),
                pairings: BTreeMap::new(),
                oauth_clients: BTreeMap::new(),
            };
            persist_state(&path, &state)?;
            state
        };
        Ok(Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn device_id(&self) -> Result<String, AuthError> {
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_grant_state(&self.path, &mut state)?;
        Ok(state.device_id.clone())
    }

    fn mutate_state<T>(
        &self,
        mutate: impl FnOnce(&mut PersistedState) -> Result<T, AuthError>,
    ) -> Result<T, AuthError> {
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_grant_state(&self.path, &mut state)?;
        let mut next = state.clone();
        let result = mutate(&mut next)?;
        persist_state(&self.path, &next)?;
        *state = next;
        Ok(result)
    }

    pub fn register_oauth_client(
        &self,
        client_id: impl Into<String>,
        redirect_uris: Vec<String>,
        client_name: impl Into<String>,
        registered_at_unix_ms: u64,
    ) -> Result<OAuthClientRecord, AuthError> {
        let client_id = client_id.into();
        let client_name = client_name.into();
        if client_id.trim().is_empty() || client_name.trim().is_empty() || redirect_uris.is_empty()
        {
            return Err(AuthError::Unauthorized);
        }
        let record = OAuthClientRecord {
            redirect_uris,
            client_name,
            registered_at_unix_ms,
        };
        self.mutate_state(|state| {
            state.oauth_clients.insert(client_id, record.clone());
            Ok(record)
        })
    }

    pub fn oauth_client(&self, client_id: &str) -> Result<Option<OAuthClientRecord>, AuthError> {
        if client_id.is_empty() {
            return Ok(None);
        }
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_grant_state(&self.path, &mut state)?;
        Ok(state.oauth_clients.get(client_id).cloned())
    }

    pub fn issue(
        &self,
        actor_id: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        ttl_ms: u64,
        now_unix_ms: u64,
    ) -> Result<IssuedGrant, AuthError> {
        self.issue_for_tenant(
            "local",
            actor_id,
            std::iter::empty::<String>(),
            scopes,
            ttl_ms,
            now_unix_ms,
        )
    }

    pub fn issue_for_tenant(
        &self,
        organization_id: impl Into<String>,
        actor_id: impl Into<String>,
        workspace_ids: impl IntoIterator<Item = impl Into<String>>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        ttl_ms: u64,
        now_unix_ms: u64,
    ) -> Result<IssuedGrant, AuthError> {
        if ttl_ms == 0 {
            return Err(AuthError::InvalidTtl);
        }
        let organization_id = organization_id.into();
        validate_id(&organization_id)?;
        let actor_id = actor_id.into();
        validate_id(&actor_id).map_err(|_| AuthError::InvalidActor)?;
        let workspace_ids: BTreeSet<String> = workspace_ids
            .into_iter()
            .map(Into::into)
            .filter(|workspace_id: &String| !workspace_id.trim().is_empty())
            .collect();
        for workspace_id in &workspace_ids {
            validate_id(workspace_id)?;
        }
        let scopes: BTreeSet<String> = scopes
            .into_iter()
            .map(Into::into)
            .filter(|scope: &String| !scope.trim().is_empty())
            .collect();
        if scopes.is_empty() {
            return Err(AuthError::NoScopes);
        }
        let expires_at_unix_ms = now_unix_ms
            .checked_add(ttl_ms)
            .ok_or(AuthError::InvalidTtl)?;
        let token_bytes: [u8; TOKEN_BYTES] = rand::random();
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash = token_hash_hex(&token);
        let record = GrantRecord {
            grant_id: random_hex::<16>(),
            organization_id,
            actor_id,
            workspace_ids,
            scopes,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            revoked: false,
        };
        self.mutate_state(|state| {
            state.grants.insert(token_hash, record.clone());
            Ok(IssuedGrant { token, record })
        })
    }

    pub fn create_pairing(
        &self,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        pairing_ttl_ms: u64,
        grant_ttl_ms: u64,
        now_unix_ms: u64,
    ) -> Result<IssuedPairing, AuthError> {
        if pairing_ttl_ms == 0 || grant_ttl_ms == 0 {
            return Err(AuthError::InvalidTtl);
        }
        let scopes: BTreeSet<String> = scopes
            .into_iter()
            .map(Into::into)
            .filter(|scope: &String| !scope.trim().is_empty())
            .collect();
        if scopes.is_empty() {
            return Err(AuthError::NoScopes);
        }
        let expires_at_unix_ms = now_unix_ms
            .checked_add(pairing_ttl_ms)
            .ok_or(AuthError::InvalidTtl)?;
        let code_bytes: [u8; PAIRING_CODE_BYTES] = rand::random();
        let code = URL_SAFE_NO_PAD.encode(code_bytes);
        let record = PairingRecord {
            pairing_id: random_hex::<16>(),
            scopes,
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            grant_ttl_ms,
        };
        self.mutate_state(|state| {
            state.pairings.insert(token_hash_hex(&code), record.clone());
            Ok(IssuedPairing { code, record })
        })
    }

    pub fn validate(
        &self,
        token: &str,
        required_scope: &str,
        now_unix_ms: u64,
    ) -> Result<GrantRecord, AuthError> {
        if token.is_empty() || required_scope.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_grant_state(&self.path, &mut state)?;
        let Some(record) = state.grants.get(&token_hash_hex(token)) else {
            return Err(AuthError::Unauthorized);
        };
        if record.revoked || record.expires_at_unix_ms <= now_unix_ms {
            return Err(AuthError::Unauthorized);
        }
        if !record.scopes.contains(required_scope) && !record.scopes.contains("*") {
            return Err(AuthError::InsufficientScope(required_scope.to_owned()));
        }
        Ok(record.clone())
    }

    pub fn redeem_pairing(
        &self,
        code: &str,
        actor_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<IssuedGrant, AuthError> {
        let actor_id = actor_id.into();
        if code.is_empty() || actor_id.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let code_hash = token_hash_hex(code);
        self.mutate_state(|state| {
            let Some(pairing) = state.pairings.get(&code_hash).cloned() else {
                return Err(AuthError::Unauthorized);
            };
            if pairing.expires_at_unix_ms <= now_unix_ms {
                state.pairings.remove(&code_hash);
                return Err(AuthError::Unauthorized);
            }
            let expires_at_unix_ms = now_unix_ms
                .checked_add(pairing.grant_ttl_ms)
                .ok_or(AuthError::InvalidTtl)?;
            let token_bytes: [u8; TOKEN_BYTES] = rand::random();
            let token = URL_SAFE_NO_PAD.encode(token_bytes);
            let record = GrantRecord {
                grant_id: random_hex::<16>(),
                organization_id: "local".into(),
                actor_id,
                workspace_ids: BTreeSet::new(),
                scopes: pairing.scopes,
                issued_at_unix_ms: now_unix_ms,
                expires_at_unix_ms,
                revoked: false,
            };
            state.pairings.remove(&code_hash);
            state.grants.insert(token_hash_hex(&token), record.clone());
            Ok(IssuedGrant { token, record })
        })
    }

    pub fn validate_for_tenant(
        &self,
        token: &str,
        required_scope: &str,
        organization_id: &str,
        workspace_id: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<GrantRecord, AuthError> {
        let record = self.validate(token, required_scope, now_unix_ms)?;
        if record.organization_id != organization_id {
            return Err(AuthError::Unauthorized);
        }
        if let Some(workspace_id) = workspace_id
            && !record.workspace_ids.contains(workspace_id)
        {
            return Err(AuthError::Unauthorized);
        }
        Ok(record)
    }

    pub fn revoke(&self, grant_id: &str) -> Result<bool, AuthError> {
        self.revoke_matching(grant_id, None)
    }

    pub fn revoke_for_tenant(
        &self,
        grant_id: &str,
        organization_id: &str,
    ) -> Result<bool, AuthError> {
        validate_id(organization_id)?;
        self.revoke_matching(grant_id, Some(organization_id))
    }

    pub fn expire_for_tenant(
        &self,
        grant_id: &str,
        organization_id: &str,
        expires_at_unix_ms: u64,
    ) -> Result<bool, AuthError> {
        validate_id(organization_id)?;
        self.mutate_state(|state| {
            let Some((token_hash, mut record)) = state
                .grants
                .iter()
                .find(|(_, record)| {
                    record.grant_id == grant_id && record.organization_id == organization_id
                })
                .map(|(hash, record)| (hash.clone(), record.clone()))
            else {
                return Ok(false);
            };
            if expires_at_unix_ms < record.issued_at_unix_ms {
                return Err(AuthError::InvalidTtl);
            }
            record.expires_at_unix_ms = expires_at_unix_ms;
            state.grants.insert(token_hash, record);
            Ok(true)
        })
    }

    pub fn remove_workspace_for_tenant(
        &self,
        grant_id: &str,
        organization_id: &str,
        workspace_id: &str,
    ) -> Result<bool, AuthError> {
        validate_id(organization_id)?;
        validate_id(workspace_id)?;
        self.mutate_state(|state| {
            let Some((token_hash, mut record)) = state
                .grants
                .iter()
                .find(|(_, record)| {
                    record.grant_id == grant_id && record.organization_id == organization_id
                })
                .map(|(hash, record)| (hash.clone(), record.clone()))
            else {
                return Ok(false);
            };
            let removed = record.workspace_ids.remove(workspace_id);
            state.grants.insert(token_hash, record);
            Ok(removed)
        })
    }

    fn revoke_matching(
        &self,
        grant_id: &str,
        organization_id: Option<&str>,
    ) -> Result<bool, AuthError> {
        self.mutate_state(|state| {
            let Some((token_hash, mut record)) = state
                .grants
                .iter()
                .find(|(_, record)| {
                    record.grant_id == grant_id
                        && organization_id
                            .is_none_or(|organization_id| record.organization_id == organization_id)
                })
                .map(|(token_hash, record)| (token_hash.clone(), record.clone()))
            else {
                return Ok(false);
            };
            record.revoked = true;
            state.grants.insert(token_hash, record);
            Ok(true)
        })
    }

    pub fn prune_expired(&self, now_unix_ms: u64) -> Result<usize, AuthError> {
        self.mutate_state(|state| {
            let before = state.grants.len();
            state
                .grants
                .retain(|_, record| record.expires_at_unix_ms > now_unix_ms && !record.revoked);
            let removed = before - state.grants.len();
            Ok(removed)
        })
    }

    pub fn prune_expired_pairings(&self, now_unix_ms: u64) -> Result<usize, AuthError> {
        self.mutate_state(|state| {
            let before = state.pairings.len();
            state
                .pairings
                .retain(|_, record| record.expires_at_unix_ms > now_unix_ms);
            let removed = before - state.pairings.len();
            Ok(removed)
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, PersistedState>, AuthError> {
        self.state.lock().map_err(|_| AuthError::Poisoned)
    }
}

#[derive(Clone)]
pub struct TenantStore {
    path: Arc<PathBuf>,
    state: Arc<Mutex<TenantPersistedState>>,
}

impl TenantStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state = if path.exists() {
            let bytes = fs::read(&path)?;
            let state: TenantPersistedState = serde_json::from_slice(&bytes)?;
            validate_tenant_state(&state)?;
            state
        } else {
            let state = TenantPersistedState {
                version: 1,
                users: BTreeMap::new(),
                organizations: BTreeMap::new(),
                memberships: BTreeMap::new(),
                workspaces: BTreeMap::new(),
                devices: BTreeMap::new(),
                subscriptions: BTreeMap::new(),
                entitlements: BTreeMap::new(),
                usage: BTreeMap::new(),
            };
            persist_tenant_state(&path, &state)?;
            state
        };
        Ok(Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn upsert_user(&self, user_id: &str, display_name: &str) -> Result<(), AuthError> {
        validate_id(user_id)?;
        self.mutate_state(|state| {
            state.users.insert(
                user_id.to_owned(),
                UserRecord {
                    user_id: user_id.to_owned(),
                    display_name: display_name.to_owned(),
                },
            );
            Ok(())
        })
    }

    pub fn upsert_organization(&self, organization_id: &str, name: &str) -> Result<(), AuthError> {
        validate_id(organization_id)?;
        self.mutate_state(|state| {
            state.organizations.insert(
                organization_id.to_owned(),
                OrganizationRecord {
                    organization_id: organization_id.to_owned(),
                    name: name.to_owned(),
                },
            );
            Ok(())
        })
    }

    pub fn upsert_workspace(
        &self,
        organization_id: &str,
        workspace_id: &str,
        name: &str,
    ) -> Result<(), AuthError> {
        validate_id(workspace_id)?;
        validate_id(organization_id)?;
        self.mutate_state(|state| {
            if !state.organizations.contains_key(organization_id) {
                return Err(AuthError::Unauthorized);
            }
            state.workspaces.insert(
                tenant_key(organization_id, workspace_id),
                WorkspaceRecord {
                    organization_id: organization_id.to_owned(),
                    workspace_id: workspace_id.to_owned(),
                    name: name.to_owned(),
                },
            );
            Ok(())
        })
    }

    pub fn set_membership(
        &self,
        organization_id: &str,
        user_id: &str,
        role: TenantRole,
    ) -> Result<(), AuthError> {
        validate_id(organization_id)?;
        validate_id(user_id)?;
        self.mutate_state(|state| {
            if !state.organizations.contains_key(organization_id)
                || !state.users.contains_key(user_id)
            {
                return Err(AuthError::Unauthorized);
            }
            state.memberships.insert(
                tenant_key(organization_id, user_id),
                MembershipRecord {
                    organization_id: organization_id.to_owned(),
                    user_id: user_id.to_owned(),
                    role,
                    revoked: false,
                },
            );
            Ok(())
        })
    }

    pub fn revoke_membership(&self, organization_id: &str, user_id: &str) -> Result<(), AuthError> {
        validate_id(organization_id)?;
        validate_id(user_id)?;
        self.mutate_state(|state| {
            let key = tenant_key(organization_id, user_id);
            let Some(mut record) = state.memberships.get(&key).cloned() else {
                return Ok(());
            };
            record.revoked = true;
            state.memberships.insert(key, record);
            Ok(())
        })
    }

    pub fn pair_device(
        &self,
        organization_id: &str,
        device_id: &str,
        workspace_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<(), AuthError> {
        validate_id(device_id)?;
        validate_id(organization_id)?;
        let workspace_ids: BTreeSet<String> = workspace_ids.into_iter().map(Into::into).collect();
        for workspace_id in &workspace_ids {
            validate_id(workspace_id)?;
        }
        self.mutate_state(|state| {
            if !state.organizations.contains_key(organization_id) {
                return Err(AuthError::Unauthorized);
            }
            for workspace_id in &workspace_ids {
                if !state
                    .workspaces
                    .contains_key(&tenant_key(organization_id, workspace_id))
                {
                    return Err(AuthError::Unauthorized);
                }
            }
            state.devices.insert(
                tenant_key(organization_id, device_id),
                TenantDeviceRecord {
                    organization_id: organization_id.to_owned(),
                    device_id: device_id.to_owned(),
                    workspace_ids,
                    revoked: false,
                },
            );
            Ok(())
        })
    }

    pub fn revoke_device(&self, organization_id: &str, device_id: &str) -> Result<(), AuthError> {
        validate_id(organization_id)?;
        validate_id(device_id)?;
        self.mutate_state(|state| {
            let key = tenant_key(organization_id, device_id);
            let Some(mut record) = state.devices.get(&key).cloned() else {
                return Ok(());
            };
            record.revoked = true;
            state.devices.insert(key, record);
            Ok(())
        })
    }

    pub fn remove_device_workspace(
        &self,
        organization_id: &str,
        device_id: &str,
        workspace_id: &str,
    ) -> Result<bool, AuthError> {
        validate_id(organization_id)?;
        validate_id(device_id)?;
        validate_id(workspace_id)?;
        self.mutate_state(|state| {
            let key = tenant_key(organization_id, device_id);
            let Some(mut record) = state.devices.get(&key).cloned() else {
                return Ok(false);
            };
            let removed = record.workspace_ids.remove(workspace_id);
            state.devices.insert(key, record);
            Ok(removed)
        })
    }

    pub fn verify_context(
        &self,
        grant: &GrantRecord,
        organization_id: &str,
        device_id: &str,
        workspace_id: Option<&str>,
        required_role: TenantRole,
    ) -> Result<VerifiedTenantContext, AuthError> {
        validate_id(organization_id)?;
        validate_id(device_id)?;
        if let Some(workspace_id) = workspace_id {
            validate_id(workspace_id)?;
        }
        if grant.organization_id != organization_id {
            return Err(AuthError::Unauthorized);
        }
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_tenant_state(&self.path, &mut state)?;
        let membership = state
            .memberships
            .get(&tenant_key(organization_id, &grant.actor_id))
            .ok_or(AuthError::Unauthorized)?;
        if membership.revoked || membership.role < required_role {
            return Err(AuthError::Unauthorized);
        }
        let device = state
            .devices
            .get(&tenant_key(organization_id, device_id))
            .ok_or(AuthError::Unauthorized)?;
        if device.revoked {
            return Err(AuthError::Unauthorized);
        }
        if let Some(workspace_id) = workspace_id {
            if !state
                .workspaces
                .contains_key(&tenant_key(organization_id, workspace_id))
                || !device.workspace_ids.contains(workspace_id)
                || !grant.workspace_ids.contains(workspace_id)
            {
                return Err(AuthError::Unauthorized);
            }
        }
        Ok(VerifiedTenantContext {
            organization_id: organization_id.to_owned(),
            actor_id: grant.actor_id.clone(),
            device_id: device_id.to_owned(),
            workspace_id: workspace_id.map(str::to_owned),
            role: membership.role,
            scopes: grant.scopes.clone(),
        })
    }

    pub fn record_usage(
        &self,
        organization_id: &str,
        workspace_id: Option<&str>,
        usage_key: &str,
        units: u64,
    ) -> Result<(), AuthError> {
        validate_id(organization_id)?;
        if let Some(workspace_id) = workspace_id {
            validate_id(workspace_id)?;
        }
        validate_id(usage_key)?;
        self.mutate_state(|state| {
            if !state.organizations.contains_key(organization_id) {
                return Err(AuthError::Unauthorized);
            }
            let key = usage_key_for(organization_id, workspace_id, usage_key);
            state
                .usage
                .entry(key)
                .and_modify(|record| record.units = record.units.saturating_add(units))
                .or_insert_with(|| UsageRecord {
                    organization_id: organization_id.to_owned(),
                    workspace_id: workspace_id.map(str::to_owned),
                    usage_key: usage_key.to_owned(),
                    units,
                });
            Ok(())
        })
    }

    pub fn list_usage_for_org(&self, organization_id: &str) -> Result<Vec<UsageRecord>, AuthError> {
        validate_id(organization_id)?;
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_tenant_state(&self.path, &mut state)?;
        Ok(state
            .usage
            .values()
            .filter(|record| record.organization_id == organization_id)
            .cloned()
            .collect())
    }

    fn lock(&self) -> Result<MutexGuard<'_, TenantPersistedState>, AuthError> {
        self.state.lock().map_err(|_| AuthError::Poisoned)
    }

    fn mutate_state<T>(
        &self,
        mutate: impl FnOnce(&mut TenantPersistedState) -> Result<T, AuthError>,
    ) -> Result<T, AuthError> {
        let mut state = self.lock()?;
        let _guard = StoreFileLock::acquire(&self.path)?;
        refresh_tenant_state(&self.path, &mut state)?;
        let mut next = state.clone();
        let result = mutate(&mut next)?;
        persist_tenant_state(&self.path, &next)?;
        *state = next;
        Ok(result)
    }
}

fn default_local_id() -> String {
    "local".to_owned()
}

fn tenant_key(organization_id: &str, resource_id: &str) -> String {
    format!("{}:{}", organization_id.len(), organization_id) + ":" + resource_id
}

fn usage_key_for(organization_id: &str, workspace_id: Option<&str>, usage_key: &str) -> String {
    format!(
        "{}:{}:{}:{}",
        organization_id.len(),
        organization_id,
        workspace_id.unwrap_or("").len(),
        workspace_id.unwrap_or("")
    ) + ":"
        + usage_key
}

fn validate_id(value: &str) -> Result<(), AuthError> {
    if value.trim().is_empty() || value.chars().any(|ch| ch.is_control()) || value.len() > 256 {
        Err(AuthError::InvalidTenant)
    } else {
        Ok(())
    }
}

fn refresh_grant_state(
    path: &Path,
    state: &mut MutexGuard<'_, PersistedState>,
) -> Result<(), AuthError> {
    let bytes = fs::read(path)?;
    let fresh: PersistedState = serde_json::from_slice(&bytes)?;
    validate_persisted_state(&fresh)?;
    **state = fresh;
    Ok(())
}

fn refresh_tenant_state(
    path: &Path,
    state: &mut MutexGuard<'_, TenantPersistedState>,
) -> Result<(), AuthError> {
    let bytes = fs::read(path)?;
    let fresh: TenantPersistedState = serde_json::from_slice(&bytes)?;
    validate_tenant_state(&fresh)?;
    **state = fresh;
    Ok(())
}

fn validate_persisted_state(state: &PersistedState) -> Result<(), AuthError> {
    if state.version != 1 || state.device_id.is_empty() {
        return Err(AuthError::InvalidState);
    }
    for record in state.grants.values() {
        validate_id(&record.organization_id)?;
        validate_id(&record.actor_id).map_err(|_| AuthError::InvalidActor)?;
        for workspace_id in &record.workspace_ids {
            validate_id(workspace_id)?;
        }
    }
    Ok(())
}

fn validate_tenant_state(state: &TenantPersistedState) -> Result<(), AuthError> {
    if state.version != 1 {
        return Err(AuthError::InvalidState);
    }
    for (key, record) in &state.organizations {
        validate_id(&record.organization_id)?;
        if key != &record.organization_id {
            return Err(AuthError::InvalidState);
        }
    }
    for (key, record) in &state.users {
        validate_id(&record.user_id).map_err(|_| AuthError::InvalidActor)?;
        if key != &record.user_id {
            return Err(AuthError::InvalidState);
        }
    }
    for (key, record) in &state.memberships {
        validate_id(&record.organization_id)?;
        validate_id(&record.user_id).map_err(|_| AuthError::InvalidActor)?;
        if key != &tenant_key(&record.organization_id, &record.user_id) {
            return Err(AuthError::InvalidState);
        }
    }
    for (key, record) in &state.workspaces {
        validate_id(&record.organization_id)?;
        validate_id(&record.workspace_id)?;
        if key != &tenant_key(&record.organization_id, &record.workspace_id) {
            return Err(AuthError::InvalidState);
        }
    }
    for (key, record) in &state.devices {
        validate_id(&record.organization_id)?;
        validate_id(&record.device_id)?;
        if key != &tenant_key(&record.organization_id, &record.device_id) {
            return Err(AuthError::InvalidState);
        }
        for workspace_id in &record.workspace_ids {
            validate_id(workspace_id)?;
        }
    }
    for (key, record) in &state.usage {
        validate_id(&record.organization_id)?;
        if let Some(workspace_id) = &record.workspace_id {
            validate_id(workspace_id)?;
        }
        validate_id(&record.usage_key)?;
        if key
            != &usage_key_for(
                &record.organization_id,
                record.workspace_id.as_deref(),
                &record.usage_key,
            )
        {
            return Err(AuthError::InvalidState);
        }
    }
    Ok(())
}

fn random_hex<const N: usize>() -> String {
    let bytes: [u8; N] = rand::random();
    hex::encode(bytes)
}

fn token_hash_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn persist_state(path: &Path, state: &PersistedState) -> Result<(), AuthError> {
    let bytes = serde_json::to_vec_pretty(state)?;
    let temp = unique_temp_path(path);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    atomic_replace(&temp, path)?;
    Ok(())
}

fn persist_tenant_state(path: &Path, state: &TenantPersistedState) -> Result<(), AuthError> {
    let bytes = serde_json::to_vec_pretty(state)?;
    let temp = unique_temp_path(path);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    atomic_replace(&temp, path)?;
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "json.{}.{}.tmp",
        std::process::id(),
        random_hex::<8>()
    ))
}

struct StoreFileLock {
    path: PathBuf,
    _file: File,
}

impl StoreFileLock {
    fn acquire(state_path: &Path) -> Result<Self, AuthError> {
        let lock_path = state_path.with_extension("lock");
        for _ in 0..100 {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(file) => {
                    return Ok(Self {
                        path: lock_path,
                        _file: file,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(AuthError::LockTimeout)
    }
}

impl Drop for StoreFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> io::Result<()> {
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    let source = wide(source);
    let target = wide(target);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let ok = unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), flags) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, target: &Path) -> io::Result<()> {
    if target.exists() {
        fs::remove_file(target)?;
    }
    fs::rename(source, target)
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth state is invalid")]
    InvalidState,
    #[error("grant TTL must be positive and representable")]
    InvalidTtl,
    #[error("actor id must not be empty")]
    InvalidActor,
    #[error("tenant identifier is invalid")]
    InvalidTenant,
    #[error("grant requires at least one scope")]
    NoScopes,
    #[error("grant is unauthorized or expired")]
    Unauthorized,
    #[error("grant lacks required scope: {0}")]
    InsufficientScope(String),
    #[error("auth state lock is poisoned")]
    Poisoned,
    #[error("auth state file lock timed out")]
    LockTimeout,
    #[error("auth state I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("auth state JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn issued_token_is_not_persisted_raw_and_survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let store = GrantStore::open(&path).unwrap();
        let device = store.device_id().unwrap();
        let issued = store.issue("operator", ["mcp"], 1_000, 10).unwrap();
        assert!(store.validate(issued.token(), "mcp", 100).is_ok());

        let disk = fs::read_to_string(&path).unwrap();
        assert!(!disk.contains(issued.token()));
        assert!(disk.contains(&token_hash_hex(issued.token())));
        drop(store);

        let reopened = GrantStore::open(&path).unwrap();
        assert_eq!(reopened.device_id().unwrap(), device);
        assert!(reopened.validate(issued.token(), "mcp", 100).is_ok());
    }

    #[test]
    fn scope_expiry_and_revoke_fail_closed() {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let issued = store.issue("operator", ["mcp"], 100, 1_000).unwrap();
        assert!(matches!(
            store.validate(issued.token(), "admin", 1_001),
            Err(AuthError::InsufficientScope(_))
        ));
        assert!(matches!(
            store.validate(issued.token(), "mcp", 1_100),
            Err(AuthError::Unauthorized)
        ));

        let second = store.issue("operator", ["mcp"], 1_000, 2_000).unwrap();
        assert!(store.revoke(&second.record.grant_id).unwrap());
        assert!(matches!(
            store.validate(second.token(), "mcp", 2_001),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn pairing_code_is_one_time_and_never_persisted_raw() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let store = GrantStore::open(&path).unwrap();
        let pairing = store
            .create_pairing(["mcp", "gateway.read"], 1_000, 5_000, 100)
            .unwrap();
        let disk = fs::read_to_string(&path).unwrap();
        assert!(!disk.contains(pairing.code()));
        let issued = store
            .redeem_pairing(pairing.code(), "client-a", 200)
            .unwrap();
        assert!(store.validate(issued.token(), "mcp", 300).is_ok());
        assert!(matches!(
            store.redeem_pairing(pairing.code(), "client-b", 300),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn oauth_client_survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let store = GrantStore::open(&path).unwrap();
        let redirect_uris = vec![
            "https://chatgpt.com/connector/oauth/callback".to_owned(),
            "https://chatgpt.com/connector_platform_oauth_redirect".to_owned(),
        ];
        let expected = store
            .register_oauth_client(
                "client-persisted",
                redirect_uris,
                "ChatGPT",
                1_726_000_000_000,
            )
            .unwrap();
        drop(store);

        let reopened = GrantStore::open(&path).unwrap();
        assert_eq!(
            reopened.oauth_client("client-persisted").unwrap(),
            Some(expected)
        );
        assert_eq!(reopened.oauth_client("missing").unwrap(), None);
    }

    #[test]
    fn debug_redacts_raw_token() {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let issued = store.issue("operator", ["mcp"], 1_000, 0).unwrap();
        let debug = format!("{issued:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(issued.token()));
    }

    fn seed_tenants(path: &Path) -> TenantStore {
        let tenants = TenantStore::open(path).unwrap();
        tenants.upsert_user("user-a", "A").unwrap();
        tenants.upsert_user("user-b", "B").unwrap();
        tenants.upsert_user("shared", "Shared").unwrap();
        tenants.upsert_organization("org-a", "Org A").unwrap();
        tenants.upsert_organization("org-b", "Org B").unwrap();
        tenants.upsert_workspace("org-a", "ws-a1", "A1").unwrap();
        tenants.upsert_workspace("org-a", "ws-a2", "A2").unwrap();
        tenants.upsert_workspace("org-b", "ws-b1", "B1").unwrap();
        tenants
            .set_membership("org-a", "user-a", TenantRole::Admin)
            .unwrap();
        tenants
            .set_membership("org-b", "user-b", TenantRole::Admin)
            .unwrap();
        tenants
            .set_membership("org-a", "shared", TenantRole::Operator)
            .unwrap();
        tenants
            .set_membership("org-b", "shared", TenantRole::Viewer)
            .unwrap();
        tenants.pair_device("org-a", "device-a", ["ws-a1"]).unwrap();
        tenants.pair_device("org-b", "device-b", ["ws-b1"]).unwrap();
        tenants
    }

    #[test]
    fn tenant_context_enforces_org_workspace_device_role_and_persists() {
        let dir = tempdir().unwrap();
        let tenants_path = dir.path().join("tenants.json");
        let grants_path = dir.path().join("auth.json");
        let tenants = seed_tenants(&tenants_path);
        let grants = GrantStore::open(&grants_path).unwrap();
        let grant_a = grants
            .issue_for_tenant("org-a", "shared", ["ws-a1"], ["mcp"], 10_000, 1_000)
            .unwrap();
        let grant_b = grants
            .issue_for_tenant("org-b", "shared", ["ws-b1"], ["mcp"], 10_000, 1_000)
            .unwrap();

        let ctx = tenants
            .verify_context(
                &grant_a.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            )
            .unwrap();
        assert_eq!(ctx.organization_id, "org-a");
        assert_eq!(ctx.workspace_id.as_deref(), Some("ws-a1"));
        assert!(matches!(
            tenants.verify_context(
                &grant_a.record,
                "org-b",
                "device-b",
                Some("ws-b1"),
                TenantRole::Viewer
            ),
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            tenants.verify_context(
                &grant_a.record,
                "org-a",
                "device-a",
                Some("ws-a2"),
                TenantRole::Operator
            ),
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            tenants.verify_context(
                &grant_b.record,
                "org-b",
                "device-b",
                Some("ws-b1"),
                TenantRole::Operator
            ),
            Err(AuthError::Unauthorized)
        ));

        tenants
            .record_usage("org-a", Some("ws-a1"), "same-key", 3)
            .unwrap();
        tenants
            .record_usage("org-b", Some("ws-b1"), "same-key", 7)
            .unwrap();
        assert_eq!(tenants.list_usage_for_org("org-a").unwrap()[0].units, 3);
        assert_eq!(tenants.list_usage_for_org("org-b").unwrap()[0].units, 7);
        drop(tenants);
        drop(grants);

        let reopened_tenants = TenantStore::open(&tenants_path).unwrap();
        let reopened_grants = GrantStore::open(&grants_path).unwrap();
        let reopened_grant = reopened_grants
            .validate_for_tenant(grant_a.token(), "mcp", "org-a", Some("ws-a1"), 2_000)
            .unwrap();
        reopened_tenants
            .verify_context(
                &reopened_grant,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            )
            .unwrap();
    }

    #[test]
    fn tenant_revocation_blocks_prepared_grant_without_erasing_other_tenant() {
        let dir = tempdir().unwrap();
        let tenants = seed_tenants(&dir.path().join("tenants.json"));
        let grants = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let grant_a = grants
            .issue_for_tenant("org-a", "shared", ["ws-a1"], ["mcp"], 10_000, 1_000)
            .unwrap();
        let grant_b = grants
            .issue_for_tenant("org-b", "user-b", ["ws-b1"], ["mcp"], 10_000, 1_000)
            .unwrap();
        tenants.revoke_membership("org-a", "shared").unwrap();
        assert!(matches!(
            tenants.verify_context(
                &grant_a.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Viewer
            ),
            Err(AuthError::Unauthorized)
        ));
        tenants
            .verify_context(
                &grant_b.record,
                "org-b",
                "device-b",
                Some("ws-b1"),
                TenantRole::Admin,
            )
            .unwrap();
    }

    #[test]
    fn empty_workspace_grant_does_not_authorize_workspace_bound_actions() {
        let dir = tempdir().unwrap();
        let tenants = seed_tenants(&dir.path().join("tenants.json"));
        let grants = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let legacy = grants.issue("shared", ["mcp"], 10_000, 1_000).unwrap();
        assert!(matches!(
            grants.validate_for_tenant(legacy.token(), "mcp", "local", Some("ws-a1"), 2_000),
            Err(AuthError::Unauthorized)
        ));

        let tenant_grant = grants
            .issue_for_tenant(
                "org-a",
                "shared",
                std::iter::empty::<String>(),
                ["mcp"],
                10_000,
                1_000,
            )
            .unwrap();
        tenants
            .verify_context(
                &tenant_grant.record,
                "org-a",
                "device-a",
                None,
                TenantRole::Operator,
            )
            .unwrap();
        assert!(matches!(
            tenants.verify_context(
                &tenant_grant.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            ),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn independent_instances_refresh_revocations_before_authorizing() {
        let dir = tempdir().unwrap();
        let tenants_path = dir.path().join("tenants.json");
        let grants_path = dir.path().join("auth.json");
        let tenants_a = seed_tenants(&tenants_path);
        let tenants_b = TenantStore::open(&tenants_path).unwrap();
        let grants_a = GrantStore::open(&grants_path).unwrap();
        let grants_b = GrantStore::open(&grants_path).unwrap();
        let issued = grants_a
            .issue_for_tenant("org-a", "shared", ["ws-a1"], ["mcp"], 10_000, 1_000)
            .unwrap();

        grants_b
            .validate_for_tenant(issued.token(), "mcp", "org-a", Some("ws-a1"), 2_000)
            .unwrap();
        grants_a.revoke(&issued.record.grant_id).unwrap();
        assert!(matches!(
            grants_b.validate_for_tenant(issued.token(), "mcp", "org-a", Some("ws-a1"), 2_001),
            Err(AuthError::Unauthorized)
        ));

        tenants_b
            .verify_context(
                &issued.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            )
            .unwrap();
        tenants_a.revoke_device("org-a", "device-a").unwrap();
        assert!(matches!(
            tenants_b.verify_context(
                &issued.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            ),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn stale_grant_writer_cannot_restore_revoked_grant_or_pairing_prune_snapshot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let a = GrantStore::open(&path).unwrap();
        let b = GrantStore::open(&path).unwrap();
        let c = GrantStore::open(&path).unwrap();
        let victim = a.issue("operator", ["mcp"], 10_000, 1_000).unwrap();
        let stale_pairing = a.create_pairing(["mcp"], 1, 10_000, 1_000).unwrap();
        b.revoke(&victim.record.grant_id).unwrap();

        let unrelated = a.issue("other", ["gateway.read"], 10_000, 1_001).unwrap();
        assert!(c.validate(unrelated.token(), "gateway.read", 1_002).is_ok());
        assert!(matches!(
            c.validate(victim.token(), "mcp", 1_002),
            Err(AuthError::Unauthorized)
        ));

        assert_eq!(a.prune_expired_pairings(1_002).unwrap(), 1);
        assert!(matches!(
            c.redeem_pairing(stale_pairing.code(), "late", 1_003),
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            c.validate(victim.token(), "mcp", 1_004),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn grant_expiry_and_workspace_scope_mutations_persist() {
        let dir = tempdir().unwrap();
        let grants_path = dir.path().join("auth.json");
        let grants_a = GrantStore::open(&grants_path).unwrap();
        let grants_b = GrantStore::open(&grants_path).unwrap();
        let issued = grants_a
            .issue_for_tenant(
                "org-a",
                "shared",
                ["ws-a1", "ws-a2"],
                ["mcp"],
                10_000,
                1_000,
            )
            .unwrap();

        assert!(
            grants_a
                .expire_for_tenant(&issued.record.grant_id, "org-a", 2_000)
                .unwrap()
        );
        assert!(matches!(
            grants_b.validate_for_tenant(issued.token(), "mcp", "org-a", Some("ws-a1"), 2_000),
            Err(AuthError::Unauthorized)
        ));

        let scoped = grants_a
            .issue_for_tenant(
                "org-a",
                "shared",
                ["ws-a1", "ws-a2"],
                ["mcp"],
                10_000,
                3_000,
            )
            .unwrap();
        assert!(
            grants_b
                .remove_workspace_for_tenant(&scoped.record.grant_id, "org-a", "ws-a1")
                .unwrap()
        );
        assert!(matches!(
            grants_a.validate_for_tenant(scoped.token(), "mcp", "org-a", Some("ws-a1"), 3_100),
            Err(AuthError::Unauthorized)
        ));
        grants_a
            .validate_for_tenant(scoped.token(), "mcp", "org-a", Some("ws-a2"), 3_100)
            .unwrap();
    }

    #[test]
    fn device_workspace_scope_mutation_persists_without_revoking_device() {
        let dir = tempdir().unwrap();
        let tenants_path = dir.path().join("tenants.json");
        let grants_path = dir.path().join("auth.json");
        let tenants_a = seed_tenants(&tenants_path);
        let tenants_b = TenantStore::open(&tenants_path).unwrap();
        tenants_a.upsert_workspace("org-a", "ws-a2", "A2").unwrap();
        tenants_a
            .pair_device("org-a", "device-a", ["ws-a1", "ws-a2"])
            .unwrap();
        let grants = GrantStore::open(&grants_path).unwrap();
        let issued = grants
            .issue_for_tenant(
                "org-a",
                "shared",
                ["ws-a1", "ws-a2"],
                ["mcp"],
                10_000,
                1_000,
            )
            .unwrap();

        assert!(
            tenants_b
                .remove_device_workspace("org-a", "device-a", "ws-a1")
                .unwrap()
        );
        assert!(matches!(
            tenants_a.verify_context(
                &issued.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            ),
            Err(AuthError::Unauthorized)
        ));
        tenants_a
            .verify_context(
                &issued.record,
                "org-a",
                "device-a",
                Some("ws-a2"),
                TenantRole::Operator,
            )
            .unwrap();
    }

    #[test]
    fn stale_tenant_writer_cannot_restore_membership_or_device_revocation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tenants.json");
        let a = seed_tenants(&path);
        let b = TenantStore::open(&path).unwrap();
        let c = TenantStore::open(&path).unwrap();
        let grants = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let grant = grants
            .issue_for_tenant("org-a", "shared", ["ws-a1"], ["mcp"], 10_000, 1_000)
            .unwrap();
        b.revoke_membership("org-a", "shared").unwrap();
        a.upsert_user("unrelated", "Unrelated").unwrap();
        assert!(matches!(
            c.verify_context(
                &grant.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Viewer,
            ),
            Err(AuthError::Unauthorized)
        ));

        c.set_membership("org-a", "shared", TenantRole::Operator)
            .unwrap();
        b.revoke_device("org-a", "device-a").unwrap();
        a.record_usage("org-a", Some("ws-a1"), "usage-a", 1)
            .unwrap();
        assert!(matches!(
            c.verify_context(
                &grant.record,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Operator,
            ),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn missing_or_invalid_opened_state_fails_closed_without_memory_fallback() {
        let dir = tempdir().unwrap();
        let grants_path = dir.path().join("auth.json");
        let grants = GrantStore::open(&grants_path).unwrap();
        let issued = grants.issue("operator", ["mcp"], 10_000, 1_000).unwrap();
        fs::remove_file(&grants_path).unwrap();
        assert!(matches!(
            grants.validate(issued.token(), "mcp", 1_001),
            Err(AuthError::Io(_))
        ));
        assert!(matches!(
            grants.issue("other", ["mcp"], 10_000, 1_001),
            Err(AuthError::Io(_))
        ));

        let tenants_path = dir.path().join("tenants.json");
        let tenants = seed_tenants(&tenants_path);
        let grant = GrantRecord {
            grant_id: "synthetic".into(),
            organization_id: "org-a".into(),
            actor_id: "shared".into(),
            workspace_ids: ["ws-a1".to_owned()].into_iter().collect(),
            scopes: ["mcp".to_owned()].into_iter().collect(),
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 10_000,
            revoked: false,
        };
        fs::write(&tenants_path, b"{not-json").unwrap();
        assert!(matches!(
            tenants.verify_context(
                &grant,
                "org-a",
                "device-a",
                Some("ws-a1"),
                TenantRole::Viewer,
            ),
            Err(AuthError::Json(_))
        ));
        assert!(matches!(
            tenants.upsert_user("new-user", "New"),
            Err(AuthError::Json(_))
        ));
    }

    #[test]
    fn malformed_composite_key_fixture_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tenants.json");
        let bad = serde_json::json!({
            "version": 1,
            "users": {"user-a": {"user_id": "user-a", "display_name": "A"}},
            "organizations": {"org-a": {"organization_id": "org-a", "name": "A"}},
            "memberships": {"org-a\u{0}user-a": {
                "organization_id": "org-a",
                "user_id": "user-a",
                "role": "admin",
                "revoked": false
            }},
            "workspaces": {},
            "devices": {},
            "subscriptions": {},
            "entitlements": {},
            "usage": {}
        });
        fs::write(&path, serde_json::to_vec_pretty(&bad).unwrap()).unwrap();
        assert!(matches!(
            TenantStore::open(&path),
            Err(AuthError::InvalidState)
        ));
    }
}
