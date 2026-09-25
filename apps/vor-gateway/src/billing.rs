// SPDX-License-Identifier: MPL-2.0

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::{GatewayState, GrantContext};
use axum::Extension;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";
const STRIPE_API_VERSION: &str = "2026-07-29.dahlia";
const SIGNATURE_TOLERANCE_SECONDS: u64 = 300;
const ACTIVE_SUBSCRIPTION_STATUSES: &[&str] = &["active", "trialing"];

#[derive(Debug, Clone, Serialize)]
pub struct BillingConfig {
    pub mode: BillingMode,
    pub personal_cloud_price_id: String,
    pub teams_price_id: String,
    pub success_url: String,
    pub cancel_url: String,
    pub portal_return_url: String,
    #[serde(skip_serializing)]
    api_key: Option<String>,
    #[serde(skip_serializing)]
    webhook_secret: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillingMode {
    Sandbox,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedBillingState {
    version: u32,
    #[serde(default)]
    events: BTreeMap<String, BillingEventRecord>,
    #[serde(default)]
    customers: BTreeMap<String, BillingCustomerRecord>,
    #[serde(default)]
    subscriptions: BTreeMap<String, BillingSubscriptionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BillingEventRecord {
    event_id: String,
    event_type: String,
    processed_at_unix_seconds: u64,
    organization_id: Option<String>,
    applied: bool,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BillingCustomerRecord {
    organization_id: String,
    stripe_customer_id: String,
    updated_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BillingSubscriptionRecord {
    organization_id: String,
    stripe_customer_id: String,
    stripe_subscription_id: String,
    status: String,
    plan_id: Option<String>,
    price_id: Option<String>,
    current_period_end: Option<u64>,
    entitlement_active: bool,
    updated_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BillingStoreSummary {
    persistent: bool,
    processed_events: usize,
    customers: usize,
    subscriptions: usize,
    active_entitlements: usize,
}

#[derive(Clone)]
pub struct BillingStore {
    path: Option<Arc<PathBuf>>,
    state: Arc<Mutex<PersistedBillingState>>,
}

impl BillingStore {
    pub fn from_env() -> Result<Self, BillingError> {
        match env::var("VOR_BILLING_STATE_PATH") {
            Ok(path) if !path.trim().is_empty() => Self::open(PathBuf::from(path)),
            _ => Ok(Self::memory()),
        }
    }

    #[cfg(test)]
    fn memory() -> Self {
        Self {
            path: None,
            state: Arc::new(Mutex::new(PersistedBillingState::default())),
        }
    }

    #[cfg(not(test))]
    fn memory() -> Self {
        Self {
            path: None,
            state: Arc::new(Mutex::new(PersistedBillingState::default())),
        }
    }

    fn open(path: PathBuf) -> Result<Self, BillingError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state = if path.exists() {
            let bytes = fs::read(&path)?;
            let state: PersistedBillingState = serde_json::from_slice(&bytes)?;
            if state.version != 1 {
                return Err(BillingError::InvalidState);
            }
            state
        } else {
            let state = PersistedBillingState::default();
            persist_state(&path, &state)?;
            state
        };
        Ok(Self {
            path: Some(Arc::new(path)),
            state: Arc::new(Mutex::new(state)),
        })
    }

    fn summary(&self) -> Result<BillingStoreSummary, BillingError> {
        let state = self.lock()?;
        Ok(BillingStoreSummary {
            persistent: self.path.is_some(),
            processed_events: state.events.len(),
            customers: state.customers.len(),
            subscriptions: state.subscriptions.len(),
            active_entitlements: state
                .subscriptions
                .values()
                .filter(|subscription| subscription.entitlement_active)
                .count(),
        })
    }

    fn customer_belongs_to(
        &self,
        organization_id: &str,
        stripe_customer_id: &str,
    ) -> Result<bool, BillingError> {
        Ok(self
            .lock()?
            .customers
            .get(stripe_customer_id)
            .is_some_and(|record| record.organization_id == organization_id))
    }

    fn apply_test_webhook(
        &self,
        event: &Value,
        now: u64,
    ) -> Result<WebhookApplyResult, BillingError> {
        let event_id = required_str(event, "id")?;
        let event_type = required_str(event, "type")?;
        let mut state = self.lock()?;
        if state.events.contains_key(&event_id) {
            return Ok(WebhookApplyResult {
                event_id,
                event_type,
                duplicate: true,
                applied: false,
                organization_id: None,
                reason: "already_processed".to_owned(),
            });
        }

        let mut result = apply_event_to_state(&mut state, &event_id, &event_type, event, now)?;
        state.events.insert(
            event_id.clone(),
            BillingEventRecord {
                event_id,
                event_type,
                processed_at_unix_seconds: now,
                organization_id: result.organization_id.clone(),
                applied: result.applied,
                reason: result.reason.clone(),
            },
        );
        self.persist_locked(&state)?;
        result.duplicate = false;
        Ok(result)
    }

    fn lock(&self) -> Result<MutexGuard<'_, PersistedBillingState>, BillingError> {
        self.state.lock().map_err(|_| BillingError::InvalidState)
    }

    fn persist_locked(&self, state: &PersistedBillingState) -> Result<(), BillingError> {
        if let Some(path) = &self.path {
            persist_state(path, state)?;
        }
        Ok(())
    }
}

impl Default for PersistedBillingState {
    fn default() -> Self {
        Self {
            version: 1,
            events: BTreeMap::new(),
            customers: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct WebhookApplyResult {
    event_id: String,
    event_type: String,
    duplicate: bool,
    applied: bool,
    organization_id: Option<String>,
    reason: String,
}

impl BillingConfig {
    pub fn from_env() -> Self {
        let api_key = first_env(["VOR_STRIPE_API_KEY", "STRIPE_API_KEY"]);
        let mode = match api_key.as_deref() {
            Some(key) if key.starts_with("rk_live_") || key.starts_with("sk_live_") => {
                BillingMode::Disabled
            }
            Some(_) => BillingMode::Sandbox,
            None => BillingMode::Disabled,
        };
        Self {
            mode,
            personal_cloud_price_id: env::var("VOR_STRIPE_PERSONAL_CLOUD_PRICE_ID")
                .unwrap_or_else(|_| "price_1UHVumCXc73VlrPxMTs4PBm4".to_owned()),
            teams_price_id: env::var("VOR_STRIPE_TEAMS_PRICE_ID")
                .unwrap_or_else(|_| "price_1UHVumCXc73VlrPxpDjOft57".to_owned()),
            success_url: env::var("VOR_STRIPE_CHECKOUT_SUCCESS_URL").unwrap_or_else(|_| {
                "https://vorcommander.app/billing/success?session_id={CHECKOUT_SESSION_ID}"
                    .to_owned()
            }),
            cancel_url: env::var("VOR_STRIPE_CHECKOUT_CANCEL_URL")
                .unwrap_or_else(|_| "https://vorcommander.app/billing".to_owned()),
            portal_return_url: env::var("VOR_STRIPE_PORTAL_RETURN_URL")
                .unwrap_or_else(|_| "https://vorcommander.app/billing".to_owned()),
            api_key,
            webhook_secret: first_env(["VOR_STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET"]),
        }
    }

    #[cfg(test)]
    pub fn test_disabled() -> Self {
        Self {
            mode: BillingMode::Disabled,
            personal_cloud_price_id: "price_personal_test".into(),
            teams_price_id: "price_teams_test".into(),
            success_url: "https://example.test/success?session_id={CHECKOUT_SESSION_ID}".into(),
            cancel_url: "https://example.test/billing".into(),
            portal_return_url: "https://example.test/billing".into(),
            api_key: None,
            webhook_secret: None,
        }
    }

    fn api_key(&self) -> Result<&str, BillingError> {
        if self.mode != BillingMode::Sandbox {
            return Err(BillingError::NotConfigured);
        }
        let Some(key) = self.api_key.as_deref() else {
            return Err(BillingError::NotConfigured);
        };
        if key.starts_with("rk_live_") || key.starts_with("sk_live_") {
            return Err(BillingError::LiveKeyRejected);
        }
        if !key.starts_with("rk_test_")
            && !key.starts_with("sk_test_")
            && !key.starts_with("rkcs_test_")
        {
            return Err(BillingError::InvalidKey);
        }
        Ok(key)
    }

    fn price_for(&self, plan_id: PlanId) -> &str {
        match plan_id {
            PlanId::PersonalCloud => &self.personal_cloud_price_id,
            PlanId::Teams => &self.teams_price_id,
        }
    }
}

fn first_env<const N: usize>(names: [&str; N]) -> Option<String> {
    names
        .into_iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

#[derive(Debug, Deserialize)]
pub struct CreateCheckoutSessionBody {
    organization_id: String,
    plan_id: PlanId,
    quantity: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePortalSessionBody {
    organization_id: String,
    stripe_customer_id: String,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
enum PlanId {
    PersonalCloud,
    Teams,
}

impl PlanId {
    fn as_str(self) -> &'static str {
        match self {
            PlanId::PersonalCloud => "personal-cloud",
            PlanId::Teams => "teams",
        }
    }
}

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("billing is not configured")]
    NotConfigured,
    #[error("live Stripe keys are rejected by this test-mode gateway")]
    LiveKeyRejected,
    #[error("Stripe key must be a test restricted or test secret key")]
    InvalidKey,
    #[error("billing request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("Stripe request failed")]
    StripeRequest,
    #[error("Stripe response was invalid")]
    StripeResponse,
    #[error("webhook signature is missing or invalid")]
    InvalidSignature,
    #[error("webhook secret is not configured")]
    MissingWebhookSecret,
    #[error("system clock is outside supported range")]
    Clock,
    #[error("billing state is invalid")]
    InvalidState,
    #[error("billing state I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("billing state JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl BillingError {
    fn status(&self) -> StatusCode {
        match self {
            Self::NotConfigured | Self::LiveKeyRejected | Self::InvalidKey => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::InvalidRequest(_) | Self::InvalidSignature | Self::MissingWebhookSecret => {
                StatusCode::BAD_REQUEST
            }
            Self::InvalidState => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Io(_)
            | Self::Json(_)
            | Self::StripeRequest
            | Self::StripeResponse
            | Self::Clock => StatusCode::BAD_GATEWAY,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "billing_not_configured",
            Self::LiveKeyRejected => "live_key_rejected",
            Self::InvalidKey => "invalid_stripe_key",
            Self::InvalidRequest(_) => "invalid_billing_request",
            Self::StripeRequest => "stripe_request_failed",
            Self::StripeResponse => "stripe_response_invalid",
            Self::InvalidSignature => "invalid_webhook_signature",
            Self::MissingWebhookSecret => "missing_webhook_secret",
            Self::Clock => "clock_unavailable",
            Self::InvalidState => "billing_state_invalid",
            Self::Io(_) => "billing_state_io_failed",
            Self::Json(_) => "billing_state_json_failed",
        }
    }
}

pub async fn status(State(state): State<GatewayState>) -> Json<Value> {
    let billing = &state.billing;
    let store = state.billing_store.summary().ok();
    Json(json!({
        "mode": billing.mode,
        "charges_enabled": false,
        "provider": "stripe",
        "checkout": {
            "enabled": billing.mode == BillingMode::Sandbox,
            "personal_cloud_price_id": billing.personal_cloud_price_id,
            "teams_price_id": billing.teams_price_id
        },
        "customer_portal": {
            "enabled": billing.mode == BillingMode::Sandbox
        },
        "webhooks": {
            "configured": billing.webhook_secret.is_some()
        },
        "state": store,
        "authority_boundary": "hosted_capacity_only"
    }))
}

pub async fn create_checkout_session(
    State(state): State<GatewayState>,
    Extension(grant): Extension<GrantContext>,
    Json(body): Json<CreateCheckoutSessionBody>,
) -> Response {
    match create_checkout_session_inner(
        &state.billing,
        &grant.0.organization_id,
        &grant.0.actor_id,
        body,
    )
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => billing_error(error),
    }
}

pub async fn create_portal_session(
    State(state): State<GatewayState>,
    Extension(grant): Extension<GrantContext>,
    Json(body): Json<CreatePortalSessionBody>,
) -> Response {
    match create_portal_session_inner(
        &state.billing,
        &state.billing_store,
        &grant.0.organization_id,
        body,
    )
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => billing_error(error),
    }
}

pub async fn webhook(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match webhook_inner(&state.billing, &state.billing_store, &headers, &body) {
        Ok(value) => Json(value).into_response(),
        Err(error) => billing_error(error),
    }
}

async fn create_checkout_session_inner(
    config: &BillingConfig,
    authenticated_organization_id: &str,
    actor_id: &str,
    body: CreateCheckoutSessionBody,
) -> Result<Value, BillingError> {
    let organization_id = clean_id(&body.organization_id, "organization_id")?;
    if organization_id != authenticated_organization_id {
        return Err(BillingError::InvalidRequest(
            "organization_id is outside the authenticated grant",
        ));
    }
    let quantity = body.quantity.unwrap_or(1);
    if quantity == 0 || quantity > 1_000 {
        return Err(BillingError::InvalidRequest(
            "quantity must be between 1 and 1000",
        ));
    }
    let price = config.price_for(body.plan_id).to_owned();
    let api_key = config.api_key()?.to_owned();
    let success_url = config.success_url.clone();
    let cancel_url = config.cancel_url.clone();
    let plan_id = body.plan_id.as_str().to_owned();
    let actor_id = actor_id.to_owned();
    tokio::task::spawn_blocking(move || {
        let auth = format!("Bearer {api_key}");
        let mut response = ureq::post(format!("{STRIPE_API_BASE}/checkout/sessions"))
            .header("Authorization", auth)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .send_form([
                ("mode", "subscription".to_owned()),
                ("success_url", success_url),
                ("cancel_url", cancel_url),
                ("line_items[0][price]", price),
                ("line_items[0][quantity]", quantity.to_string()),
                ("client_reference_id", organization_id.clone()),
                ("metadata[organization_id]", organization_id.clone()),
                ("metadata[plan_id]", plan_id.clone()),
                ("metadata[requested_by_actor_id]", actor_id),
                (
                    "integration_identifier",
                    format!("vor_commander_{}", random_letters::<8>()),
                ),
            ])
            .map_err(|_| BillingError::StripeRequest)?;
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|_| BillingError::StripeResponse)?;
        let value: Value = serde_json::from_str(&text).map_err(|_| BillingError::StripeResponse)?;
        Ok(json!({
            "provider": "stripe",
            "mode": "sandbox",
            "checkout_session_id": required_str(&value, "id")?,
            "url": required_str(&value, "url")?,
            "organization_id": organization_id,
            "plan_id": plan_id
        }))
    })
    .await
    .map_err(|_| BillingError::StripeRequest)?
}

async fn create_portal_session_inner(
    config: &BillingConfig,
    store: &BillingStore,
    authenticated_organization_id: &str,
    body: CreatePortalSessionBody,
) -> Result<Value, BillingError> {
    let organization_id = clean_id(&body.organization_id, "organization_id")?;
    if organization_id != authenticated_organization_id {
        return Err(BillingError::InvalidRequest(
            "organization_id is outside the authenticated grant",
        ));
    }
    let customer_id = clean_id(&body.stripe_customer_id, "stripe_customer_id")?;
    if !customer_id.starts_with("cus_") {
        return Err(BillingError::InvalidRequest(
            "stripe_customer_id must be a Stripe customer ID",
        ));
    }
    if !store.customer_belongs_to(&organization_id, &customer_id)? {
        return Err(BillingError::InvalidRequest(
            "stripe_customer_id is not mapped to organization_id",
        ));
    }
    let api_key = config.api_key()?.to_owned();
    let return_url = config.portal_return_url.clone();
    tokio::task::spawn_blocking(move || {
        let auth = format!("Bearer {api_key}");
        let mut response = ureq::post(format!("{STRIPE_API_BASE}/billing_portal/sessions"))
            .header("Authorization", auth)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .send_form([
                ("customer", customer_id.clone()),
                ("return_url", return_url),
            ])
            .map_err(|_| BillingError::StripeRequest)?;
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|_| BillingError::StripeResponse)?;
        let value: Value = serde_json::from_str(&text).map_err(|_| BillingError::StripeResponse)?;
        Ok(json!({
            "provider": "stripe",
            "mode": "sandbox",
            "portal_session_id": required_str(&value, "id")?,
            "url": required_str(&value, "url")?,
            "organization_id": organization_id
        }))
    })
    .await
    .map_err(|_| BillingError::StripeRequest)?
}

fn webhook_inner(
    config: &BillingConfig,
    store: &BillingStore,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value, BillingError> {
    let Some(secret) = config.webhook_secret.as_deref() else {
        return Err(BillingError::MissingWebhookSecret);
    };
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(BillingError::InvalidSignature)?;
    verify_stripe_signature(secret, signature, body, now_unix_seconds()?)?;
    let event: Value =
        serde_json::from_slice(body).map_err(|_| BillingError::InvalidRequest("invalid JSON"))?;
    if event
        .get("livemode")
        .and_then(Value::as_bool)
        .unwrap_or_default()
    {
        return Err(BillingError::InvalidRequest(
            "live Stripe events are rejected by this test-mode gateway",
        ));
    }
    let applied = store.apply_test_webhook(&event, now_unix_seconds()?)?;
    Ok(json!({
        "received": true,
        "livemode": false,
        "event_id": applied.event_id,
        "event_type": applied.event_type,
        "duplicate": applied.duplicate,
        "applied": applied.applied,
        "organization_id": applied.organization_id,
        "reason": applied.reason,
        "entitlement_mutation": "sandbox_state_recorded"
    }))
}

fn verify_stripe_signature(
    secret: &str,
    header: &str,
    body: &[u8],
    now: u64,
) -> Result<(), BillingError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "t" => timestamp = value.parse::<u64>().ok(),
            "v1" => signatures.push(value),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or(BillingError::InvalidSignature)?;
    if timestamp > now.saturating_add(SIGNATURE_TOLERANCE_SECONDS)
        || now.saturating_sub(timestamp) > SIGNATURE_TOLERANCE_SECONDS
    {
        return Err(BillingError::InvalidSignature);
    }
    let mut signed = timestamp.to_string().into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(body);
    let expected = hex::encode(hmac_sha256(secret.as_bytes(), &signed));
    if signatures
        .iter()
        .any(|signature| constant_time_eq(signature.as_bytes(), expected.as_bytes()))
    {
        Ok(())
    } else {
        Err(BillingError::InvalidSignature)
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= normalized[index];
        opad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn clean_id(value: &str, name: &'static str) -> Result<String, BillingError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(BillingError::InvalidRequest(name));
    }
    Ok(trimmed.to_owned())
}

fn required_str(value: &Value, field: &'static str) -> Result<String, BillingError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(BillingError::StripeResponse)
}

fn apply_event_to_state(
    state: &mut PersistedBillingState,
    event_id: &str,
    event_type: &str,
    event: &Value,
    now: u64,
) -> Result<WebhookApplyResult, BillingError> {
    match event_type {
        "checkout.session.completed" => {
            apply_checkout_completed(state, event_id, event_type, event, now)
        }
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            apply_subscription_event(state, event_id, event_type, event, now)
        }
        _ => Ok(WebhookApplyResult {
            event_id: event_id.to_owned(),
            event_type: event_type.to_owned(),
            duplicate: false,
            applied: false,
            organization_id: None,
            reason: "event_type_recorded_only".to_owned(),
        }),
    }
}

fn apply_checkout_completed(
    state: &mut PersistedBillingState,
    event_id: &str,
    event_type: &str,
    event: &Value,
    now: u64,
) -> Result<WebhookApplyResult, BillingError> {
    let object = stripe_object(event)?;
    let organization_id = nested_str(object, &["metadata", "organization_id"]).ok_or(
        BillingError::InvalidRequest("missing organization_id metadata"),
    )?;
    let organization_id = clean_id(organization_id, "organization_id")?;
    let customer_id = nested_str(object, &["customer"]).unwrap_or_default();
    let subscription_id = nested_str(object, &["subscription"]).unwrap_or_default();
    let plan_id = nested_str(object, &["metadata", "plan_id"]).map(str::to_owned);
    if !customer_id.starts_with("cus_") || !subscription_id.starts_with("sub_") {
        return Err(BillingError::InvalidRequest(
            "checkout session missing Stripe customer or subscription",
        ));
    }
    upsert_customer(state, &organization_id, customer_id, now)?;
    state
        .subscriptions
        .entry(subscription_id.to_owned())
        .or_insert_with(|| BillingSubscriptionRecord {
            organization_id: organization_id.clone(),
            stripe_customer_id: customer_id.to_owned(),
            stripe_subscription_id: subscription_id.to_owned(),
            status: "checkout_completed".to_owned(),
            plan_id: plan_id.clone(),
            price_id: None,
            current_period_end: None,
            entitlement_active: false,
            updated_at_unix_seconds: now,
        });
    Ok(WebhookApplyResult {
        event_id: event_id.to_owned(),
        event_type: event_type.to_owned(),
        duplicate: false,
        applied: true,
        organization_id: Some(organization_id),
        reason: "checkout_customer_subscription_recorded".to_owned(),
    })
}

fn apply_subscription_event(
    state: &mut PersistedBillingState,
    event_id: &str,
    event_type: &str,
    event: &Value,
    now: u64,
) -> Result<WebhookApplyResult, BillingError> {
    let object = stripe_object(event)?;
    let subscription_id = nested_str(object, &["id"]).unwrap_or_default();
    let customer_id = nested_str(object, &["customer"]).unwrap_or_default();
    if !subscription_id.starts_with("sub_") || !customer_id.starts_with("cus_") {
        return Err(BillingError::InvalidRequest(
            "subscription event missing Stripe customer or subscription",
        ));
    }
    let Some(customer) = state.customers.get(customer_id).cloned() else {
        return Ok(WebhookApplyResult {
            event_id: event_id.to_owned(),
            event_type: event_type.to_owned(),
            duplicate: false,
            applied: false,
            organization_id: None,
            reason: "unknown_customer_fail_closed".to_owned(),
        });
    };
    let status = nested_str(object, &["status"])
        .unwrap_or("unknown")
        .to_owned();
    let price_id = object
        .pointer("/items/data/0/price/id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let current_period_end = nested_u64(object, &["current_period_end"]);
    let entitlement_active = ACTIVE_SUBSCRIPTION_STATUSES.contains(&status.as_str());
    let plan_id = state
        .subscriptions
        .get(subscription_id)
        .and_then(|record| record.plan_id.clone());
    state.subscriptions.insert(
        subscription_id.to_owned(),
        BillingSubscriptionRecord {
            organization_id: customer.organization_id.clone(),
            stripe_customer_id: customer_id.to_owned(),
            stripe_subscription_id: subscription_id.to_owned(),
            status,
            plan_id,
            price_id,
            current_period_end,
            entitlement_active,
            updated_at_unix_seconds: now,
        },
    );
    Ok(WebhookApplyResult {
        event_id: event_id.to_owned(),
        event_type: event_type.to_owned(),
        duplicate: false,
        applied: true,
        organization_id: Some(customer.organization_id),
        reason: "subscription_state_recorded".to_owned(),
    })
}

fn upsert_customer(
    state: &mut PersistedBillingState,
    organization_id: &str,
    customer_id: &str,
    now: u64,
) -> Result<(), BillingError> {
    if let Some(existing) = state.customers.get(customer_id)
        && existing.organization_id != organization_id
    {
        return Err(BillingError::InvalidRequest(
            "stripe customer is already mapped to another organization",
        ));
    }
    state.customers.insert(
        customer_id.to_owned(),
        BillingCustomerRecord {
            organization_id: organization_id.to_owned(),
            stripe_customer_id: customer_id.to_owned(),
            updated_at_unix_seconds: now,
        },
    );
    Ok(())
}

fn stripe_object(event: &Value) -> Result<&Value, BillingError> {
    event
        .pointer("/data/object")
        .ok_or(BillingError::InvalidRequest("missing Stripe event object"))
}

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn nested_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64()
}

fn persist_state(path: &Path, state: &PersistedBillingState) -> Result<(), BillingError> {
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(state)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    Ok(())
}

fn billing_error(error: BillingError) -> Response {
    (
        error.status(),
        Json(json!({
            "error": error.code(),
            "message": error.to_string(),
            "charges_enabled": false
        })),
    )
        .into_response()
}

fn random_letters<const N: usize>() -> String {
    let bytes: [u8; N] = rand::random();
    bytes
        .into_iter()
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect()
}

fn now_unix_seconds() -> Result<u64, BillingError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BillingError::Clock)?;
    Ok(elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_isolated_billing_env_test(
        test_name: &str,
        child_marker: &str,
        state_path: Option<&Path>,
        ignored: bool,
    ) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test_name, "--nocapture"])
            .env(child_marker, "1");
        if ignored {
            command.arg("--ignored");
        }
        if let Some(state_path) = state_path {
            command.env("VOR_BILLING_STATE_PATH", state_path);
        } else {
            command.env_remove("VOR_BILLING_STATE_PATH");
        }
        command.output().unwrap()
    }

    fn recorded_event(event_id: &str) -> Value {
        json!({
            "id": event_id,
            "type": "billing.durability.probe",
            "livemode": false
        })
    }

    #[test]
    fn persisted_event_id_remains_deduplicated_after_restart() {
        const CHILD_MARKER: &str = "VOR_TEST_PERSISTED_BILLING_RESTART_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let temp_dir = tempfile::tempdir().unwrap();
            let state_path = temp_dir.path().join("billing-state.json");
            let output = run_isolated_billing_env_test(
                "billing::tests::persisted_event_id_remains_deduplicated_after_restart",
                CHILD_MARKER,
                Some(&state_path),
                false,
            );
            assert!(
                output.status.success(),
                "isolated test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let event = recorded_event("evt_persisted_restart");

        let store = BillingStore::from_env().unwrap();
        let first = store.apply_test_webhook(&event, 1).unwrap();
        assert!(!first.duplicate);
        drop(store);

        let restarted_store = BillingStore::from_env().unwrap();
        let retried = restarted_store.apply_test_webhook(&event, 2).unwrap();

        assert!(retried.duplicate);
        assert_eq!(restarted_store.summary().unwrap().processed_events, 1);
    }

    #[test]
    #[ignore = "billing state is intentionally in-memory when VOR_BILLING_STATE_PATH is absent"]
    // HUECO REAL: a restart forgets Stripe event IDs, so a retry can be processed twice.
    fn in_memory_event_id_should_remain_deduplicated_after_restart() {
        const CHILD_MARKER: &str = "VOR_TEST_IN_MEMORY_BILLING_RESTART_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let output = run_isolated_billing_env_test(
                "billing::tests::in_memory_event_id_should_remain_deduplicated_after_restart",
                CHILD_MARKER,
                None,
                true,
            );
            assert!(
                output.status.success(),
                "isolated test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let event = recorded_event("evt_in_memory_restart");
        let store = BillingStore::from_env().unwrap();
        let first = store.apply_test_webhook(&event, 1).unwrap();
        assert!(!first.duplicate);
        drop(store);

        let restarted_store = BillingStore::from_env().unwrap();
        let retried = restarted_store.apply_test_webhook(&event, 2).unwrap();

        assert!(
            retried.duplicate,
            "a fresh in-memory store accepted the Stripe retry as new"
        );
    }

    #[test]
    #[ignore = "independent stores have no cross-instance lock or deduplication"]
    // HUECO REAL: concurrent instances do not deduplicate and can also collide on the shared .tmp.
    fn stores_sharing_a_path_should_deduplicate_a_concurrent_event() {
        use std::sync::Barrier;
        use std::thread;

        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("billing-state.json");
        let store_a = BillingStore::open(state_path.clone()).unwrap();
        let store_b = BillingStore::open(state_path).unwrap();
        let start = Arc::new(Barrier::new(3));

        let run = |store: BillingStore, start: Arc<Barrier>| {
            thread::spawn(move || {
                start.wait();
                let outcome = store.apply_test_webhook(&recorded_event("evt_concurrent"), 1);
                let processed_events = store.summary().unwrap().processed_events;
                (outcome, processed_events)
            })
        };
        let worker_a = run(store_a, Arc::clone(&start));
        let worker_b = run(store_b, Arc::clone(&start));
        start.wait();

        let outcomes = [worker_a.join().unwrap(), worker_b.join().unwrap()];
        let processed_by_stores = outcomes
            .iter()
            .map(|(_, processed_events)| processed_events)
            .sum::<usize>();
        assert_eq!(
            processed_by_stores, 1,
            "both stores recorded the concurrent event independently: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|(outcome, _)| outcome.as_ref().is_ok_and(|result| result.duplicate)),
            "neither store deduplicated the concurrent event: {outcomes:?}"
        );
    }

    #[test]
    #[ignore = "independent stores replace the whole JSON from stale snapshots"]
    // HUECO REAL: the last writer can erase events and billing state written by another instance.
    fn stores_sharing_a_path_should_preserve_each_others_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("billing-state.json");
        let store_a = BillingStore::open(state_path.clone()).unwrap();
        let store_b = BillingStore::open(state_path.clone()).unwrap();

        store_a
            .apply_test_webhook(&recorded_event("evt_writer_a"), 1)
            .unwrap();
        store_b
            .apply_test_webhook(&recorded_event("evt_writer_b"), 2)
            .unwrap();

        let restarted_store = BillingStore::open(state_path).unwrap();
        let state = restarted_store.lock().unwrap();
        assert!(state.events.contains_key("evt_writer_a"));
        assert!(state.events.contains_key("evt_writer_b"));
    }

    #[test]
    fn stripe_webhook_signature_accepts_valid_test_payload() {
        let body = br#"{"id":"evt_test","livemode":false,"type":"checkout.session.completed"}"#;
        let secret = "whsec_test_secret";
        let timestamp = 1_789_800_000u64;
        let mut signed = timestamp.to_string().into_bytes();
        signed.push(b'.');
        signed.extend_from_slice(body);
        let signature = hex::encode(hmac_sha256(secret.as_bytes(), &signed));
        let header = format!("t={timestamp},v1={signature}");

        assert!(verify_stripe_signature(secret, &header, body, timestamp + 10).is_ok());
    }

    #[test]
    fn stripe_webhook_signature_rejects_tampered_payload() {
        let body = br#"{"id":"evt_test","livemode":false}"#;
        let secret = "whsec_test_secret";
        let timestamp = 1_789_800_000u64;
        let header = format!(
            "t={timestamp},v1={}",
            hex::encode(hmac_sha256(secret.as_bytes(), b"wrong"))
        );

        assert!(matches!(
            verify_stripe_signature(secret, &header, body, timestamp),
            Err(BillingError::InvalidSignature)
        ));
    }

    #[test]
    fn live_keys_are_rejected() {
        let mut config = BillingConfig::test_disabled();
        config.mode = BillingMode::Sandbox;
        config.api_key = Some("sk_live_not_allowed".into());

        assert!(matches!(
            config.api_key(),
            Err(BillingError::LiveKeyRejected)
        ));
    }

    #[tokio::test]
    async fn checkout_session_rejects_cross_tenant_body_organization() {
        let config = BillingConfig::test_disabled();
        let body = CreateCheckoutSessionBody {
            organization_id: "org-b".to_owned(),
            plan_id: PlanId::PersonalCloud,
            quantity: Some(1),
        };
        let error = create_checkout_session_inner(&config, "org-a", "actor-a", body)
            .await
            .unwrap_err();
        assert!(matches!(error, BillingError::InvalidRequest(_)));
    }

    #[test]
    fn checkout_webhook_maps_customer_and_is_idempotent() {
        let store = BillingStore::memory();
        let event = json!({
            "id": "evt_checkout",
            "type": "checkout.session.completed",
            "livemode": false,
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "customer": "cus_test_123",
                    "subscription": "sub_test_123",
                    "metadata": {
                        "organization_id": "org_demo",
                        "plan_id": "personal-cloud"
                    }
                }
            }
        });

        let first = store.apply_test_webhook(&event, 1_789_800_000).unwrap();
        assert!(first.applied);
        assert!(!first.duplicate);
        assert_eq!(first.organization_id.as_deref(), Some("org_demo"));
        assert!(
            store
                .customer_belongs_to("org_demo", "cus_test_123")
                .unwrap()
        );

        let second = store.apply_test_webhook(&event, 1_789_800_001).unwrap();
        assert!(second.duplicate);
        assert!(!second.applied);
        assert_eq!(store.summary().unwrap().processed_events, 1);
    }

    #[test]
    fn stripe_customer_cannot_map_to_two_organizations() {
        let store = BillingStore::memory();
        let checkout_for_org_a = json!({
            "id": "evt_checkout_org_a",
            "type": "checkout.session.completed",
            "livemode": false,
            "data": {
                "object": {
                    "customer": "cus_shared_customer",
                    "subscription": "sub_org_a",
                    "metadata": {
                        "organization_id": "org-a",
                        "plan_id": "teams"
                    }
                }
            }
        });
        let checkout_for_org_b = json!({
            "id": "evt_checkout_org_b",
            "type": "checkout.session.completed",
            "livemode": false,
            "data": {
                "object": {
                    "customer": "cus_shared_customer",
                    "subscription": "sub_org_b",
                    "metadata": {
                        "organization_id": "org-b",
                        "plan_id": "teams"
                    }
                }
            }
        });

        store.apply_test_webhook(&checkout_for_org_a, 1).unwrap();
        let error = store
            .apply_test_webhook(&checkout_for_org_b, 2)
            .unwrap_err();

        assert!(matches!(error, BillingError::InvalidRequest(_)));
        assert!(
            store
                .customer_belongs_to("org-a", "cus_shared_customer")
                .unwrap()
        );
        assert!(
            !store
                .customer_belongs_to("org-b", "cus_shared_customer")
                .unwrap()
        );
        assert_eq!(store.summary().unwrap().customers, 1);
    }

    #[test]
    fn subscription_webhook_updates_entitlement_for_known_customer() {
        let store = BillingStore::memory();
        let checkout = json!({
            "id": "evt_checkout",
            "type": "checkout.session.completed",
            "livemode": false,
            "data": {
                "object": {
                    "customer": "cus_test_123",
                    "subscription": "sub_test_123",
                    "metadata": {
                        "organization_id": "org_demo",
                        "plan_id": "teams"
                    }
                }
            }
        });
        store.apply_test_webhook(&checkout, 1).unwrap();

        let subscription = json!({
            "id": "evt_subscription",
            "type": "customer.subscription.updated",
            "livemode": false,
            "data": {
                "object": {
                    "id": "sub_test_123",
                    "customer": "cus_test_123",
                    "status": "active",
                    "current_period_end": 1_800_000_000u64,
                    "items": {
                        "data": [{
                            "price": { "id": "price_teams_test" }
                        }]
                    }
                }
            }
        });

        let applied = store.apply_test_webhook(&subscription, 2).unwrap();
        assert!(applied.applied);
        let summary = store.summary().unwrap();
        assert_eq!(summary.subscriptions, 1);
        assert_eq!(summary.active_entitlements, 1);
    }

    #[test]
    fn subscription_webhook_for_unknown_customer_fails_closed() {
        let store = BillingStore::memory();
        let subscription = json!({
            "id": "evt_subscription",
            "type": "customer.subscription.updated",
            "livemode": false,
            "data": {
                "object": {
                    "id": "sub_test_123",
                    "customer": "cus_unknown",
                    "status": "active"
                }
            }
        });

        let applied = store.apply_test_webhook(&subscription, 2).unwrap();
        assert!(!applied.applied);
        assert_eq!(applied.reason, "unknown_customer_fail_closed");
        assert_eq!(store.summary().unwrap().active_entitlements, 0);
    }

    #[tokio::test]
    async fn portal_session_requires_customer_organization_mapping() {
        let config = BillingConfig::test_disabled();
        let store = BillingStore::memory();
        let body = CreatePortalSessionBody {
            organization_id: "org_demo".to_owned(),
            stripe_customer_id: "cus_test_123".to_owned(),
        };

        let error = create_portal_session_inner(&config, &store, "org_demo", body)
            .await
            .unwrap_err();
        assert!(matches!(error, BillingError::InvalidRequest(_)));
    }
}
