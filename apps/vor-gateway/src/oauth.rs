use super::GatewayState;
use axum::body::Body;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header::LOCATION};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use url::Url;

const ISSUER: &str = "https://mcp.vorcommander.app";
const RESOURCE: &str = "https://mcp.vorcommander.app/mcp";
const ACCESS_TTL_MS: u64 = 2_592_000_000;
const CODE_TTL_MS: u64 = 300_000;

#[derive(Clone, Default)]
pub(super) struct OAuthRuntime {
    codes: Arc<Mutex<BTreeMap<String, AuthorizationCodeRecord>>>,
}

#[derive(Clone)]
struct AuthorizationCodeRecord {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scopes: Vec<String>,
    actor_id: String,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
struct ClientRegistrationRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    application_type: Option<String>,
}
#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: Option<String>,
    resource: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeForm {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    resource: String,
    owner_token: String,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
}
pub(super) fn router() -> Router<GatewayState> {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(authorization_server_metadata),
        )
        .route("/oauth/register", post(register_client))
        .route("/oauth/authorize", get(authorize_get).post(authorize_post))
        .route("/oauth/token", post(token))
}

async fn protected_resource_metadata() -> Json<serde_json::Value> {
    Json(json!({
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["mcp", "gateway.read"],
        "bearer_methods_supported": ["header"],
        "resource_name": "V\u{00f6}r Commander MCP"
    }))
}

async fn authorization_server_metadata() -> Json<serde_json::Value> {
    Json(json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/oauth/authorize"),
        "token_endpoint": format!("{ISSUER}/oauth/token"),
        "registration_endpoint": format!("{ISSUER}/oauth/register"),
        "scopes_supported": ["mcp", "gateway.read"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true
    }))
}
async fn register_client(
    State(state): State<GatewayState>,
    Json(body): Json<ClientRegistrationRequest>,
) -> Response {
    if body.redirect_uris.is_empty() || body.redirect_uris.len() > 16 {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    if body
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|m| m != "none")
    {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let app_type = body.application_type.as_deref().unwrap_or("web");
    if !body
        .redirect_uris
        .iter()
        .all(|uri| valid_redirect_uri(uri, app_type))
    {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    if body
        .grant_types
        .as_ref()
        .is_some_and(|v| !v.iter().any(|x| x == "authorization_code"))
    {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    if body
        .response_types
        .as_ref()
        .is_some_and(|v| !v.iter().any(|x| x == "code"))
    {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }

    let client_id = random_secret();
    let client_name = body.client_name.unwrap_or_else(|| "MCP Client".to_owned());
    let Some(registered_at_unix_ms) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .grants
        .register_oauth_client(
            client_id.clone(),
            body.redirect_uris.clone(),
            client_name.clone(),
            registered_at_unix_ms,
        )
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let issued_at = registered_at_unix_ms / 1000;
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": issued_at,
            "client_name": client_name,
            "redirect_uris": body.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "application_type": app_type
        })),
    )
        .into_response()
}

async fn authorize_get(
    State(state): State<GatewayState>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let Ok((client, scopes)) = validate_authorization(
        &state,
        &query.client_id,
        &query.redirect_uri,
        &query.response_type,
        &query.code_challenge,
        query.code_challenge_method.as_deref().unwrap_or(""),
        query.scope.as_deref(),
        query.resource.as_deref(),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            "invalid OAuth authorization request",
        )
            .into_response();
    };
    let scope = scopes.join(" ");
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>Vör Commander OAuth</title>\
<style>body{{font:16px system-ui;max-width:620px;margin:4rem auto;padding:0 1rem}}\
input,button{{font:inherit;padding:.7rem;width:100%;box-sizing:border-box;margin:.4rem 0}}\
code{{background:#eee;padding:.15rem .3rem}}</style>\
<h1>Authorize Vör Commander</h1>\
<p>Client: <strong>{}</strong></p>\
<p>Requested scopes: <code>{}</code></p>\
<p>Paste the current owner bootstrap token. It is verified in memory and is not stored by this page.</p>\
<form method=post action=/oauth/authorize>{}{}{}{}{}{}{}{}\
<label>Owner bootstrap token<input name=owner_token type=password autocomplete=off required></label>\
<button type=submit>Authorize ChatGPT</button></form>",
        html_escape(&client.client_name),
        html_escape(&scope),
        hidden("response_type", &query.response_type),
        hidden("client_id", &query.client_id),
        hidden("redirect_uri", &query.redirect_uri),
        hidden("scope", &scope),
        hidden("state", query.state.as_deref().unwrap_or("")),
        hidden("code_challenge", &query.code_challenge),
        hidden(
            "code_challenge_method",
            query.code_challenge_method.as_deref().unwrap_or("S256")
        ),
        hidden("resource", query.resource.as_deref().unwrap_or("")),
    );
    Html(html).into_response()
}
async fn authorize_post(
    State(state): State<GatewayState>,
    Form(form): Form<AuthorizeForm>,
) -> Response {
    let resource = if form.resource.is_empty() {
        None
    } else {
        Some(form.resource.as_str())
    };
    let Ok((_client, scopes)) = validate_authorization(
        &state,
        &form.client_id,
        &form.redirect_uri,
        &form.response_type,
        &form.code_challenge,
        &form.code_challenge_method,
        Some(&form.scope),
        resource,
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            "invalid OAuth authorization request",
        )
            .into_response();
    };
    let Some(now) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(owner) = state.grants.validate(&form.owner_token, "mcp", now) else {
        return (StatusCode::UNAUTHORIZED, "invalid owner bootstrap token").into_response();
    };
    if owner.actor_id != "local-pilot" {
        return (StatusCode::FORBIDDEN, "owner bootstrap token required").into_response();
    }
    let pairing = match state
        .grants
        .create_pairing(scopes.clone(), CODE_TTL_MS, ACCESS_TTL_MS, now)
    {
        Ok(value) => value,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let code = pairing.code().to_owned();
    let record = AuthorizationCodeRecord {
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        code_challenge: form.code_challenge,
        scopes,
        actor_id: "chatgpt-owner".to_owned(),
        expires_at_unix_ms: now.saturating_add(CODE_TTL_MS),
    };
    let Ok(mut codes) = state.oauth.codes.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    codes.retain(|_, item| item.expires_at_unix_ms > now);
    codes.insert(secret_hash(&code), record);
    drop(codes);

    let Ok(mut redirect) = Url::parse(&form.redirect_uri) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    {
        let mut query = redirect.query_pairs_mut();
        query.append_pair("code", &code);
        if !form.state.is_empty() {
            query.append_pair("state", &form.state);
        }
        query.append_pair("iss", ISSUER);
    }
    redirect_response(redirect)
}

async fn token(State(state): State<GatewayState>, Form(form): Form<TokenForm>) -> Response {
    match form.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, form),
        _ => oauth_json_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn exchange_authorization_code(state: &GatewayState, form: TokenForm) -> Response {
    let (Some(code), Some(client_id), Some(redirect_uri), Some(verifier)) = (
        form.code,
        form.client_id,
        form.redirect_uri,
        form.code_verifier,
    ) else {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(now) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(mut codes) = state.oauth.codes.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Some(record) = codes.remove(&secret_hash(&code)) else {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    drop(codes);
    if record.expires_at_unix_ms <= now
        || record.client_id != client_id
        || record.redirect_uri != redirect_uri
        || !verify_pkce(&verifier, &record.code_challenge)
    {
        return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    let issued = match state.grants.redeem_pairing(&code, record.actor_id, now) {
        Ok(value) => value,
        Err(_) => return oauth_json_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    Json(json!({
        "access_token": issued.token(),
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_MS / 1000,
        "scope": record.scopes.join(" ")
    }))
    .into_response()
}
#[allow(clippy::too_many_arguments)]
fn validate_authorization(
    state: &GatewayState,
    client_id: &str,
    redirect_uri: &str,
    response_type: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<(vor_auth::OAuthClientRecord, Vec<String>), ()> {
    if response_type != "code" || code_challenge_method != "S256" || code_challenge.len() < 32 {
        return Err(());
    }
    if resource.is_some_and(|resource| resource != RESOURCE) {
        return Err(());
    }
    let client = state
        .grants
        .oauth_client(client_id)
        .map_err(|_| ())?
        .ok_or(())?;
    if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        return Err(());
    }
    let scopes = parse_scopes(scope)?;
    Ok((client, scopes))
}

fn parse_scopes(scope: Option<&str>) -> Result<Vec<String>, ()> {
    let raw = scope.unwrap_or("mcp gateway.read");
    let mut scopes = Vec::new();
    for scope in raw.split_ascii_whitespace() {
        if !matches!(scope, "mcp" | "gateway.read") {
            return Err(());
        }
        if !scopes.iter().any(|value| value == scope) {
            scopes.push(scope.to_owned());
        }
    }
    if !scopes.iter().any(|scope| scope == "mcp") {
        return Err(());
    }
    Ok(scopes)
}

fn valid_redirect_uri(value: &str, application_type: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.scheme() == "https" {
        return url.host_str().is_some();
    }
    if application_type == "native" && url.scheme() == "http" {
        return matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("::1")
        );
    }
    false
}
fn verify_pkce(verifier: &str, expected: &str) -> bool {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == expected
}

fn random_secret() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn secret_hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn now_unix_ms() -> Option<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

fn redirect_response(url: Url) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, url.as_str())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
fn oauth_json_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(json!({"error": error}))).into_response()
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=hidden name=\"{}\" value=\"{}\">",
        html_escape(name),
        html_escape(value)
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_accepts_known_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(verifier, challenge));
    }

    #[test]
    fn redirect_policy_is_fail_closed() {
        assert!(valid_redirect_uri(
            "https://chatgpt.com/connector/oauth/callback",
            "web"
        ));
        assert!(valid_redirect_uri(
            "http://127.0.0.1:8765/callback",
            "native"
        ));
        assert!(!valid_redirect_uri("http://evil.example/callback", "web"));
    }
}
