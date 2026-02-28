use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response, Json},
    Json as ExtractJson,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use rsa::pkcs8::EncodePublicKey;

use crate::config::{AppState, SessionInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub uuid: String,
    pub sid: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscarClaims {
    pub uuid: String,
    pub sid: String,
    pub fp: String,
    pub scope: String,
    pub exp: i64,
}

#[derive(Deserialize)]
pub struct LocalLoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LocalSignupPayload {
    pub username: String,
    pub invite_code: String,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub username: String,
    pub password: String,
    pub recovery_phrase: String,
    pub token: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct DiscordCallbackQuery {
    pub code: String,
}

#[derive(Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
}

pub async fn discord_callback(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<DiscordCallbackQuery>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let client = &state.reqwest_client;

    // Exchange code for token
    let token_res = client
        .post("https://discord.com/api/oauth2/token")
        .form(&[
            ("client_id", state.config.discord_client_id.as_str()),
            ("client_secret", state.config.discord_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", query.code.as_str()),
            ("redirect_uri", state.config.discord_redirect_uri.as_str()),
        ])
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Discord token exchange failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Token exchange failed" })))
        })?;

    if !token_res.status().is_success() {
        let err_text = token_res.text().await.unwrap_or_default();
        tracing::error!("Discord token error: {}", err_text);
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Discord rejected the code" }))));
    }

    let token_data: DiscordTokenResponse = token_res.json().await.map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invalid token response" })))
    })?;

    // Get user info
    let user_res = client
        .get("https://discord.com/api/users/@me")
        .bearer_auth(token_data.access_token)
        .send()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to get user info" }))))?;

    let discord_user: DiscordUser = user_res.json().await.map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invalid user response" })))
    })?;

    // Check if user exists
    let mut user = state.db.get_user_by_identifier("discord", &discord_user.id).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    if user.is_none() {
        // For Discord, we might want to check an invite or whitelist.
        // For MVP, if they are the SUPER_ADMIN_ID, they are auto-created as admin.
        // Others might need an invite (Phase 3).
        let role = if discord_user.id == state.config.super_admin_id { "admin" } else { "user" };
        
        let new_user = crate::db::User {
            uuid: uuid::Uuid::new_v4().to_string(),
            username: Some(discord_user.username),
            provider: "discord".to_string(),
            identifier: discord_user.id.clone(),
            role: role.to_string(),
        };
        
        state.db.create_user(new_user.clone(), None).map_err(|e| {
            tracing::error!("Failed to create user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to create user" })))
        })?;
        user = Some(new_user);
    }

    let user = user.unwrap();
    issue_session(&state, user).await
}

pub async fn local_signup(
    State(state): State<Arc<AppState>>,
    ExtractJson(payload): ExtractJson<LocalSignupPayload>,
) -> Result<Json<SignupResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Validate invite
    let is_valid = state.db.validate_invite(&payload.invite_code).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    if !is_valid {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Invalid or expired invite code" }))));
    }

    // Check if username taken
    let exists = state.db.get_user_by_identifier("local", &payload.username).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    if exists.is_some() {
        return Err((StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Username already taken" }))));
    }

    // Generate credentials
    let password = format!("{}-{}", payload.username, uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
    
    use bip39::Mnemonic;
    use rand::{rngs::OsRng, RngCore};
    let mut rng = OsRng;
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    let recovery_phrase = mnemonic.to_string();

    use argon2::{
        password_hash::{SaltString},
        Argon2, PasswordHasher,
    };
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Password hashing failed" }))))?
        .to_string();

    let uuid = uuid::Uuid::new_v4().to_string();
    let user = crate::db::User {
        uuid: uuid.clone(),
        username: Some(payload.username.clone()),
        provider: "local".to_string(),
        identifier: payload.username.clone(),
        role: "user".to_string(),
    };

    state.db.create_user(user.clone(), Some(password_hash)).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to create user" })))
    })?;

    state.db.use_invite(&payload.invite_code, &uuid).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invite update error" })))
    })?;

    let token_res = issue_session(&state, user).await?;
    
    Ok(Json(SignupResponse {
        username: payload.username,
        password,
        recovery_phrase,
        token: token_res.0.token,
    }))
}

pub async fn local_login(
    State(state): State<Arc<AppState>>,
    ExtractJson(payload): ExtractJson<LocalLoginPayload>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let user = state.db.verify_password("local", &payload.username, &payload.password).map_err(|e| {
        tracing::error!("Auth verification error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Authentication error" })))
    })?;

    match user {
        Some(u) => issue_session(&state, u).await,
        None => Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid credentials" })))),
    }
}

async fn issue_session(
    state: &AppState,
    user: crate::db::User,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let sid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let exp = now + state.config.auth_session_ttl_seconds as i64;

    state.active_auth_sessions.write().await.insert(
        sid.clone(),
        SessionInfo {
            uuid: user.uuid.clone(),
            expires_at: exp,
        },
    );

    let claims = Claims {
        uuid: user.uuid,
        sid,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to create token" })))
    })?;

    Ok(Json(LoginResponse { token }))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> impl IntoResponse {
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(token_str) = auth_header.to_str() {
            if token_str.starts_with("Bearer ") {
                let token = &token_str[7..];
                if let Ok(token_data) = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
                    &Validation::default(),
                ) {
                    state.active_auth_sessions.write().await.remove(&token_data.claims.sid);
                }
            }
        }
    }

    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .unwrap();

    response.headers_mut().insert(
        header::SET_COOKIE,
        "oscar_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure".parse().unwrap(),
    );

    response
}

pub async fn session_check() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

pub async fn get_public_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pem = state
        .config
        .app_encryption_private_key
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap_or_default();
    
    Json(serde_json::json!({
        "algorithm": "RSA-OAEP-256/AES-256-GCM",
        "publicKeyPem": pem
    }))
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        ))?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid token" })),
        )
    })?;

    let claims = token_data.claims;
    let now = chrono::Utc::now().timestamp();
    
    let mut sessions = state.active_auth_sessions.write().await;
    sessions.retain(|_, s| s.expires_at > now);

    if let Some(session) = sessions.get(&claims.sid) {
        if session.uuid == claims.uuid {
            req.extensions_mut().insert(claims);
            return Ok(next.run(req).await);
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "Session expired" })),
    ))
}

pub async fn require_oscar_session_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let path = req.uri().path().to_string();
    tracing::debug!("require_oscar_session_middleware: path={}", path);

    let cookie_header = req.headers().get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    tracing::debug!("require_oscar_session_middleware: cookie_header present={}", !cookie_header.is_empty());

    let mut oscar_session = None;
    for cookie_str in cookie_header.split(';') {
        let trimmed = cookie_str.trim();
        if let Some(val) = trimmed.strip_prefix("oscar_session=") {
            oscar_session = Some(val.to_string());
            break;
        }
    }

    let token = match oscar_session {
        Some(t) => {
            tracing::debug!("require_oscar_session_middleware: oscar_session cookie found, len={}", t.len());
            t
        }
        None => {
            tracing::debug!("require_oscar_session_middleware: NO oscar_session cookie => redirect to /");
            return Err(axum::response::Redirect::to("/"));
        }
    };

    let token_data = decode::<OscarClaims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    ).map_err(|e| {
        tracing::debug!("require_oscar_session_middleware: token decode failed: {}", e);
        axum::response::Redirect::to("/")
    })?;

    let claims = token_data.claims;
    if claims.scope != "oscar" {
        tracing::debug!("require_oscar_session_middleware: scope mismatch: {}", claims.scope);
        return Err(axum::response::Redirect::to("/"));
    }

    let now = chrono::Utc::now().timestamp();
    let mut sessions = state.active_auth_sessions.write().await;
    sessions.retain(|_, s| s.expires_at > now);

    if !sessions.contains_key(&claims.sid) {
        tracing::debug!("require_oscar_session_middleware: session {} not found in active sessions (count={})", claims.sid, sessions.len());
        return Err(axum::response::Redirect::to("/"));
    }

    let user_agent = req.headers().get(header::USER_AGENT).and_then(|h| h.to_str().ok()).unwrap_or("");
    let accept_language = req.headers().get(header::ACCEPT_LANGUAGE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let fp_str = format!("{}\n{}", user_agent, accept_language);
    
    use sha2::{Sha256, Digest};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let mut hasher = Sha256::new();
    hasher.update(fp_str.as_bytes());
    let fp = URL_SAFE_NO_PAD.encode(hasher.finalize());

    if fp != claims.fp {
        tracing::debug!("require_oscar_session_middleware: fingerprint mismatch. computed={} vs claims={}", fp, claims.fp);
        tracing::debug!("require_oscar_session_middleware: user_agent='{}' accept_language='{}'", user_agent, accept_language);
        return Err(axum::response::Redirect::to("/"));
    }

    tracing::debug!("require_oscar_session_middleware: session valid, proceeding");
    Ok(next.run(req).await)
}
