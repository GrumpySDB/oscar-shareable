use axum::{
    extract::{Request, State, ConnectInfo, Host, Query},
    http::{header, StatusCode, HeaderMap},
    middleware::Next,
    response::{IntoResponse, Response, Json},
    Json as ExtractJson,
    Extension,
};
use std::net::SocketAddr;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use rsa::pkcs8::EncodePublicKey;

use crate::config::{AppState, SessionInfo, UPLOAD_ROOT, PROFILE_ROOT};
// Unused bollard imports removed
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub uuid: String,
    #[serde(rename = "sub")]
    pub username: String,
    pub role: String,
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
    pub is_guest: bool,
    pub container_key: String,
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
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Deserialize)]
pub struct DiscordLoginQuery {
    pub invite: Option<String>,
    pub prompt: Option<String>,
}

#[derive(Serialize)]
pub struct InviteValidationResponse {
    pub code: String,
    pub status: crate::db::InviteStatus,
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

pub async fn discord_login(
    State(state): State<Arc<AppState>>,
    Host(host): Host,
    headers: axum::http::HeaderMap,
    Query(query): Query<DiscordLoginQuery>,
) -> impl IntoResponse {
    let client_id = &state.config.discord_client_id;
    
    // Dynamically determine redirect URI based on host
    let proto = headers.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    
    let redirect_uri_base = if host.is_empty() {
        state.config.discord_redirect_uri.clone()
    } else {
        format!("{}://{}/api/auth/discord/callback", proto, host)
    };
    
    tracing::info!("Discord Login: Generated redirect_uri_base: {}", redirect_uri_base);
    let redirect_uri = urlencoding::encode(&redirect_uri_base);
    let state_param = query.invite.unwrap_or_default();
    let prompt = query.prompt.as_deref().unwrap_or("none");
    
    let url = format!(
        "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify&state={}&prompt={}",
        client_id, redirect_uri, state_param, prompt
    );
    
    axum::response::Redirect::to(&url)
}

pub async fn discord_callback(
    State(state): State<Arc<AppState>>,
    req_headers: HeaderMap,
    Query(query): Query<DiscordCallbackQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if let Some(err) = query.error {
        if err == "consent_required" {
            let state_param = query.state.unwrap_or_default();
            let redirect_url = format!("/api/auth/discord/login?invite={}&prompt=consent", state_param);
            return Ok(axum::response::Redirect::to(&redirect_url).into_response());
        }
        tracing::error!("Discord OAuth error: {} - {:?}", err, query.error_description);
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Discord authorization failed or was denied" }))));
    }

    let code_str = query.code.ok_or((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing code from Discord" }))))?;

    let client = &state.external_client;

    // Exchange code for token
    let host = req_headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let proto = req_headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("https");
    
    let redirect_uri = if host.is_empty() {
        state.config.discord_redirect_uri.clone()
    } else {
        format!("{}://{}/api/auth/discord/callback", proto, host)
    };
    
    tracing::info!("Discord Callback: Generated redirect_uri: {}", redirect_uri);

    let token_res = client
        .post("https://discord.com/api/oauth2/token")
        .form(&[
            ("client_id", state.config.discord_client_id.as_str()),
            ("client_secret", state.config.discord_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code_str.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
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
        // Enforce invite logic for NEW Discord users
        let invite_code = query.state.as_deref().unwrap_or("");
        
        if invite_code.is_empty() {
             tracing::warn!("Discord login attempt for non-existent user with NO invite code.");
             return Ok(axum::response::Redirect::to("/?error=uninvited").into_response());
        }

        if !state.db.validate_invite(invite_code).unwrap_or(false) {
             tracing::warn!("Discord login attempt for new user with INVALID invite code: {}", invite_code);
             return Ok(axum::response::Redirect::to("/?error=invalid_invite").into_response());
        }
        
        let now = chrono::Utc::now().timestamp();
        let new_user = crate::db::User {
            uuid: uuid::Uuid::new_v4().to_string(),
            username: Some(discord_user.username.clone()),
            provider: "discord".to_string(),
            identifier: discord_user.id.clone(),
            role: "user".to_string(),
            created_at: now,
            last_accessed_at: Some(now),
        };
        
        state.db.create_user_with_invite(new_user.clone(), None, None, invite_code).map_err(|e| {
            tracing::error!("Failed to create Discord user with invite: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to link Discord account with invite" })))
        })?;
        
        // Create user profile templates
        let u_name = discord_user.username.clone();
        let uuid_clone = new_user.uuid.clone();
        let config_clone = state.config.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = create_user_profile(&u_name, &uuid_clone, &config_clone) {
                tracing::error!("Failed to create template files for new discord user {}: {}", u_name, e);
            }
        }).await;
        
        user = Some(new_user);
    }

    let user = user.unwrap();
    let (headers, token_res) = issue_session(&state, user.clone()).await?;
    
    let username = user.username.as_deref().unwrap_or("unknown");
    tracing::info!(
        "Successful Discord login for user '{}' (uuid: {})",
        username,
        user.uuid
    );
    let _ = state.db.log_audit_event(
        "discord_login",
        Some(&user.uuid),
        Some(username),
        None,
        None // ip not easily available in this callback without more rework
    );

    let url = format!("/?login_token={}", token_res.0.token);
    let mut response = axum::response::Redirect::to(&url).into_response();
    response.headers_mut().extend(headers);
    Ok(response)
}

pub async fn local_signup(
    State(state): State<Arc<AppState>>,
    ExtractJson(payload): ExtractJson<LocalSignupPayload>,
) -> Result<(header::HeaderMap, Json<SignupResponse>), (StatusCode, Json<serde_json::Value>)> {
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

    // Backend validation for username
    if payload.username.is_empty() || payload.username.len() > 128 || !payload.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid username format" }))));
    }

    // Generate credentials (ensure > 20 chars minimum)
    let password = uuid::Uuid::new_v4().simple().to_string();
    
    use bip39::Mnemonic;
    use rand::{rngs::OsRng, RngCore};
    let mut rng = OsRng;
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    let recovery_phrase = mnemonic.to_string();

    let password_clone = password.clone();
    let recovery_phrase_clone = recovery_phrase.clone();
    let (password_hash, recovery_hash) = tokio::task::spawn_blocking(move || {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let argon2 = Argon2::default();
        
        let p_salt = SaltString::generate(&mut rng);
        let p_hash = argon2.hash_password(password_clone.as_bytes(), &p_salt)
            .map(|h| h.to_string())
            .map_err(|_| "Password hashing failed")?;
            
        let r_salt = SaltString::generate(&mut rng);
        let r_hash = argon2.hash_password(recovery_phrase_clone.as_bytes(), &r_salt)
            .map(|h| h.to_string())
            .map_err(|_| "Recovery phrase hashing failed")?;
            
        Ok::<(_, _), &'static str>((p_hash, r_hash))
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal error" }))))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

    let uuid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let user = crate::db::User {
        uuid: uuid.clone(),
        username: Some(payload.username.clone()),
        provider: "local".to_string(),
        identifier: payload.username.clone(),
        role: "user".to_string(),
        created_at: now,
        last_accessed_at: Some(now),
    };

    state.db.create_user_with_invite(user.clone(), Some(password_hash), Some(recovery_hash), &payload.invite_code).map_err(|e| {
        tracing::error!("Failed to create user with invite: {}", e);
        if e.to_string().contains("Query returned no rows") {
            (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Invite already used or expired" })))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to create account" })))
        }
    })?;

    let (_headers, token_res) = issue_session(&state, user.clone()).await?;
    
    tracing::info!(
        "New local user signup: '{}' (uuid: {}) using invite: {}",
        payload.username,
        uuid,
        payload.invite_code
    );
    let _ = state.db.log_audit_event(
        "local_signup",
        Some(&uuid),
        Some(&payload.username),
        Some(&format!("invite: {}", payload.invite_code)),
        None
    );

    Ok((header::HeaderMap::new(), Json(SignupResponse {
        username: payload.username,
        password,
        recovery_phrase,
        token: token_res.0.token,
    })))
}

pub async fn local_login(
    State(state): State<Arc<AppState>>,
    headers_map: header::HeaderMap,
    ExtractJson(payload): ExtractJson<LocalLoginPayload>,
) -> Result<(header::HeaderMap, Json<LoginResponse>), (StatusCode, Json<serde_json::Value>)> {
    let state_clone = state.clone();
    let username = payload.username.clone();
    let password = payload.password.clone();
    
    let user_res = tokio::task::spawn_blocking(move || {
        state_clone.db.verify_password("local", &username, &password)
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal task error" }))))?;

    let user = user_res.map_err(|e| {
        tracing::error!("Auth verification error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Authentication error" })))
    })?;
    match user {
        Some(u) => {
            let (headers, token_res) = issue_session(&state, u.clone()).await?;
            let uname = u.username.as_deref().unwrap_or("unknown");
            tracing::info!(
                "Successful local login for user '{}' (uuid: {})",
                uname,
                u.uuid
            );
            
            // Try to extract IP from headers (behind proxy)
            let ip = headers_map.get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

            let _ = state.db.log_audit_event(
                "local_login",
                Some(&u.uuid),
                Some(uname),
                None,
                ip.as_deref()
            );
            Ok((headers, token_res))
        }
        None => {
            // Log failed login attempt
            let ip = headers_map.get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());
            
            let _ = state.db.log_audit_event(
                "failed_login",
                None,
                Some(&payload.username),
                Some("Invalid credentials"),
                ip.as_deref()
            );
            Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid credentials" }))))
        }
    }
}

#[derive(Deserialize)]
pub struct LocalRecoveryPayload {
    pub username: String,
    pub recovery_phrase: String,
}

pub async fn local_recovery_handler(
    State(state): State<Arc<AppState>>,
    headers_map: header::HeaderMap,
    ExtractJson(payload): ExtractJson<LocalRecoveryPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Basic input sanitization
    let username = payload.username.trim();
    let recovery_phrase = payload.recovery_phrase.trim();

    if username.is_empty() || recovery_phrase.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Username and recovery phrase are required" }))));
    }

    if username.len() > 128 || recovery_phrase.len() > 512 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Input too long" }))));
    }

    let state_clone = state.clone();
    let u_clone = username.to_string();
    let r_clone = recovery_phrase.to_string();

    let user_res = tokio::task::spawn_blocking(move || {
        state_clone.db.verify_recovery_phrase("local", &u_clone, &r_clone)
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal task error" }))))?;

    let ip = headers_map.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let user = user_res.map_err(|e| {
        tracing::error!("Recovery verification error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Recovery error" })))
    })?;

    match user {
        Some(u) => {
            // Generate new password
            // [SAST-REMEDIATION]: Uuid::new_v4() provides 122 bits of high-quality 
            // entropy, sufficient for a temporary password.
            let new_pw = uuid::Uuid::new_v4().simple().to_string();
            let new_pw_clone = new_pw.clone();
            
            let password_hash = tokio::task::spawn_blocking(move || {
                use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
                use rand::rngs::OsRng;
                let salt = SaltString::generate(&mut OsRng);
                Argon2::default()
                    .hash_password(new_pw_clone.as_bytes(), &salt)
                    .map(|h| h.to_string())
            })
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal error" }))))?
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Hash error" }))))?;

            state.db.reset_user_password(&u.uuid, &password_hash).map_err(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to reset password" })))
            })?;

            // Clear active sessions for this user
            state.active_auth_sessions.retain(|_, s| s.uuid != u.uuid);

            let uname = u.username.as_deref().unwrap_or("unknown");
            tracing::info!(
                "Password reset successful via recovery phrase for user '{}' (uuid: {})",
                uname,
                u.uuid
            );
            let _ = state.db.log_audit_event(
                "password_recovery",
                Some(&u.uuid),
                Some(uname),
                None,
                ip.as_deref()
            );

            Ok(Json(serde_json::json!({
                "message": "Password successfully reset",
                "new_password": new_pw
            })))
        }
        None => {
            let _ = state.db.log_audit_event(
                "failed_recovery",
                None,
                Some(username),
                Some("Invalid recovery phrase"),
                ip.as_deref()
            );
            Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid username or recovery phrase" }))))
        }
    }
}

async fn issue_session(
    state: &AppState,
    user: crate::db::User,
) -> Result<(header::HeaderMap, Json<LoginResponse>), (StatusCode, Json<serde_json::Value>)> {
    let sid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let exp = now + state.config.auth_session_ttl_seconds as i64;

    state.active_auth_sessions.insert(
        sid.clone(),
        SessionInfo {
            uuid: user.uuid.clone(),
            expires_at: exp,
            is_guest: false,
        },
    );

    let user_uuid = user.uuid.clone();
    let claims = Claims {
        uuid: user.uuid,
        username: user.username.unwrap_or_default(),
        role: user.role,
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

    // Update last_accessed_at on new session creation
    let _ = state.db.touch_user_access(&user_uuid);

    let mut headers = header::HeaderMap::new();
    let cookie = format!(
        "auth_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict; Secure",
        token,
        state.config.auth_session_ttl_seconds
    );
    headers.insert(header::SET_COOKIE, cookie.parse().unwrap());

    Ok((headers, Json(LoginResponse { token })))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> impl IntoResponse {
    // Accept the JWT from either the Authorization Bearer header (frontend logout())
    // or the auth_session cookie (overlay handleLogout, which sends no Bearer token).
    let bearer_token = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let cookie_token = req.headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .find(|c| c.trim().starts_with("auth_session="))
                .map(|c| c.trim()["auth_session=".len()..].to_string())
        });

    let token_str = bearer_token.or(cookie_token);

    if let Some(token) = token_str {
        // Use a more lenient validation for logout so we can invalidate the session even if technically expired
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false; 

        if let Ok(token_data) = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &validation,
        ) {
            let sid = &token_data.claims.sid;
            if state.active_auth_sessions.remove(sid).is_some() {
                tracing::info!("Logged out session: {}", sid);
            } else {
                tracing::debug!("Logout requested for session that was no longer active: {}", sid);
            }

            let uuid = token_data.claims.uuid.clone();
            
            // Find and remove all containers belonging to this user
            let mut to_cleanup = Vec::new();
            {
                let keys: Vec<String> = state.active_containers.iter()
                    .filter(|entry| entry.value().owner_uuid == uuid)
                    .map(|entry| entry.key().clone())
                    .collect();
                
                for k in keys {
                    if let Some((_, info)) = state.active_containers.remove(&k) {
                        to_cleanup.push(info.container_id);
                    }
                }
            }

            for container_id in to_cleanup {
                let state_clone = state.clone();
                let uuid_clone = uuid.to_string();
                tokio::spawn(async move {
                    crate::proxy::cleanup_oscar_session(state_clone, uuid_clone, container_id).await;
                });
            }
        } else {
             // Even if decoding fails, we proceed to clear cookies below
             tracing::warn!("Logout requested with undecodable token");
        }
    } else {
        tracing::debug!("Logout requested with no token present");
    }

    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .unwrap();

    // Clear both session cookies so the browser cannot re-authenticate automatically.
    response.headers_mut().insert(
        header::SET_COOKIE,
        "auth_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure".parse().unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        "oscar_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure".parse().unwrap(),
    );

    response
}


pub async fn session_check(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> impl IntoResponse {
    let _ = state.db.touch_user_access(&claims.uuid);
    Json(serde_json::json!({ "authenticated": true, "username": claims.username, "role": claims.role }))
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
    let api_key_header = req.headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok());

    if let Some(api_key) = api_key_header {
        // Parse "id.secret"
        if let Some((id_str, secret)) = api_key.split_once('.') {
            if let Ok(id) = id_str.parse::<i64>() {
                if let Ok(Some((hash, uuid))) = state.db.get_api_key_hash(id) {
                    use argon2::{password_hash::{PasswordHash, PasswordVerifier}, Argon2};
                    if let Ok(parsed_hash) = PasswordHash::new(&hash) {
                        if Argon2::default().verify_password(secret.as_bytes(), &parsed_hash).is_ok() {
                            if let Ok(Some(user)) = state.db.get_user_by_uuid(&uuid) {
                                let _ = state.db.touch_api_key(id);
                                let claims = Claims {
                                    uuid: user.uuid,
                                    username: user.username.unwrap_or_default(),
                                    role: user.role,
                                    sid: "api_key_auth".to_string(), // Fake session ID so downstream uses think there's a session
                                    exp: chrono::Utc::now().timestamp() + 3600,
                                };
                                req.extensions_mut().insert(claims);
                                return Ok(next.run(req).await);
                            }
                        }
                    }
                }
            }
        }
        // If API key is present but invalid, reject immediately.
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid API Key" }))));
    }

    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let cookie_auth = req.headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .find(|c| c.trim().starts_with("auth_session="))
                .map(|c| c.trim()["auth_session=".len()..].to_string())
        });

    let token = auth_header.map(|s| s.to_string()).or(cookie_auth);

    let is_html_request = req.uri().path().starts_with("/admin") || req.uri().path() == "/";

    let token = match token {
        Some(t) => t,
        None => {
            if is_html_request {
                return Ok(axum::response::Redirect::to("/").into_response());
            }
            if req.uri().path() == "/api/session" {
                return Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({ "authenticated": false }))
                ).into_response());
            }
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Unauthorized" })),
            ));
        }
    };

    let method = req.method();
    let is_mutation = method != axum::http::Method::GET 
        && method != axum::http::Method::HEAD 
        && method != axum::http::Method::OPTIONS;
    let is_logout = req.uri().path() == "/api/logout";

    if is_mutation && auth_header.is_none() && !is_logout {
        tracing::warn!(
            "Blocked mutation request ({}) to {} without Authorization header (CSRF prevention)",
            method,
            req.uri().path()
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "CSRF Prevention: Authorization header required for mutations" })),
        ));
    }

    let token_data_res = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    );

    let token_data = match token_data_res {
        Ok(td) => td,
        Err(_) => {
            if is_html_request {
                return Ok(axum::response::Redirect::to("/").into_response());
            }
            if req.uri().path() == "/api/session" {
                return Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({ "authenticated": false }))
                ).into_response());
            }
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Invalid token" })),
            ));
        }
    };

    let claims = token_data.claims;
    let now = chrono::Utc::now().timestamp();
    
    let is_valid = {
        state.active_auth_sessions.retain(|_, s| s.expires_at > now);

        if let Some(session) = state.active_auth_sessions.get(&claims.sid) {
            session.uuid == claims.uuid
        } else {
            false
        }
    };

    if is_valid {
        req.extensions_mut().insert(claims);
        return Ok(next.run(req).await);
    }

    if is_html_request {
        return Ok(axum::response::Redirect::to("/").into_response());
    }

    if req.uri().path() == "/api/session" {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "authenticated": false }))
        ).into_response());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "Session expired" })),
    ))
}

pub async fn admin_middleware(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let claims = req.extensions().get::<Claims>().ok_or((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "Unauthorized" })),
    ))?;

    if claims.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden: Admin access only" })),
        ));
    }

    Ok(next.run(req).await)
}

#[derive(Deserialize)]
pub struct CreateInvitePayload {
    pub expire_days: Option<i64>,
    pub label: Option<String>,
}

pub async fn generate_invite_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<Claims>,
    ExtractJson(payload): ExtractJson<CreateInvitePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let days = payload.expire_days.unwrap_or(3);
    let code = uuid::Uuid::new_v4().to_string().split('-').next().unwrap().to_uppercase();
    let expires_at = chrono::Utc::now().timestamp() + (days * 86400);
    state.db.create_invite(&code, &claims.uuid, expires_at, payload.label.clone()).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    tracing::info!(
        "Admin user {} generated a new invite: {} (expires_at: {})",
        claims.uuid,
        code,
        expires_at
    );
    let _ = state.db.log_audit_event(
        "generate_invite",
        Some(&claims.uuid),
        Some(&claims.username),
        Some(&format!("code: {}, label: {:?}", code, payload.label)),
        None
    );

    Ok(Json(serde_json::json!({ "code": code, "expires_at": expires_at })))
}

pub async fn revoke_invite_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(code): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.db.revoke_invite(&code).map_err(|_| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Invite not found or already deleted" })))
    })?;

    tracing::info!("Invite code {} was revoked.", code);
    let _ = state.db.log_audit_event(
        "revoke_invite",
        None,
        None,
        Some(&format!("code: {}", code)),
        None
    );

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ValidateInviteQuery {
    pub code: String,
}

pub async fn validate_invite_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ValidateInviteQuery>,
) -> Result<Json<InviteValidationResponse>, (StatusCode, Json<serde_json::Value>)> {
    let status = state.db.check_invite(&query.code).map_err(|e| {
        tracing::error!("Database error checking invite {}: {}", query.code, e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    Ok(Json(InviteValidationResponse {
        code: query.code,
        status,
    }))
}

pub async fn list_invites_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let invites = state.db.get_all_invites().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;
    Ok(Json(serde_json::json!({ "invites": invites })))
}

pub async fn list_users_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let users = state.db.get_all_users().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;
    
    let sanitized_users: Vec<_> = users.into_iter().map(|u| {
        serde_json::json!({
            "uuid": u.uuid,
            "username": u.username,
            "provider": u.provider,
            "role": u.role,
            "created_at": u.created_at,
            "last_accessed_at": u.last_accessed_at,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "users": sanitized_users })))
}

pub async fn list_audit_logs_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<AuditLogQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let (logs, total) = state.db.get_audit_logs(limit, offset).map_err(|e| {
        tracing::error!("Database error fetching audit logs: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    Ok(Json(serde_json::json!({ "logs": logs, "total": total })))
}

#[derive(serde::Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn delete_self_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    delete_user_handler_impl(state, claims.uuid).await
}

pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(uuid_param): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    delete_user_handler_impl(state, uuid_param).await
}

async fn delete_user_handler_impl(
    state: Arc<AppState>,
    uuid_param: String,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Fetch user first to determine folder name and perform cleanup
    let user_opt = state.db.get_user_by_uuid(&uuid_param).map_err(|e| {
        tracing::error!("Database error fetching user for deletion: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    let user = match user_opt {
        Some(u) => u,
        None => return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "User not found" })))),
    };

    let folder_name = crate::utils::sanitize_folder_name(user.username.as_deref().unwrap_or("")).unwrap_or(user.uuid.clone());

    // 2. Erase their active sessions
    state.active_auth_sessions.retain(|_, s| s.uuid != uuid_param);
    
    // 3. Evict active OSCAR containers (primary and guest) if they exist
    {
        let mut to_cleanup = Vec::new();
        
        state.active_containers.retain(|_, info| {
            if info.owner_uuid == uuid_param {
                to_cleanup.push(info.container_id.clone());
                false
            } else {
                true
            }
        });

        for cid in to_cleanup {
            let state_clone = state.clone();
            let upid = uuid_param.clone();
            tokio::spawn(async move {
                crate::proxy::cleanup_oscar_session(state_clone, upid, cid).await;
            });
        }
    }

    // 4. Delete their files from filesystem
    let upload_path = PathBuf::from(UPLOAD_ROOT).join(&folder_name);
    let profile_path = PathBuf::from(PROFILE_ROOT).join(&folder_name);
    let app_config_path = PathBuf::from(&state.config.app_config_root).join(&folder_name);
    
    let _ = fs::remove_dir_all(upload_path).await;
    let _ = fs::remove_dir_all(profile_path).await;
    let _ = fs::remove_dir_all(app_config_path).await;

    // 5. Delete user from SQLite database. This cascade-deletes their invites and share_links.
    state.db.delete_user(&uuid_param).map_err(|e| {
        tracing::error!("Database error deleting user {}: {}", uuid_param, e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to delete from database" })))
    })?;
    
    let uname = user.username.as_deref().unwrap_or("unknown");
    tracing::info!("User account deleted: {} (uuid: {})", uname, uuid_param);
    let _ = state.db.log_audit_event(
        "delete_user",
        Some(&uuid_param),
        Some(uname),
        None,
        None
    );

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn reset_password_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(uuid_param): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let new_pw = uuid::Uuid::new_v4().simple().to_string();
    
    use bip39::Mnemonic;
    use rand::{rngs::OsRng, RngCore};
    let mut rng = OsRng;
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    let recovery_phrase = mnemonic.to_string();

    let new_pw_clone = new_pw.clone();
    let recovery_phrase_clone = recovery_phrase.clone();
    
    let (password_hash, recovery_hash) = tokio::task::spawn_blocking(move || {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let argon2 = Argon2::default();
        
        let p_salt = SaltString::generate(&mut rng);
        let p_hash = argon2.hash_password(new_pw_clone.as_bytes(), &p_salt)
            .map(|h| h.to_string())
            .map_err(|_| "Password hashing failed")?;
            
        let r_salt = SaltString::generate(&mut rng);
        let r_hash = argon2.hash_password(recovery_phrase_clone.as_bytes(), &r_salt)
            .map(|h| h.to_string())
            .map_err(|_| "Recovery phrase hashing failed")?;
            
        Ok::<(_, _), &'static str>((p_hash, r_hash))
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal error" }))))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

    state.db.reset_user_credentials(&uuid_param, &password_hash, &recovery_hash).map_err(|_| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Local user not found" })))
    })?;

    // Clear active sessions for this user so they have to login again
    state.active_auth_sessions.retain(|_, s| s.uuid != uuid_param);

    tracing::info!("Admin reset credentials for user (uuid: {})", uuid_param);
    let _ = state.db.log_audit_event(
        "admin_reset_password",
        Some(&uuid_param),
        None,
        None,
        None
    );

    Ok(Json(serde_json::json!({ "new_password": new_pw, "recovery_phrase": recovery_phrase })))
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
        &Validation::new(Algorithm::HS256),
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
    let is_valid = {
        state.active_auth_sessions.retain(|_, s| s.expires_at > now);
        state.active_auth_sessions.contains_key(&claims.sid)
    };

    if !is_valid {
        tracing::debug!("require_oscar_session_middleware: session {} not found in active sessions", claims.sid);
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
    
    let mut req = req;
    req.extensions_mut().insert(claims.clone());
    
    Ok(next.run(req).await)
}

pub async fn list_share_links(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    match state.db.get_active_share_links_for_user(&claims.uuid) {
        Ok(links) => (StatusCode::OK, axum::Json(links)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Database error" }))).into_response(),
    }
}

pub async fn create_share_link(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now().timestamp() + 24 * 60 * 60; // 24 hours
    
    // Enforce max 5 links: delete oldest
    if let Ok(links) = state.db.get_active_share_links_for_user(&claims.uuid) {
        if links.len() >= 5 {
            // links are ordered created_at DESC. index 0 is newest.
            // keep index 0..3 (4 links), delete index 4+
            for link in links.iter().skip(4) {
                if let Some(token_to_delete) = link.get("token").and_then(|t| t.as_str()) {
                    let _ = state.db.delete_share_link(token_to_delete, &claims.uuid);
                }
            }
        }
    }

    match state.db.create_share_link(&token, &claims.uuid, expires_at) {
        Ok(_) => {
            tracing::info!("User {} created a new share link: {}", claims.uuid, token);
            let _ = state.db.log_audit_event(
                "create_share_link",
                Some(&claims.uuid),
                Some(&claims.username),
                Some(&format!("token: {}", token)),
                None
            );
            (StatusCode::OK, axum::Json(serde_json::json!({ "token": token, "expires_at": expires_at }))).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to create share link: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Failed to create share link" }))).into_response()
        }
    }
}

pub async fn delete_share_link(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(token): axum::extract::Path<String>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    match state.db.delete_share_link(&token, &claims.uuid) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(rusqlite::Error::QueryReturnedNoRows) => (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "error": "Share link not found" }))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Database error" }))).into_response(),
    }
}

pub async fn auth_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    let ip = addr.ip().to_string();
    let now = chrono::Utc::now().timestamp();

    let mut entry = state.auth_attempts.entry(ip).or_insert((0, now));
    let (count, start_time) = entry.value_mut();

    if now - *start_time > 60 {
        *count = 1;
        *start_time = now;
    } else {
        *count += 1;
    }

    if *count > 5 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({ "error": "Too many attempts. Please wait 60 seconds." })),
        ));
    }

    drop(entry);
    Ok(next.run(req).await)
}

pub fn create_user_profile(username: &str, uuid: &str, config: &crate::config::AppConfig) -> std::io::Result<()> {
    let folder_name = crate::utils::sanitize_folder_name(username).unwrap_or_else(|| uuid.to_string());
    
    let profile_user_dir = std::path::PathBuf::from(crate::config::PROFILE_ROOT)
        .join(&folder_name)
        .join("Profiles")
        .join(&folder_name);
        
    let app_config_dir = std::path::PathBuf::from(&config.app_config_root)
        .join(&folder_name);

    std::fs::create_dir_all(&profile_user_dir)?;
    std::fs::create_dir_all(&app_config_dir)?;

    let pref_xml = crate::templates::PREFERENCES_XML_TEMPLATE
        .replace("{USERNAME}", &folder_name)
        .replace("{VERSION}", &config.oscar_version);
        
    let prof_xml = crate::templates::PROFILE_XML_TEMPLATE
        .replace("{USERNAME}", &folder_name)
        .replace("{VERSION}", &config.oscar_version);

    std::fs::write(std::path::PathBuf::from(crate::config::PROFILE_ROOT).join(&folder_name).join("Preferences.xml"), pref_xml)?;
    std::fs::write(profile_user_dir.join("Profile.xml"), prof_xml)?;
    std::fs::write(app_config_dir.join("OSCAR.conf"), crate::templates::OSCAR_CONF_TEMPLATE)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        // Best effort chown to the upload uid/gid so uploader can manage it correctly
        let _ = chown(std::path::PathBuf::from(crate::config::PROFILE_ROOT).join(&folder_name), Some(config.upload_uid), Some(config.upload_gid));
        let _ = chown(&app_config_dir, Some(config.upload_uid), Some(config.upload_gid));
        let _ = chown(std::path::PathBuf::from(crate::config::PROFILE_ROOT).join(&folder_name).join("Preferences.xml"), Some(config.upload_uid), Some(config.upload_gid));
        let _ = chown(&profile_user_dir, Some(config.upload_uid), Some(config.upload_gid));
        let _ = chown(profile_user_dir.join("Profile.xml"), Some(config.upload_uid), Some(config.upload_gid));
        let _ = chown(app_config_dir.join("OSCAR.conf"), Some(config.upload_uid), Some(config.upload_gid));
    }

    Ok(())
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    pub label: Option<String>,
    pub scopes: Option<String>,
}

pub async fn create_api_key_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<Claims>,
    ExtractJson(payload): ExtractJson<CreateApiKeyPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use rand::{rngs::OsRng, RngCore};
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

    let secret_clone = secret.clone();
    let hash = tokio::task::spawn_blocking(move || {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(secret_clone.as_bytes(), &salt)
            .map(|h| h.to_string())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal error" }))))?
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Hash error" }))))?;

    let id = state.db.create_api_key(&claims.uuid, &hash, payload.label.clone(), payload.scopes.clone()).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;

    let plaintext_key = format!("{}.{}", id, secret);

    tracing::info!("User {} created a new API key: {}", claims.uuid, id);
    let _ = state.db.log_audit_event(
        "create_api_key",
        Some(&claims.uuid),
        Some(&claims.username),
        Some(&format!("key_id: {}, label: {:?}", id, payload.label)),
        None
    );

    Ok(Json(serde_json::json!({ "key": plaintext_key, "id": id })))
}

pub async fn list_api_keys_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let keys = state.db.list_api_keys(&claims.uuid).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;
    Ok(Json(serde_json::json!({ "api_keys": keys })))
}

pub async fn revoke_api_key_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.db.revoke_api_key(id, &claims.uuid).map_err(|_| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "API key not found" })))
    })?;

    tracing::info!("User {} revoked API key: {}", claims.uuid, id);
    let _ = state.db.log_audit_event(
        "revoke_api_key",
        Some(&claims.uuid),
        Some(&claims.username),
        Some(&format!("key_id: {}", id)),
        None
    );

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn get_me_handler(
    axum::Extension(claims): axum::Extension<Claims>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "uuid": claims.uuid,
        "username": claims.username,
        "role": claims.role,
    }))
}
