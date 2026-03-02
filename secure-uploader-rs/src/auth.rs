use axum::{
    extract::{Request, State, ConnectInfo},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response, Json},
    Json as ExtractJson,
    Extension,
};
use std::net::SocketAddr;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use rsa::pkcs8::EncodePublicKey;

use crate::config::{AppState, SessionInfo, UPLOAD_ROOT, PROFILE_ROOT};
use bollard::container::{StopContainerOptions, RemoveContainerOptions};
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub uuid: String,
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
    pub state: Option<String>,
}

#[derive(Deserialize)]
pub struct DiscordLoginQuery {
    pub invite: Option<String>,
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
    axum::extract::Query(query): axum::extract::Query<DiscordLoginQuery>,
) -> impl IntoResponse {
    let client_id = &state.config.discord_client_id;
    let redirect_uri = urlencoding::encode(&state.config.discord_redirect_uri);
    let state_param = query.invite.unwrap_or_default();
    
    let url = format!(
        "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify&state={}",
        client_id, redirect_uri, state_param
    );
    
    axum::response::Redirect::to(&url)
}

pub async fn discord_callback(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<DiscordCallbackQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
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
            username: Some(discord_user.username),
            provider: "discord".to_string(),
            identifier: discord_user.id.clone(),
            role: "user".to_string(),
            created_at: now,
            last_accessed_at: Some(now),
        };
        
        state.db.create_user(new_user.clone(), None).map_err(|e| {
            tracing::error!("Failed to create user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to create user" })))
        })?;
        
        // Mark invite as used
        let _ = state.db.use_invite(invite_code, &new_user.uuid);
        
        user = Some(new_user);
    }

    let user = user.unwrap();
    let (headers, token_res) = issue_session(&state, user).await?;
    
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
    if payload.username.len() < 1 || payload.username.len() > 128 || !payload.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
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
    let password_hash = tokio::task::spawn_blocking(move || {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let salt = SaltString::generate(&mut rng);
        let argon2 = Argon2::default();
        argon2.hash_password(password_clone.as_bytes(), &salt)
            .map(|h| h.to_string())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal error" }))))?
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Password hashing failed" }))))?;

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

    state.db.create_user(user.clone(), Some(password_hash)).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to create user" })))
    })?;

    state.db.use_invite(&payload.invite_code, &uuid).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invite update error" })))
    })?;

    let (headers, token_res) = issue_session(&state, user).await?;
    
    Ok((headers, Json(SignupResponse {
        username: payload.username,
        password,
        recovery_phrase,
        token: token_res.0.token,
    })))
}

pub async fn local_login(
    State(state): State<Arc<AppState>>,
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
            let (headers, token_res) = issue_session(&state, u).await?;
            Ok((headers, token_res))
        }
        None => Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Invalid credentials" })))),
    }
}

async fn issue_session(
    state: &AppState,
    user: crate::db::User,
) -> Result<(header::HeaderMap, Json<LoginResponse>), (StatusCode, Json<serde_json::Value>)> {
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

                    let uuid = token_data.claims.uuid.clone();
                    if let Some(info) = state.active_containers.write().await.remove(&uuid) {
                        let docker = state.docker.clone();
                        tokio::spawn(async move {
                            tracing::info!("User logged out. Evicting OSCAR container {}.", info.container_id);
                            let _ = docker.stop_container(&info.container_id, None::<StopContainerOptions>).await;
                            let _ = docker.remove_container(&info.container_id, Some(RemoveContainerOptions { force: true, ..Default::default() })).await;
                        });
                    }
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

pub async fn session_check(
    State(state): State<Arc<AppState>>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> impl IntoResponse {
    let _ = state.db.touch_user_access(&claims.uuid);
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
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Unauthorized" })),
            ));
        }
    };

    let token_data_res = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    );

    let token_data = match token_data_res {
        Ok(td) => td,
        Err(_) => {
            if is_html_request {
                return Ok(axum::response::Redirect::to("/").into_response());
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
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.retain(|_, s| s.expires_at > now);

        if let Some(session) = sessions.get(&claims.sid) {
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
    state.db.create_invite(&code, &claims.uuid, expires_at, payload.label).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" })))
    })?;
    Ok(Json(serde_json::json!({ "code": code, "expires_at": expires_at })))
}

pub async fn revoke_invite_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(code): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.db.revoke_invite(&code).map_err(|_| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Invite not found or already deleted" })))
    })?;
    Ok(Json(serde_json::json!({ "ok": true })))
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

pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(uuid_param): axum::extract::Path<String>,
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
    {
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.retain(|_, s| s.uuid != uuid_param);
    }
    
    // 3. Evict active OSCAR container if it exists
    {
        let mut containers = state.active_containers.write().await;
        if let Some(info) = containers.remove(&uuid_param) {
            let docker = state.docker.clone();
            let upid = uuid_param.clone();
            tokio::spawn(async move {
                tracing::info!("Evicting OSCAR container {} for deleted user {}.", info.container_id, upid);
                let _ = docker.stop_container(&info.container_id, None::<StopContainerOptions>).await;
                let _ = docker.remove_container(&info.container_id, Some(RemoveContainerOptions { force: true, ..Default::default() })).await;
            });
        }
    }

    // 4. Delete their files from filesystem
    let upload_path = PathBuf::from(UPLOAD_ROOT).join(&folder_name);
    let profile_path = PathBuf::from(PROFILE_ROOT).join(&folder_name);
    
    let _ = fs::remove_dir_all(upload_path).await;
    let _ = fs::remove_dir_all(profile_path).await;

    // 5. Delete user from SQLite database. This cascade-deletes their invites and share_links.
    state.db.delete_user(&uuid_param).map_err(|e| {
        tracing::error!("Database error deleting user {}: {}", uuid_param, e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to delete from database" })))
    })?;
    
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn reset_password_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(uuid_param): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let new_pw = uuid::Uuid::new_v4().to_string().split('-').next().unwrap().to_string();
    
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(new_pw.as_bytes(), &salt)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Hash error" }))))?
        .to_string();

    state.db.reset_user_password(&uuid_param, &password_hash).map_err(|_| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Local user not found" })))
    })?;

    // Clear active sessions for this user so they have to login again
    let mut sessions = state.active_auth_sessions.write().await;
    sessions.retain(|_, s| s.uuid != uuid_param);

    Ok(Json(serde_json::json!({ "new_password": new_pw })))
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
    let is_valid = {
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.retain(|_, s| s.expires_at > now);
        sessions.contains_key(&claims.sid)
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
            for num in 4..links.len() {
                if let Some(token_to_delete) = links[num].get("token").and_then(|t| t.as_str()) {
                    let _ = state.db.delete_share_link(token_to_delete, &claims.uuid);
                }
            }
        }
    }

    match state.db.create_share_link(&token, &claims.uuid, expires_at) {
        Ok(_) => (StatusCode::OK, axum::Json(serde_json::json!({ "token": token, "expires_at": expires_at }))).into_response(),
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
