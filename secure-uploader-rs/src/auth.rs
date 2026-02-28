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

use crate::{
    config::{AppState, SessionInfo},
    utils::safe_equal,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub sid: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscarClaims {
    pub sub: String,
    pub sid: String,
    pub fp: String,
    pub scope: String,
    pub exp: i64,
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ExtractJson(payload): ExtractJson<LoginPayload>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let username = payload.username.unwrap_or_default();
    let password = payload.password.unwrap_or_default();

    if !safe_equal(&username, &state.config.app_username)
        || !safe_equal(&password, &state.config.app_password)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid credentials" })),
        ));
    }

    let sid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let exp = now + state.config.auth_session_ttl_seconds as i64;

    state.active_auth_sessions.write().await.insert(
        sid.clone(),
        SessionInfo {
            sub: username.clone(),
            expires_at: exp,
        },
    );

    let claims = Claims {
        sub: username,
        sid,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to create token" })),
        )
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
        if session.sub == claims.sub {
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
    let cookie_header = req.headers().get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let mut oscar_session = None;
    for cookie_str in cookie_header.split(';') {
        let trimmed = cookie_str.trim();
        if let Some(val) = trimmed.strip_prefix("oscar_session=") {
            oscar_session = Some(val.to_string());
            break;
        }
    }

    let token = match oscar_session {
        Some(t) => t,
        None => return Err(axum::response::Redirect::to("/")),
    };

    let token_data = decode::<OscarClaims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    ).map_err(|_| axum::response::Redirect::to("/"))?;

    let claims = token_data.claims;
    if claims.scope != "oscar" {
        return Err(axum::response::Redirect::to("/"));
    }

    let now = chrono::Utc::now().timestamp();
    let mut sessions = state.active_auth_sessions.write().await;
    sessions.retain(|_, s| s.expires_at > now);

    if !sessions.contains_key(&claims.sid) {
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
        return Err(axum::response::Redirect::to("/"));
    }

    Ok(next.run(req).await)
}
