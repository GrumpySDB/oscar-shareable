use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response, Redirect},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::config::{AppState, ContainerInfo};
use crate::auth::{Claims, OscarClaims};
use bollard::container::{Config, CreateContainerOptions, StartContainerOptions, InspectContainerOptions};
use bollard::models::HostConfig;

#[derive(Deserialize)]
pub struct OscarLaunchQuery {
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LaunchTokenClaims {
    pub sub: String,
    pub sid: String,
    pub fp: String,
    pub jti: String,
    pub purpose: String,
    pub exp: i64,
}

pub async fn ensure_oscar_container(
    state: &Arc<AppState>,
    owner_uuid: &str,
    owner_username: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let host_path = std::env::var("DOCKER_HOST_PATH").unwrap_or_else(|_| ".".to_string());
    let docker_network = std::env::var("DOCKER_NETWORK").unwrap_or_else(|_| "oscar-shareable_internal".to_string());
    
    // Safety check: ensure owner_username is sanitized to avoid path traversal
    let username = crate::utils::sanitize_folder_name(owner_username).unwrap_or(owner_uuid.to_string());
    let container_name = format!("oscar-session-{}", owner_uuid);

    // Ensure directories exist on host before container start to prevent Docker from creating them as root
    let uploads_dir = std::path::PathBuf::from("./data/uploads").join(&username);
    let profiles_dir = std::path::PathBuf::from("./data/profiles").join(&username);
    let _ = tokio::fs::create_dir_all(&uploads_dir).await;
    let _ = tokio::fs::create_dir_all(&profiles_dir).await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        let _ = chown(&uploads_dir, Some(911), Some(911));
        let _ = chown(&profiles_dir, Some(911), Some(911));
    }

    let docker = &state.docker;
    let mut ip_address = String::new();

    match docker.inspect_container(&container_name, None::<InspectContainerOptions>).await {
        Ok(info) => {
            if !info.state.as_ref().and_then(|s| s.running).unwrap_or(false) {
                let _ = docker.start_container(&container_name, None::<StartContainerOptions<String>>).await;
            }
            if let Some(net) = info.network_settings.and_then(|n| n.networks) {
                if let Some(n) = net.get(&docker_network) {
                    ip_address = n.ip_address.clone().unwrap_or_default();
                }
            }
        },
        Err(e) => {
            if e.to_string().contains("404") || e.to_string().contains("No such container") {
                let options = Some(CreateContainerOptions {
                    name: container_name.clone(),
                    platform: None,
                });
                let config = Config {
                    image: Some("custom-oscar-vnc:latest".to_string()),
                    host_config: Some(HostConfig {
                        binds: Some(vec![
                            format!("{}/data/profiles/{}:/config/Documents/OSCAR_Data:rw", host_path, username),
                            format!("{}/data/uploads/{}:/config/Documents/SDCARD:rw", host_path, username),
                        ]),
                        network_mode: Some(docker_network.clone()),
                        shm_size: Some(1024 * 1024 * 1024),
                        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                        ..Default::default()
                    }),
                    env: Some(vec![
                        "PUID=911".to_string(),
                        "PGID=911".to_string(),
                        "TZ=America/Chicago".to_string(),
                        "TITLE=OSCAR 1.7.0".to_string(),
                        "START_DOCKER=false".to_string(),
                        "DISABLE_IPV6=true".to_string(),
                        "NO_DECOR=true".to_string(),
                        "NO_GAMEPAD=true".to_string(),
                        "HARDEN_DESKTOP=true".to_string(),
                        "HARDEN_OPENBOX=true".to_string(),
                        "SELKIES_ENABLE_CURSORS=true".to_string(),
                    ]),
                    ..Default::default()
                };

                if let Err(err) = docker.create_container(options, config).await {
                    tracing::error!("Failed to create container {}: {}", container_name, err);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Failed to provision OSCAR environment" }))));
                }

                if let Err(err) = docker.start_container(&container_name, None::<StartContainerOptions<String>>).await {
                    tracing::error!("Failed to start container {}: {}", container_name, err);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Failed to start OSCAR environment" }))));
                }

                // Wait slightly for networking to settle
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                if let Ok(info) = docker.inspect_container(&container_name, None::<InspectContainerOptions>).await {
                    if let Some(net) = info.network_settings.and_then(|n| n.networks) {
                        if let Some(n) = net.get(&docker_network) {
                            ip_address = n.ip_address.clone().unwrap_or_default();
                        }
                    }
                }
            } else {
                tracing::error!("Error inspecting container {}: {}", container_name, e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Internal container error" }))));
            }
        }
    }

    if ip_address.is_empty() {
        tracing::error!("Could not query network IP for container {}", container_name);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Networking failure. OSCAR did not attach to bridge correctly." }))));
    }

    {
        let mut containers = state.active_containers.write().await;
        containers.insert(owner_uuid.to_string(), ContainerInfo {
            container_id: container_name.clone(),
            ip_address,
            last_active: chrono::Utc::now().timestamp(),
        });
    }

    Ok(())
}

pub async fn oscar_launch(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let claims = req.extensions().get::<Claims>().unwrap();
    
    let user_agent = req.headers().get(header::USER_AGENT).and_then(|h| h.to_str().ok()).unwrap_or("");
    let accept_language = req.headers().get(header::ACCEPT_LANGUAGE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let fp_str = format!("{}\n{}", user_agent, accept_language);
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(fp_str.as_bytes());
    let fp = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let jti = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    if let Err(e) = ensure_oscar_container(&state, &claims.uuid, &claims.username).await {
        return e.into_response();
    }
    
    let launch_claims = LaunchTokenClaims {
        sub: claims.uuid.clone(),
        sid: claims.sid.clone(),
        fp,
        jti,
        purpose: "oscar-launch".into(),
        exp: now + 120, // 2 minutes
    };

    let token = encode(
        &Header::default(),
        &launch_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes())
    ).unwrap();

    axum::Json(serde_json::json!({
        "launchUrl": format!("/oscar/login?token={}", urlencoding::encode(&token))
    })).into_response()
}

pub async fn oscar_share_launch(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(share_token): axum::extract::Path<String>,
    req: Request,
) -> Response {
    let owner_uuid = match state.db.get_share_link_owner(&share_token) {
        Ok(Some(uuid)) => uuid,
        Ok(None) => return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({ "error": "Invalid or expired share link" }))).into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Database error" }))).into_response(),
    };

    let owner = match state.db.get_user_by_uuid(&owner_uuid) {
        Ok(Some(u)) => u,
        _ => return (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "error": "Profile owner not found" }))).into_response(),
    };
    let owner_username = owner.username.unwrap_or(owner.uuid.clone());

    if let Err(e) = ensure_oscar_container(&state, &owner_uuid, &owner_username).await {
        return e.into_response();
    }

    let user_agent = req.headers().get(header::USER_AGENT).and_then(|h| h.to_str().ok()).unwrap_or("");
    let accept_language = req.headers().get(header::ACCEPT_LANGUAGE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let fp_str = format!("{}\n{}", user_agent, accept_language);
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(fp_str.as_bytes());
    let fp = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let jti = uuid::Uuid::new_v4().to_string();
    let guest_sid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    // Create an ephemeral auth session for the guest tied to the owner's UUID
    {
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.insert(guest_sid.clone(), crate::config::SessionInfo {
            uuid: owner_uuid.clone(),
            expires_at: now + 8 * 60 * 60,
        });
    }

    let launch_claims = LaunchTokenClaims {
        sub: owner_uuid,
        sid: guest_sid,
        fp,
        jti,
        purpose: "oscar-launch".into(),
        exp: now + 120, // 2 minutes
    };

    let token = encode(
        &Header::default(),
        &launch_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes())
    ).unwrap();

    axum::Json(serde_json::json!({
        "launchUrl": format!("/oscar/login?token={}", urlencoding::encode(&token))
    })).into_response()
}

/// Dedicated handler for /oscar/login.
/// This route is NOT behind the session-cookie middleware.
/// Instead it validates a one-time launch token (issued only to authenticated users)
/// and creates the session cookie.
pub async fn oscar_login_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    tracing::debug!("oscar_login_handler: /oscar/login hit");
    let qs = req.uri().query().unwrap_or("");
    let query_params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(qs.as_bytes())
        .into_owned()
        .collect();

    let token = if let Some(t) = query_params.get("token") {
        t.clone()
    } else {
        tracing::debug!("oscar_login_handler: no token param => redirect to /");
        return Redirect::to("/").into_response();
    };

    let now = chrono::Utc::now().timestamp();
    {
        let mut consumed = state.consumed_launch_tokens.write().await;
        consumed.retain(|_, &mut exp| exp > now);
    }

    let token_data = match decode::<LaunchTokenClaims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!("oscar_login_handler: token decode failed: {}", e);
            return Redirect::to("/").into_response();
        }
    };

    let claims = token_data.claims;
    if claims.purpose != "oscar-launch" {
        tracing::debug!("oscar_login_handler: purpose mismatch: {}", claims.purpose);
        return Redirect::to("/").into_response();
    }

    {
        let mut consumed = state.consumed_launch_tokens.write().await;
        if consumed.contains_key(&claims.jti) {
            tracing::debug!("oscar_login_handler: token already consumed: {}", claims.jti);
            return Redirect::to("/").into_response();
        }
        consumed.insert(claims.jti, now + 120);
    }

    // Verify the auth session is still active
    {
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.retain(|_, s| s.expires_at > now);
        if !sessions.contains_key(&claims.sid) {
            tracing::debug!("oscar_login_handler: auth session {} not found", claims.sid);
            return Redirect::to("/").into_response();
        }
    }

    let oscar_claims = OscarClaims {
        uuid: claims.sub,
        sid: claims.sid.clone(),
        fp: claims.fp,
        scope: "oscar".into(),
        exp: now + 8 * 60 * 60, // 8 hours
    };

    let session_token = encode(
        &Header::default(),
        &oscar_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes())
    ).unwrap();

    let cookie_value = format!("oscar_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax; Secure", session_token, 8*60*60);
    tracing::debug!("oscar_login_handler: setting cookie, redirecting to /oscar/, sid={}", claims.sid);

    let mut res = Redirect::to("/oscar/").into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value.parse().unwrap()
    );
    res
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let mut path = req.uri().path().to_string();
    if path.starts_with("/oscar") {
        path = path.replacen("/oscar", "", 1);
        if path.is_empty() {
            path = "/".into();
        }
    }
    
    let qs = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    
    let claims = match req.extensions().get::<OscarClaims>() {
        Some(c) => c,
        None => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("Missing OSCAR session claims")).unwrap(),
    };

    let target_ip = {
        let containers = state.active_containers.read().await;
        if let Some(info) = containers.get(&claims.uuid) {
            info.ip_address.clone()
        } else {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Container session expired or stopped. Please return to the homepage and relaunch OSCAR."))
                .unwrap();
        }
    };

    {
        let mut containers = state.active_containers.write().await;
        if let Some(info) = containers.get_mut(&claims.uuid) {
            info.last_active = chrono::Utc::now().timestamp();
        }
    }

    let target_url = format!("http://{}:3000{}{}", target_ip, path, qs);

    // Filter hop-by-hop headers
    let hop_by_hop = vec![
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "authorization",
    ];



    let is_upgrade = req.headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_upgrade {
        return handle_websocket_upgrade(state, req, &target_url).await;
    }

    let client = &state.reqwest_client;
    let mut builder = client.request(req.method().clone(), &target_url);

    for (name, value) in req.headers() {
        if !hop_by_hop.contains(&name.as_str()) {
            builder = builder.header(name.clone(), value.clone());
        }
    }

    let req_body = req.into_body();
    builder = builder.body(reqwest::Body::wrap_stream(req_body.into_data_stream()));

    match builder.send().await {
        Ok(proxy_res) => {
            let mut response = Response::builder().status(proxy_res.status());
            
            for (name, value) in proxy_res.headers() {
                if name == "transfer-encoding" {
                    continue;
                }
                if name == "content-security-policy" {
                    if let Ok(val) = value.to_str() {
                        let mut dirs: Vec<&str> = val.split(';').map(|s| s.trim()).filter(|s| !s.is_empty() && !s.to_lowercase().starts_with("frame-ancestors")).collect();
                        dirs.push("frame-ancestors 'self'");
                        response.headers_mut().unwrap().insert(
                            name,
                            HeaderValue::try_from(dirs.join("; ")).unwrap()
                        );
                        continue;
                    }
                }
                response.headers_mut().unwrap().insert(name, value.clone());
            }

            response.body(Body::from_stream(proxy_res.bytes_stream())).unwrap()
        }
        Err(e) => {
            tracing::error!("Proxy request failed: {}", e);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Unable to connect to OSCAR service"))
                .unwrap()
        }
    }
}

async fn handle_websocket_upgrade(
    _state: Arc<AppState>,
    req: Request,
    target_url: &str,
) -> Response {
    // Handling websockets. We convert the http url to ws or wss
    let ws_url = if target_url.starts_with("https://") {
        target_url.replacen("https://", "wss://", 1)
    } else {
        target_url.replacen("http://", "ws://", 1)
    };

    let mut ws_req = reqwest::Request::new(reqwest::Method::GET, reqwest::Url::parse(&ws_url).unwrap());
    for (k, v) in req.headers() {
        ws_req.headers_mut().insert(k.clone(), v.clone());
    }

    // `axum` has an upgrade capability we can use to accept the client WS,
    // but the simplest way is to manually do a tokio tunnel.
    // For now we will return 502 Not Implemented properly, and implement in next iteration if needed 
    // or use tokio-tungstenite to forward. 
    // Let's implement full tunnel with tokio-tungstenite.

    use futures::{StreamExt, SinkExt};
    use axum::extract::FromRequestParts;
    let mut parts = req.into_parts().0;
    let upgrade = match axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(u) => u,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    upgrade.on_upgrade(move |client_ws: axum::extract::ws::WebSocket| async move {
        match tokio_tungstenite::connect_async(ws_url).await {
            Ok((server_ws, _)) => {
                let (mut client_tx, mut client_rx) = client_ws.split();
                let (mut server_tx, mut server_rx) = server_ws.split();

                let client_to_server = async {
                    while let Some(Ok(msg)) = client_rx.next().await {
                        use axum::extract::ws::Message as AxumMsg;
                        use tokio_tungstenite::tungstenite::Message as TungMsg;
                        let tung_msg = match msg {
                            AxumMsg::Text(t) => TungMsg::Text(t),
                            AxumMsg::Binary(b) => TungMsg::Binary(b),
                            AxumMsg::Ping(p) => TungMsg::Ping(p),
                            AxumMsg::Pong(p) => TungMsg::Pong(p),
                            AxumMsg::Close(_) => TungMsg::Close(None),
                        };
                        if server_tx.send(tung_msg).await.is_err() {
                            break;
                        }
                    }
                };

                let server_to_client = async {
                    while let Some(Ok(msg)) = server_rx.next().await {
                        use axum::extract::ws::Message as AxumMsg;
                        use tokio_tungstenite::tungstenite::Message as TungMsg;
                        let ax_msg = match msg {
                            TungMsg::Text(t) => AxumMsg::Text(t),
                            TungMsg::Binary(b) => AxumMsg::Binary(b),
                            TungMsg::Ping(p) => AxumMsg::Ping(p),
                            TungMsg::Pong(p) => AxumMsg::Pong(p),
                            TungMsg::Close(_) => AxumMsg::Close(None),
                            TungMsg::Frame(_) => continue,
                        };
                        if client_tx.send(ax_msg).await.is_err() {
                            break;
                        }
                    }
                };

                tokio::select! {
                    _ = client_to_server => {}
                    _ = server_to_client => {}
                }
            }
            Err(e) => {
                tracing::error!("Failed to connect to backend WS: {}", e);
            }
        }
    })
}
