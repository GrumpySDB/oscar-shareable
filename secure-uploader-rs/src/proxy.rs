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
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::config::{AppState, ContainerInfo};
use crate::auth::{Claims, OscarClaims};
use bollard::container::{Config, CreateContainerOptions, StartContainerOptions, InspectContainerOptions, StopContainerOptions, RemoveContainerOptions};
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
    pub container_key: String,
}

async fn create_ephemeral_profile(owner_username: &str, ephemeral_folder: &str) -> std::io::Result<()> {
    let script = format!(r#"
        PROFILE="{}"
        EPHEM="{}"
        mkdir -p data/profiles/$EPHEM/Profiles/$PROFILE
        cp -r data/profiles/$PROFILE/*.xml data/profiles/$EPHEM/ 2>/dev/null || true
        cp -r data/profiles/$PROFILE/Profiles/$PROFILE/*.xml data/profiles/$EPHEM/Profiles/$PROFILE/ 2>/dev/null || true
        cp -r data/profiles/$PROFILE/Profiles/$PROFILE/lockfile data/profiles/$EPHEM/Profiles/$PROFILE/ 2>/dev/null || true
        cp -r data/profiles/$PROFILE/Profiles/$PROFILE/*.dat data/profiles/$EPHEM/Profiles/$PROFILE/ 2>/dev/null || true
        cp -r data/profiles/$PROFILE/Profiles/$PROFILE/*.shg data/profiles/$EPHEM/Profiles/$PROFILE/ 2>/dev/null || true
        cp -r data/profiles/$PROFILE/Profiles/$PROFILE/*.cache data/profiles/$EPHEM/Profiles/$PROFILE/ 2>/dev/null || true
        
        for machine in data/profiles/$PROFILE/Profiles/$PROFILE/*/; do
            [ -d "$machine" ] || continue
            mname=$(basename "$machine")
            mkdir -p "data/profiles/$EPHEM/Profiles/$PROFILE/$mname"
            for item in "$machine"*; do
                iname=$(basename "$item")
                if [ -d "$item" ]; then
                    ln -s "/original_profile/Profiles/$PROFILE/$mname/$iname" "data/profiles/$EPHEM/Profiles/$PROFILE/$mname/$iname"
                else
                    cp -r "$item" "data/profiles/$EPHEM/Profiles/$PROFILE/$mname/" 2>/dev/null || true
                fi
            done
        done
        
        mkdir -p data/app_config/$EPHEM
        cp -r data/app_config/$PROFILE/* data/app_config/$EPHEM/ 2>/dev/null || true
    "#, owner_username, ephemeral_folder);

    let status = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .status()
        .await?;
        
    if !status.success() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to create ephemeral profile"));
    }
    
    #[cfg(unix)]
    {
        let p_dir = format!("data/profiles/{}", ephemeral_folder);
        let c_dir = format!("data/app_config/{}", ephemeral_folder);
        let _ = tokio::process::Command::new("chown").args(&["-R", "911:911", &p_dir, &c_dir]).status().await;
    }
    
    Ok(())
}

pub async fn ensure_oscar_container(
    state: &Arc<AppState>,
    owner_uuid: &str,
    owner_username: &str,
    container_key: &str,
    is_ephemeral: bool,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let host_path = std::env::var("DOCKER_HOST_PATH").unwrap_or_else(|_| ".".to_string());
    let docker_network = std::env::var("DOCKER_NETWORK").unwrap_or_else(|_| "oscar-shareable_internal".to_string());
    
    let base_username = crate::utils::sanitize_folder_name(owner_username).unwrap_or(owner_uuid.to_string());
    let active_username = if is_ephemeral {
        format!("ephemeral_{}", container_key)
    } else {
        base_username.clone()
    };
    
    let container_name = if is_ephemeral {
        format!("oscar-ephemeral-{}", container_key)
    } else {
        format!("oscar-session-{}", container_key)
    };

    let uploads_dir = std::path::PathBuf::from("./data/uploads").join(&base_username); // SDCARD is always base_username
    let profiles_dir = std::path::PathBuf::from("./data/profiles").join(&active_username);
    let app_config_dir = std::path::PathBuf::from("./data/app_config").join(&active_username);
    
    if is_ephemeral {
        if let Err(e) = create_ephemeral_profile(&base_username, &active_username).await {
            tracing::error!("Failed to generate ephemeral profile: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "error": "Failed to generate temporary profile" }))));
        }
    } else {
        let _ = tokio::fs::create_dir_all(&uploads_dir).await;
        let _ = tokio::fs::create_dir_all(&profiles_dir).await;
        let _ = tokio::fs::create_dir_all(&app_config_dir).await;
        #[cfg(unix)]
        {
            use std::os::unix::fs::chown;
            let _ = chown(&uploads_dir, Some(911), Some(911));
            let _ = chown(&profiles_dir, Some(911), Some(911));
            let _ = chown(&app_config_dir, Some(911), Some(911));
        }
    }

    let docker = &state.docker;
    let mut ip_address = String::new();

    let is_active = {
        let mut to_cleanup = Vec::new();
        {
            let containers = state.active_containers.read().await;
            if !is_ephemeral {
                // For primary sessions, find any existing active containers for the SAME user
                // but with DIFFERENT keys (stale sessions from a previous launch).
                for (k, info) in containers.iter() {
                    if info.owner_uuid == owner_uuid && k != container_key {
                        to_cleanup.push((k.clone(), info.container_id.clone()));
                    }
                }
            }
        }

        if !to_cleanup.is_empty() {
            let mut containers = state.active_containers.write().await;
            for (k, cid) in to_cleanup {
                tracing::info!("Evicting stale session {} for user {} as a new session is launching.", k, owner_uuid);
                containers.remove(&k);
                let state_clone = state.clone();
                let uuid_clone = owner_uuid.to_string();
                tokio::spawn(async move {
                    cleanup_oscar_session(state_clone, uuid_clone, cid).await;
                });
            }
        }

        let containers = state.active_containers.read().await;
        containers.contains_key(container_key)
    };

    if !is_active {
        // Enforce a strict cleanup before proceeding to prevent race conditions during rapid re-logins
        let _ = docker.remove_container(&container_name, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await;
        
        // Wait until it's really gone
        for _ in 0..20 {
            if docker.inspect_container(&container_name, None::<InspectContainerOptions>).await.is_err() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }

        // Now meticulously purge physical lockfile from disk if starting a fresh primary session.
        // We do this because the memory-based 'last_active' check already confirmed the container 
        // isn't actually in use by a live session tab, so any remaining lockfile is stale.
        let profiles_dir = std::path::PathBuf::from("./data/profiles").join(&active_username).join("Profiles");
        if let Ok(mut entries) = tokio::fs::read_dir(&profiles_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                    let lockfile_path = entry.path().join("lockfile");
                    if lockfile_path.exists() {
                        tracing::info!("Pre-emptively purging lockfile at {:?}", lockfile_path);
                        let _ = tokio::fs::remove_file(lockfile_path).await;
                    }
                }
            }
        }
    }

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
                let mut binds = vec![
                    format!("{}/data/profiles/{}:/config/Documents/OSCAR_Data:rw", host_path, active_username),
                    format!("{}/data/uploads/{}:/config/Documents/SDCARD:ro", host_path, base_username),
                    format!("{}/data/app_config/{}:/config/.config/OSCAR_Team:rw", host_path, active_username),
                ];
                
                if is_ephemeral {
                    binds.push(format!("{}/data/profiles/{}:/original_profile:ro", host_path, base_username));
                }

                let config = Config {
                    image: Some(state.config.oscar_docker_image.clone()),
                    host_config: Some(HostConfig {
                        binds: Some(binds),
                        network_mode: Some(docker_network.clone()),
                        shm_size: Some(1024 * 1024 * 1024),
                        memory: Some(768 * 1024 * 1024), // 768MB
                        memory_swap: Some(768 * 1024 * 1024), // No swap beyond 768MB
                        nano_cpus: Some(1_000_000_000), // 1.0 CPU
                        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                        ..Default::default()
                    }),
                    env: Some(vec![
                        "PUID=911".to_string(),
                        "PGID=911".to_string(),
                        "TZ=America/Chicago".to_string(),
                        "MAX_RES=3840x2160".to_string(),
                        "TITLE=OSCAR (Web)".to_string(),
                        "START_DOCKER=false".to_string(),
                        "DISABLE_IPV6=true".to_string(),
                        "NO_DECOR=true".to_string(),
                        "NO_GAMEPAD=true".to_string(),
                        "HARDEN_DESKTOP=true".to_string(),
                        "HARDEN_OPENBOX=true".to_string(),
                        "SELKIES_ENABLE_CURSORS=true".to_string(),
                        "SELKIES_AUDIO_ENABLED=false".to_string(),
                        "SELKIES_GAMEPAD_ENABLED=false".to_string(),
                        "SELKIES_UI_SIDEBAR_SHOW_GAMEPADS=false".to_string(),
                        "SELKIES_UI_SIDEBAR_SHOW_CLIPBOARD=false".to_string(),
                        "SELKIES_UI_SIDEBAR_SHOW_AUDIO_SETTINGS=false".to_string(),
                        "SELKIES_UI_SIDEBAR_SHOW_SHARING=false".to_string(),
                        "SELKIES_MICROPHONE_ENABLED=false".to_string(),
                        "SELKIES_CLIPBOARD_IN_ENABLED=false".to_string(),
                        "SELKIES_CLIPBOARD_OUT_ENABLED=true".to_string(),
                        "SELKIES_SECOND_SCREEN=false".to_string(),
                        "SELKIES_ENABLE_SHARING=true".to_string(),
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
        containers.insert(container_key.to_string(), ContainerInfo {
            container_id: container_name.clone(),
            ip_address,
            last_active: chrono::Utc::now().timestamp(),
            owner_uuid: owner_uuid.to_string(),
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

    let now = chrono::Utc::now().timestamp();

    // Always issue a fresh launch token — never shortcut to /oscar/ directly.
    // This ensures Selkies always gets a clean signaling init rather than
    // reconnecting to a potentially dirty WebSocket state from a prior session.
    
    // Generate a unique container key for this launch to isolate transitions
    // and prevent race conditions with disconnect beacons from old windows.
    let container_key = format!("{}-{}", claims.uuid, &uuid::Uuid::new_v4().to_string()[..8]);
    
    tracing::info!("oscar_launch: Launching personal session for user {} with key {}", claims.uuid, container_key);
    if let Err(e) = ensure_oscar_container(&state, &claims.uuid, &claims.username, &container_key, false).await {
        return e.into_response();
    }
    
    let jti = uuid::Uuid::new_v4().to_string();
    let launch_claims = LaunchTokenClaims {
        sub: claims.uuid.clone(),
        sid: claims.sid.clone(),
        fp,
        jti,
        purpose: "oscar-launch".into(),
        exp: now + 120, // 2 minutes
        container_key,
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

    let guest_sid = uuid::Uuid::new_v4().to_string();
    let container_key = guest_sid.clone();

    tracing::info!("oscar_share_launch: Launching ephemeral guest session for owner {}. LinkToken={}, Sid={}", owner_uuid, share_token, guest_sid);

    // Guests ALWAYS use ephemeral containers to ensure they never "squat" on the owner's primary container slot.
    if let Err(e) = ensure_oscar_container(&state, &owner_uuid, &owner_username, &container_key, true).await {
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
    let now = chrono::Utc::now().timestamp();

    {
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.insert(guest_sid.clone(), crate::config::SessionInfo {
            uuid: owner_uuid.clone(),
            expires_at: now + 60 * 60,
            is_guest: true,
        });
    }

    let launch_claims = LaunchTokenClaims {
        sub: owner_uuid,
        sid: guest_sid,
        fp,
        jti,
        purpose: "oscar-launch".into(),
        exp: now + 120, // 2 minutes
        container_key,
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

    let is_guest = {
        let mut sessions = state.active_auth_sessions.write().await;
        sessions.retain(|_, s| s.expires_at > now);
        if let Some(s) = sessions.get(&claims.sid) {
            s.is_guest
        } else {
            tracing::debug!("oscar_login_handler: auth session {} not found", claims.sid);
            return Redirect::to("/").into_response();
        }
    };

    let oscar_claims = OscarClaims {
        uuid: claims.sub,
        sid: claims.sid.clone(),
        fp: claims.fp,
        scope: "oscar".into(),
        exp: now + 60 * 60, // 1 hour
        is_guest,
        container_key: claims.container_key,
    };

    let session_token = encode(
        &Header::default(),
        &oscar_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes())
    ).unwrap();

    let cookie_value = format!("oscar_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax; Secure", session_token, 60*60);
    tracing::debug!("oscar_login_handler: setting cookie, redirecting to /oscar/, sid={}", claims.sid);

    let mut res = Redirect::to("/oscar/").into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value.parse().unwrap()
    );
    res
}

pub async fn oscar_keepalive_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let claims = match req.extensions().get::<OscarClaims>() {
        Some(c) => c.clone(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let query_params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        .into_owned()
        .collect();

    let container_key = query_params.get("key").cloned().unwrap_or_else(|| claims.container_key.clone());

    {
        let mut containers = state.active_containers.write().await;
        if let Some(info) = containers.get_mut(&container_key) {
            // Simple security check: owner must match claims
            if info.owner_uuid == claims.uuid {
                info.last_active = chrono::Utc::now().timestamp();
                tracing::debug!("oscar_keepalive: refreshed last_active for container {}", container_key);
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn serve_overlay_script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "private, max-age=300"),
        ],
        include_str!("oscar_overlay.js"),
    )
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let accepts_html = req.headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);

    // Capture the original path before stripping /oscar prefix so we know
    // whether to inject the overlay script into the response HTML.
    let original_path = req.uri().path().to_string();
    let is_oscar_root = original_path == "/oscar" || original_path == "/oscar/";

    let mut path = req.uri().path().to_string();
    if path.starts_with("/oscar") {
        path = path.replacen("/oscar", "", 1);
        if path.is_empty() {
            path = "/".into();
        }
    }
    
    let qs = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    
    let (target_ip, container_key, is_guest) = {
        let claims = match req.extensions().get::<OscarClaims>() {
            Some(c) => c,
            None => return Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("Missing OSCAR session claims")).unwrap(),
        };

        let containers = state.active_containers.read().await;
        if let Some(info) = containers.get(&claims.container_key) {
            tracing::debug!("proxy_handler: Routing request for user {} to container {}", claims.uuid, info.container_id);
            (info.ip_address.clone(), claims.container_key.clone(), claims.is_guest)
        } else {
            tracing::warn!("proxy_handler: No active container found for key {}", claims.container_key);
            if accepts_html {
                return Redirect::to("/?timeout=1").into_response();
            }

            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Container session expired or stopped. Please return to the homepage and relaunch OSCAR."))
                .unwrap();
        }
    };

    {
        // Don't register activity for background polling or non-user requests
        let is_polling = path.ends_with("/audio") || path.ends_with("/websockify");
        if !is_polling {
            let mut containers = state.active_containers.write().await;
            if let Some(info) = containers.get_mut(&container_key) {
                info.last_active = chrono::Utc::now().timestamp();
            }
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
        return handle_websocket_upgrade(state, req, &target_url, container_key).await;
    }

    let client = &state.reqwest_client;
    let mut builder = client.request(req.method().clone(), &target_url);

    for (name, value) in req.headers() {
        if !hop_by_hop.contains(&name.as_str()) {
            // When buffering the oscar root page to inject the overlay script, we
            // must NOT forward Accept-Encoding. reqwest disables automatic
            // decompression when this header is manually set, which would cause
            // bytes() to return raw compressed data → garbled UTF-8 on the page.
            if is_oscar_root && name == header::ACCEPT_ENCODING {
                continue;
            }
            builder = builder.header(name.clone(), value.clone());
        }
    }

    let req_body = req.into_body();
    builder = builder.body(reqwest::Body::wrap_stream(req_body.into_data_stream()));

    match builder.send().await {
        Ok(proxy_res) => {
            let resp_status = proxy_res.status();

            // Check if we should inject the overlay script into this response.
            let is_html_response = proxy_res.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.contains("text/html"))
                .unwrap_or(false);

            if is_oscar_root && is_html_response && resp_status.is_success() {
                // Buffer full response so we can inject the overlay <script> tag.
                // Collect headers first (before consuming body).
                let headers_vec: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)> =
                    proxy_res.headers().iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                let bytes = proxy_res.bytes().await.unwrap_or_default();
                let original_html = String::from_utf8_lossy(&bytes);
                let mut modified_html = original_html.into_owned();
                
                // Inject session metadata into the body tag for the frontend scripts
                if let Some(pos) = modified_html.find("<body") {
                    if let Some(end_bracket) = modified_html[pos..].find('>') {
                        let mut injection = format!(" data-container-key=\"{}\"", container_key);
                        if is_guest {
                            injection.push_str(" data-guest-session=\"true\"");
                        }
                        modified_html.insert_str(pos + end_bracket, &injection);
                    }
                }

                let inject_tag = r#"<script src="/oscar-overlay.js"></script>"#;
                let final_html = if let Some(pos) = modified_html.rfind("</body>") {
                    modified_html.insert_str(pos, inject_tag);
                    modified_html
                } else {
                    modified_html + inject_tag
                };
                let modified_bytes = final_html.into_bytes();

                let mut response = Response::builder().status(resp_status);
                for (name, value) in headers_vec {
                    let name_str = name.as_str();
                    // Drop hop-by-hop + content-length (body size has changed)
                    if name_str == "transfer-encoding" || name_str == "content-length" {
                        continue;
                    }
                    if name_str == "content-security-policy" {
                        if let Ok(val) = value.to_str() {
                            let mut dirs: Vec<&str> = val.split(';').map(|s| s.trim())
                                .filter(|s| !s.is_empty() && !s.to_lowercase().starts_with("frame-ancestors"))
                                .collect();
                            dirs.push("frame-ancestors 'self'");
                            if let Ok(hv) = HeaderValue::try_from(dirs.join("; ")) {
                                response.headers_mut().unwrap().insert(
                                    header::CONTENT_SECURITY_POLICY, hv
                                );
                            }
                        }
                        continue;
                    }
                    if let (Ok(axum_name), Ok(axum_value)) = (
                        axum::http::HeaderName::from_bytes(name.as_str().as_bytes()),
                        HeaderValue::from_bytes(value.as_bytes()),
                    ) {
                        response.headers_mut().unwrap().insert(axum_name, axum_value);
                    }
                }
                response.body(Body::from(modified_bytes)).unwrap()
            } else {
                // Normal streaming passthrough.
                let mut response = Response::builder().status(resp_status);
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
        }
        Err(e) => {
            tracing::error!("Proxy request failed: {}", e);
            
            if accepts_html {
                Redirect::to("/?timeout=1").into_response()
            } else {
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Container session expired or stopped. Please return to the homepage and relaunch OSCAR."))
                    .unwrap()
            }
        }
    }
}

async fn handle_websocket_upgrade(
    _state: Arc<AppState>,
    req: Request,
    target_url: &str,
    container_key: String,
) -> Response {
    let ws_url = if target_url.starts_with("https://") {
        target_url.replacen("https://", "wss://", 1)
    } else {
        target_url.replacen("http://", "ws://", 1)
    };

    // Forward essential companion headers
    let mut forward_headers = Vec::new();
    let header_names = [
        header::USER_AGENT,
        header::ACCEPT_LANGUAGE,
        header::SEC_WEBSOCKET_PROTOCOL,
    ];

    for name in &header_names {
        if let Some(value) = req.headers().get(name) {
            forward_headers.push((name.clone(), value.clone()));
        }
    }

    // Capture protocols for axum side
    let protocols = req.headers().get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    use futures::{StreamExt, SinkExt};
    use axum::extract::FromRequestParts;
    let mut parts = req.into_parts().0;
    
    let mut upgrade = match axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("WebSocket upgrade extraction failed for key {}: {}", container_key, e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Mirror sub-protocols
    if let Some(ref p) = protocols {
        let p_list: Vec<String> = p.split(',').map(|s| s.trim().to_string()).collect();
        upgrade = upgrade.protocols(p_list);
    }

    upgrade.on_upgrade(move |client_ws: axum::extract::ws::WebSocket| async move {
        tracing::debug!("Started WebSocket tunnel for container key {}", container_key);

        let mut request = ws_url.into_client_request().unwrap();
        for (name, value) in forward_headers {
            request.headers_mut().insert(name, value);
        }

        match tokio_tungstenite::connect_async(request).await {
            Ok((server_ws, _)) => {
                let (mut client_tx, mut client_rx) = client_ws.split();
                let (mut server_tx, mut server_rx) = server_ws.split();

                // NOTE: User input (mouse, keyboard) travels via WebRTC DataChannel
                // peer-to-peer and is NEVER visible on this signaling WebSocket.
                // Activity tracking is handled by the browser-side keepalive in
                // oscar_overlay.js (POST /api/oscar-keepalive, Page Visibility aware).
                //
                // We use tokio::join! (not select!) so both halves run to completion.
                // When either side drops the connection, that half sends an explicit
                // WebSocket Close frame to the other side. This lets Selkies reset its
                // signaling/ICE state cleanly instead of seeing a raw TCP teardown.

                // client → server
                let c2s = tokio::spawn(async move {
                    use axum::extract::ws::Message as AxumMsg;
                    use tokio_tungstenite::tungstenite::Message as TungMsg;
                    loop {
                        match client_rx.next().await {
                            Some(Ok(msg)) => {
                                let is_close = matches!(msg, AxumMsg::Close(_));
                                let tung_msg = match msg {
                                    AxumMsg::Text(t)   => TungMsg::Text(t),
                                    AxumMsg::Binary(b) => TungMsg::Binary(b),
                                    AxumMsg::Ping(p)   => TungMsg::Ping(p),
                                    AxumMsg::Pong(p)   => TungMsg::Pong(p),
                                    AxumMsg::Close(_)  => TungMsg::Close(None),
                                };
                                if let Err(e) = server_tx.send(tung_msg).await {
                                    tracing::debug!("Proxy c2s: server send error: {}", e);
                                    break;
                                }
                                if is_close { break; }
                            }
                            Some(Err(e)) => {
                                tracing::debug!("Proxy c2s: client recv error: {}", e);
                                break;
                            }
                            None => break,
                        }
                    }
                    // Propagate Close to server so Selkies can reset signaling cleanly.
                    let _ = server_tx.send(TungMsg::Close(None)).await;
                    tracing::debug!("Proxy c2s: loop done, Close sent to server");
                });

                // server → client
                let s2c = tokio::spawn(async move {
                    use axum::extract::ws::Message as AxumMsg;
                    use tokio_tungstenite::tungstenite::Message as TungMsg;
                    loop {
                        match server_rx.next().await {
                            Some(Ok(msg)) => {
                                let is_close = matches!(msg, TungMsg::Close(_));
                                let ax_msg = match msg {
                                    TungMsg::Text(t)   => AxumMsg::Text(t),
                                    TungMsg::Binary(b) => AxumMsg::Binary(b),
                                    TungMsg::Ping(p)   => AxumMsg::Ping(p),
                                    TungMsg::Pong(p)   => AxumMsg::Pong(p),
                                    TungMsg::Close(_)  => AxumMsg::Close(None),
                                    TungMsg::Frame(_)  => continue,
                                };
                                if let Err(e) = client_tx.send(ax_msg).await {
                                    tracing::debug!("Proxy s2c: client send error: {}", e);
                                    break;
                                }
                                if is_close { break; }
                            }
                            Some(Err(e)) => {
                                tracing::debug!("Proxy s2c: server recv error: {}", e);
                                break;
                            }
                            None => break,
                        }
                    }
                    // Propagate Close to client so the browser knows the session ended.
                    let _ = client_tx.send(AxumMsg::Close(None)).await;
                    tracing::debug!("Proxy s2c: loop done, Close sent to client");
                });

                // Wait for both halves — neither is discarded prematurely.
                let _ = tokio::join!(c2s, s2c);
            }
            Err(e) => {
                tracing::error!("Failed to connect to backend WS: {}", e);
            }
        }
    })
}

/// Called by the frontend (via navigator.sendBeacon) when the user intentionally
/// navigates away from the OSCAR view. We evict the container from the active map
/// and initiate a graceful stop so the next launch always gets a clean Selkies process.
pub async fn oscar_disconnect_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let claims = match req.extensions().get::<OscarClaims>() {
        Some(c) => c.clone(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let user_uuid = claims.uuid.clone();

    // Prioritize key from query parameter (explicitly sent by frontend)
    // to avoid "Beacon Suicide" where a new session's cookie kills an old session's unload.
    let query_params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        .into_owned()
        .collect();

    let container_key = query_params.get("key").cloned().unwrap_or_else(|| claims.container_key.clone());

    // Remove from active map immediately so the next oscar_launch triggers a clean
    // container provision via ensure_oscar_container (which force-removes first).
    let maybe_container = {
        let mut containers = state.active_containers.write().await;
        
        // Security check: If we're using a key from the query string, 
        // verify it belongs to the authenticated user.
        if let Some(info) = containers.get(&container_key) {
            if info.owner_uuid != user_uuid {
                tracing::warn!("oscar_disconnect: user {} tried to disconnect unauthorized key {}", user_uuid, container_key);
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        
        containers.remove(&container_key)
    };

    if let Some(info) = maybe_container {
        let state_clone = state.clone();
        let container_id = info.container_id.clone();
        let user_uuid = user_uuid.clone();
        tokio::spawn(async move {
            cleanup_oscar_session(state_clone, user_uuid, container_id).await;
        });
    } else {
        tracing::debug!("oscar_disconnect: no active container for user {}, nothing to evict", user_uuid);
    }

    StatusCode::NO_CONTENT.into_response()
}

pub async fn cleanup_oscar_session(state: Arc<AppState>, uuid: String, container_id: String) {
    let docker = &state.docker;
    tracing::info!("Evicting OSCAR container {} and cleaning up resources for user {}.", container_id, uuid);

    // Stop and remove the container, ensuring anonymous volumes are removed (v: true)
    // We give it 30 seconds to finish saving profile data.
    let _ = docker.stop_container(&container_id, Some(StopContainerOptions { t: 30 })).await;
    let _ = docker.remove_container(
        &container_id,
        Some(RemoveContainerOptions {
            force: true,
            v: true, // IMPORTANT: removes anonymous volumes attached to container
            ..Default::default()
        }),
    ).await;
    
    // Check if this was an ephemeral profile, using string matching format "oscar-ephemeral-{key}"
    if let Some(key) = container_id.strip_prefix("oscar-ephemeral-") {
        tracing::info!("Cleaning up sparse ephemeral profile: ephemeral_{}", key);
        let p_dir = std::path::PathBuf::from("./data/profiles").join(format!("ephemeral_{}", key));
        let c_dir = std::path::PathBuf::from("./data/app_config").join(format!("ephemeral_{}", key));
        let _ = tokio::fs::remove_dir_all(&p_dir).await;
        let _ = tokio::fs::remove_dir_all(&c_dir).await;
    }

    // Purge the dangling lockfile from user profile directory
    // We get the username from the DB, then sanitize it to match directory names
    if let Ok(Some(user)) = state.db.get_user_by_uuid(&uuid) {
        let username = crate::utils::sanitize_folder_name(user.username.as_deref().unwrap_or("")).unwrap_or(uuid.clone());
        let profiles_dir = std::path::PathBuf::from("./data/profiles").join(&username).join("Profiles");
        
        if let Ok(mut entries) = tokio::fs::read_dir(&profiles_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                    let lockfile_path = entry.path().join("lockfile");
                    if lockfile_path.exists() {
                        tracing::info!("Purging lockfile at {:?}", lockfile_path);
                        let _ = tokio::fs::remove_file(lockfile_path).await;
                    }
                }
            }
        }
    }
}
