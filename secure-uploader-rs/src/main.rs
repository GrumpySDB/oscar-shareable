pub mod auth;
pub mod config;
pub mod proxy;
pub mod upload;
pub mod utils;
pub mod db;
pub mod templates;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post, any},
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::{
    limit::RequestBodyLimitLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use bollard::container::{StopContainerOptions, RemoveContainerOptions, ListContainersOptions, InspectContainerOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,secure_uploader=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = config::AppConfig::load()?;
    let shared_state = Arc::new(config::AppState::new(cfg.clone()).await?);

    // Orphan cleanup and volume pruning
    {
        let docker_clone = shared_state.docker.clone();
        let config_clone = cfg.clone();
        tokio::spawn(async move {
            tracing::info!("Scanning for orphaned OSCAR containers...");
            let mut filters = std::collections::HashMap::new();
            // Match both primary and ephemeral containers
            filters.insert("name".to_string(), vec!["oscar-session-".to_string(), "oscar-ephemeral-".to_string()]);
            
            let options = ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            };
            
            if let Ok(containers) = docker_clone.list_containers(Some(options)).await {
                for c in containers {
                    if let Some(names) = c.names {
                        if names.iter().any(|n| n.starts_with("/oscar-session-") || n.starts_with("/oscar-ephemeral-")) {
                            if let Some(id) = c.id {
                                tracing::info!("Removing orphaned container {}", id);
                                let _ = docker_clone.stop_container(&id, None::<StopContainerOptions>).await;
                                let _ = docker_clone.remove_container(&id, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await;
                            }
                        }
                    }
                }
            }
            
            tracing::info!("Pruning dangling Docker volumes...");
            let _ = docker_clone.prune_volumes(None::<bollard::volume::PruneVolumesOptions<String>>).await;

            // Also cleanup orphaned ephemeral directories on disk
            tracing::info!("Scanning for orphaned ephemeral directories...");
            let profile_root = PathBuf::from(crate::config::PROFILE_ROOT);
            let app_config_root = PathBuf::from(&config_clone.app_config_root);

            let mut ephemeral_keys = std::collections::HashSet::new();
            if let Ok(mut entries) = tokio::fs::read_dir(&profile_root).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Some(key) = name.strip_prefix("ephemeral_") {
                            ephemeral_keys.insert(key.to_string());
                        }
                    }
                }
            }

            for key in ephemeral_keys {
                let container_name = format!("oscar-ephemeral-{}", key);
                // If container doesn't exist, purge the directories
                if docker_clone.inspect_container(&container_name, None::<InspectContainerOptions>).await.is_err() {
                    tracing::info!("Purging orphaned ephemeral data for key {}", key);
                    let p_dir = profile_root.join(format!("ephemeral_{}", key));
                    let c_dir = app_config_root.join(format!("ephemeral_{}", key));
                    let _ = tokio::fs::remove_dir_all(p_dir).await;
                    let _ = tokio::fs::remove_dir_all(c_dir).await;
                }
            }
        });
    }

    let cleaner_state = shared_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = chrono::Utc::now().timestamp();
            let mut to_remove = Vec::new();

            for entry in cleaner_state.active_containers.iter() {
                let (container_key, info) = entry.pair();
                let timeout = cleaner_state.config.oscar_idle_timeout_seconds;
                if now - info.last_active > timeout {
                    to_remove.push((container_key.clone(), info.owner_uuid.clone(), info.container_id.clone()));
                }
            }

            for (container_key, owner_uuid, container_id) in to_remove {
                if cleaner_state.active_containers.remove(&container_key).is_some() {
                    let state_clone = cleaner_state.clone();
                    tokio::spawn(async move {
                        crate::proxy::cleanup_oscar_session(state_clone, owner_uuid, container_id).await;
                    });
                }
            }

            // Daily audit log purge (entries > 90 days)
            let _ = cleaner_state.db.purge_old_audit_logs(90);
        }
    });

    tracing::info!("Starting secure-uploader Rust version...");

    let public_dir = PathBuf::from("./public");
    // serve_dir will be used as a fallback for the root to serve index.html, 
    // but we'll handle assets and specific pages separately to ensure disk-freshness.
    let serve_dir = ServeDir::new(&public_dir)
        .fallback(ServeFile::new("./public/index.html"));

    let admin_api_routes = Router::new()
        .route("/users", get(auth::list_users_handler))
        .route("/users/:uuid", delete(auth::delete_user_handler))
        .route("/users/:uuid/reset-password", post(auth::reset_password_handler))
        .route("/invites", get(auth::list_invites_handler))
        .route("/invites", post(auth::generate_invite_handler))
        .route("/invites/:code", delete(auth::revoke_invite_handler))
        .route("/audit-logs", get(auth::list_audit_logs_handler))
        .layer(middleware::from_fn(auth::admin_middleware))
        .layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_middleware));

    let api_routes = Router::new()
        .route("/auth/discord/login", get(auth::discord_login))
        .route("/auth/discord/callback", get(auth::discord_callback))
        .route("/auth/local/signup", post(auth::local_signup).layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_rate_limit_middleware)))
        .route("/auth/local/login", post(auth::local_login).layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_rate_limit_middleware)))
        .route("/auth/local/recover", post(auth::local_recovery_handler).layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_rate_limit_middleware)))
        .route("/auth/invite/validate", get(auth::validate_invite_handler))
        .route("/banner-images", get(upload::list_banner_images))
        .nest("/admin", admin_api_routes)
        .merge(
            Router::new()
                .route("/logout", post(auth::logout))
                .route("/session", get(auth::session_check))
                .route("/encryption-public-key", get(auth::get_public_key))
                .route("/oscar-launch", post(proxy::oscar_launch))
                .route("/files", get(upload::list_files))
                .route("/upload", post(upload::handle_upload))
                .route("/files", delete(upload::delete_folder))
                .route("/account", delete(auth::delete_self_handler))
                .route("/share-links", get(auth::list_share_links))
                .route("/share-links", post(auth::create_share_link))
                .route("/share-links/:token", delete(auth::delete_share_link))
                .route("/share/:share_token", get(proxy::oscar_share_launch))
                .layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_middleware))
        )
        .layer(DefaultBodyLimit::disable()) // Disable 2MB multipart limits explicitly for all API routes before nest
        .with_state(shared_state.clone());

    // /oscar/login is a separate route with its own launch-token auth (not session-cookie based).
    // It must NOT go through require_oscar_session_middleware because it creates the session.
    let oscar_login_route = Router::new()
        .route("/oscar/login", get(proxy::oscar_login_handler));

    // For proxy we need `any` to proxy all verbs, plus handle websocket upgrades.
    // These routes require an active Oscar session cookie.
    let proxy_routes = Router::new()
        .route("/oscar", any(proxy::proxy_handler))
        .route("/oscar/", any(proxy::proxy_handler))
        .route("/oscar/*path", any(proxy::proxy_handler))
        .route("/websockify", any(proxy::proxy_handler))
        // Overlay JS served from the Rust binary (injected into /oscar/ root HTML)
        .route("/oscar-overlay.js", get(proxy::serve_overlay_script))
        // Browser-side keepalive: updates last_active when the OSCAR tab is visible
        .route("/api/oscar-keepalive", post(proxy::oscar_keepalive_handler))
        // Browser-side disconnect signal: evicts container so next launch gets clean Selkies
        .route("/api/oscar-disconnect", post(proxy::oscar_disconnect_handler))
        // proxy needs special Oscar session checking middleware
        .layer(middleware::from_fn_with_state(shared_state.clone(), auth::require_oscar_session_middleware));

    let security_headers = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        // Standard CSP is applied globally but NOT inside /oscar/ proxy since it overrides it
        .layer(middleware::from_fn(add_security_headers));

    let admin_page_route = Router::new()
        .route_service("/admin", ServeFile::new("./public/admin.html"))
        .layer(middleware::from_fn(auth::admin_middleware))
        .layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_middleware));

    let invite_page_route = Router::new()
        .route_service("/invite", ServeFile::new("./public/invite.html"));

    let app = Router::new()
        .nest("/api", api_routes)
        .merge(oscar_login_route)
        .merge(proxy_routes)
        .merge(admin_page_route)
        .merge(invite_page_route)
        .route_service("/", ServeFile::new("./public/index.html"))
        .route_service("/privacy-security-policy", ServeFile::new("./public/privacy-security-policy.html"))
        .route_service("/how-to-uploader", ServeFile::new("./public/how-to-uploader.html"))
        .route_service("/faq", ServeFile::new("./public/faq.html"))
        .route_service("/licensing", ServeFile::new("./public/licensing.html"))
        .route_service("/recovery", ServeFile::new("./public/recovery.html"))
        .route_service("/recovery/", ServeFile::new("./public/recovery.html"))
        .route_service("/share/*path", ServeFile::new("./public/index.html"))
        .nest_service("/assets", ServeDir::new("./public/assets"))
        .nest_service("/images", ServeDir::new("./public/images"))
        .fallback_service(serve_dir)
        .layer(security_headers)
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024 * 5000)) // 50GB limit per request total. Individual chunks streamed.
        .with_state(shared_state);

    // Listen on plain HTTP — TLS is terminated by nginx at the container boundary.
    // The Docker internal network is isolated; no plain-text traffic crosses a trust boundary.
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.http_port));
    tracing::info!("Listening on http://{} (internal, behind nginx TLS)", addr);

    axum_server::bind(addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

async fn add_security_headers(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let is_oscar_route = path.starts_with("/oscar") || path.starts_with("/websockify");
    
    let mut response = next.run(req).await;
    
    if !is_oscar_route {
        let headers = response.headers_mut();
        headers.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            ),
        );
        headers.insert(
            axum::http::header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Authorization"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    
    response
}
