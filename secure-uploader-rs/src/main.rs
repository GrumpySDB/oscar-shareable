pub mod auth;
pub mod config;
pub mod proxy;
pub mod upload;
pub mod utils;
pub mod db;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::{Html, Response},
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,secure_uploader=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = config::AppConfig::load()?;
    let shared_state = Arc::new(config::AppState::new(cfg.clone()).await?);

    tracing::info!("Starting secure-uploader Rust version...");

    let public_dir = PathBuf::from("./public");
    let serve_dir = ServeDir::new(&public_dir).not_found_service(ServeFile::new(public_dir.join("index.html")));

    let api_routes = Router::new()
        .route("/auth/discord/callback", get(auth::discord_callback))
        .route("/auth/local/signup", post(auth::local_signup))
        .route("/auth/local/login", post(auth::local_login))
        .merge(
            Router::new()
                .route("/logout", post(auth::logout))
                .route("/session", get(auth::session_check))
                .route("/encryption-public-key", get(auth::get_public_key))
                .route("/oscar-launch", post(proxy::oscar_launch))
                .route("/files", get(upload::list_files))
                .route("/upload", post(upload::handle_upload))
                .route("/files", delete(upload::delete_folder))
                .layer(middleware::from_fn_with_state(shared_state.clone(), auth::auth_middleware))
        )
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

    let app = Router::new()
        .nest("/api", api_routes)
        .merge(oscar_login_route)
        .merge(proxy_routes)
        .route("/privacy-security-policy", get(|| async { Html(include_str!("../public/privacy-security-policy.html")) }))
        .route("/how-to-uploader", get(|| async { Html(include_str!("../public/how-to-uploader.html")) }))
        .route("/faq", get(|| async { Html(include_str!("../public/faq.html")) }))
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
        .serve(app.into_make_service())
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
                "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com 'unsafe-eval' 'unsafe-hashes' 'sha256-+OsIn6RhyCZCUkkvtHxFtP0kU3CGdGeLjDd9Fzqdl3o='; style-src 'self' 'unsafe-hashes' 'sha256-+OsIn6RhyCZCUkkvtHxFtP0kU3CGdGeLjDd9Fzqdl3o='; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            ),
        );
    }
    
    response
}
