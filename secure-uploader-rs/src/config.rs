use anyhow::{Context, Result};
use std::env;
use tokio::sync::RwLock;
use std::collections::HashMap;
use reqwest::Client;
use std::sync::Arc;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub app_username: String,
    pub app_password: String,
    pub http_port: u16,
    pub oscar_base_url: url::Url,
    pub auth_session_ttl_seconds: u64,
    pub upload_uid: u32,
    pub upload_gid: u32,
    pub app_encryption_private_key: RsaPrivateKey,
    pub max_upload_batch_bytes: usize,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let jwt_secret = env::var("JWT_SECRET").context("JWT_SECRET must be set")?;
        let app_username = env::var("APP_USERNAME").unwrap_or_else(|_| "shared-user".to_string());
        let app_password = env::var("APP_PASSWORD").context("APP_PASSWORD must be set")?;
        // HTTP port for the internal Docker network listener (TLS is terminated by nginx)
        let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string()).parse()?;
        let oscar_base_url = url::Url::parse(&env::var("OSCAR_BASE_URL").unwrap_or_else(|_| "http://oscar:3000".to_string()))?;
        let auth_session_ttl_seconds = env::var("AUTH_SESSION_TTL_SECONDS").unwrap_or_else(|_| "1800".to_string()).parse()?;
        let upload_uid = env::var("UPLOAD_UID").unwrap_or_else(|_| "911".to_string()).parse()?;
        let upload_gid = env::var("UPLOAD_GID").unwrap_or_else(|_| "911".to_string()).parse()?;

        let max_upload_batch_bytes: usize = env::var("MAX_UPLOAD_BATCH_BYTES")
            .unwrap_or_else(|_| "1073741824".to_string())
            .parse()
            .context("Invalid MAX_UPLOAD_BATCH_BYTES")?;

        let app_encryption_private_key = if let Ok(pem) = env::var("APP_ENCRYPTION_PRIVATE_KEY") {
            if pem.is_empty() {
                RsaPrivateKey::new(&mut OsRng, 2048)?
            } else {
                RsaPrivateKey::from_pkcs8_pem(&pem).context("Invalid APP_ENCRYPTION_PRIVATE_KEY")?
            }
        } else {
            RsaPrivateKey::new(&mut OsRng, 2048)?
        };

        Ok(Self {
            jwt_secret,
            app_username,
            app_password,
            http_port,
            oscar_base_url,
            auth_session_ttl_seconds,
            upload_uid,
            upload_gid,
            app_encryption_private_key,
            max_upload_batch_bytes,
        })
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub active_auth_sessions: RwLock<HashMap<String, SessionInfo>>,
    pub consumed_launch_tokens: RwLock<HashMap<String, i64>>,
    pub pending_upload_sessions: RwLock<HashMap<String, UploadSession>>,
    pub reqwest_client: Client,
}

#[derive(Clone)]
pub struct SessionInfo {
    pub sub: String,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct UploadSession {
    pub folder: String,
    pub selected_date: i64,
    pub total_batches: usize,
    pub upload_type: String,
    pub next_batch_index: usize,
    pub seen_required: std::collections::HashSet<String>,
    pub seen_paths: std::collections::HashSet<String>,
    pub seen_wellue_db_parents: std::collections::HashSet<String>,
    pub expires_at: i64,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        let reqwest_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            config,
            active_auth_sessions: RwLock::new(HashMap::new()),
            consumed_launch_tokens: RwLock::new(HashMap::new()),
            pending_upload_sessions: RwLock::new(HashMap::new()),
            reqwest_client,
        })
    }
}
