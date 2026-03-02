use anyhow::{Context, Result};
use std::env;
use tokio::sync::RwLock;
use std::collections::HashMap;
use reqwest::Client;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rand::rngs::OsRng;
use crate::db::Database;
use bollard::Docker;
use dashmap::DashMap;

pub const UPLOAD_ROOT: &str = "./data/uploads";
pub const PROFILE_ROOT: &str = "./data/profiles";

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
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_redirect_uri: String,
    pub super_admin_id: String,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let jwt_secret = env::var("JWT_SECRET").context("JWT_SECRET must be set")?;
        let app_username = env::var("APP_USERNAME").unwrap_or_else(|_| "shared-user".to_string());
        let app_password = env::var("APP_PASSWORD").context("APP_PASSWORD must be set")?;
        // HTTP port for the internal Docker network listener (TLS is terminated by nginx)
        let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string()).parse()?;
        let oscar_base_url = url::Url::parse(&env::var("OSCAR_BASE_URL").unwrap_or_else(|_| "http://oscar:3000".to_string()))?;
        let auth_session_ttl_seconds = env::var("AUTH_SESSION_TTL_SECONDS").unwrap_or_else(|_| "900".to_string()).parse()?;
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
            discord_client_id: env::var("DISCORD_CLIENT_ID").unwrap_or_default(),
            discord_client_secret: env::var("DISCORD_CLIENT_SECRET").unwrap_or_default(),
            discord_redirect_uri: env::var("DISCORD_REDIRECT_URI").unwrap_or_default(),
            super_admin_id: env::var("SUPER_ADMIN_ID").unwrap_or_default(),
        })
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub db: Database,
    pub active_auth_sessions: RwLock<HashMap<String, SessionInfo>>,
    pub consumed_launch_tokens: RwLock<HashMap<String, i64>>,
    pub pending_upload_sessions: RwLock<HashMap<String, UploadSession>>,
    pub reqwest_client: Client,
    pub docker: Docker,
    pub active_containers: RwLock<HashMap<String, ContainerInfo>>,
    pub auth_attempts: DashMap<String, (u32, i64)>, // IP -> (count, first_attempt_timestamp)
}

#[derive(Clone, Debug)]
pub struct ContainerInfo {
    pub container_id: String,
    pub ip_address: String,
    pub last_active: i64,
}

#[derive(Clone)]
pub struct SessionInfo {
    pub uuid: String,
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

        let db_path = env::var("DATABASE_PATH").unwrap_or_else(|_| "./data/db.sqlite".to_string());
        // Ensure data dir exists
        if let Some(parent) = std::path::Path::new(&db_path).parent() {
            std::fs::create_dir_all(parent).unwrap_or_default();
        }
        let db = Database::new(&db_path, &config.app_username, &config.app_password)?;

        Ok(Self {
            config,
            db,
            active_auth_sessions: RwLock::new(HashMap::new()),
            consumed_launch_tokens: RwLock::new(HashMap::new()),
            pending_upload_sessions: RwLock::new(HashMap::new()),
            reqwest_client,
            docker: if let Ok(host) = env::var("DOCKER_HOST") {
                Docker::connect_with_http(&host, 10, bollard::API_DEFAULT_VERSION).unwrap_or_else(|_| Docker::connect_with_local_defaults().unwrap())
            } else {
                Docker::connect_with_local_defaults().unwrap_or_else(|_| Docker::connect_with_unix_defaults().unwrap())
            },
            active_containers: RwLock::new(HashMap::new()),
            auth_attempts: DashMap::new(),
        })
    }
}
