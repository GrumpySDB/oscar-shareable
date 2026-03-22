use anyhow::{Context, Result};
use std::env;
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
    pub oscar_idle_timeout_seconds: i64,
    pub upload_uid: u32,
    pub upload_gid: u32,
    pub app_encryption_private_key: RsaPrivateKey,
    pub max_upload_batch_bytes: usize,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_redirect_uri: String,
    pub super_admin_id: String,
    pub oscar_version: String,
    pub oscar_docker_image: String,
    pub app_config_root: String,
    pub selkies_audio_enabled: bool,
    pub selkies_gamepad_enabled: bool,
    pub selkies_ui_sidebar_show_gamepads: bool,
    pub selkies_ui_sidebar_show_audio_settings: bool,
    pub selkies_ui_sidebar_show_clipboard: bool,
    pub selkies_ui_sidebar_show_sharing: bool,
    pub puid: String,
    pub pgid: String,
    pub tz: String,
    pub max_res: String,
    pub title: String,
    pub start_docker: bool,
    pub disable_ipv6: bool,
    pub no_decor: bool,
    pub no_gamepad: bool,
    pub harden_desktop: bool,
    pub harden_openbox: bool,
    pub selkies_enable_cursors: bool,
    pub selkies_microphone_enabled: bool,
    pub selkies_clipboard_in_enabled: bool,
    pub selkies_clipboard_out_enabled: bool,
    pub selkies_second_screen: bool,
    pub selkies_enable_sharing: bool,
    pub selkies_ui_show_core_buttons: bool,
    pub selkies_use_browser_cursors: bool,
    pub max_resolution: String,
}

impl AppConfig {
    fn get_env_or_file(key: &str) -> Option<String> {
        if let Ok(file_path) = env::var(format!("{}_FILE", key)) {
            if let Ok(content) = std::fs::read_to_string(&file_path) {
                return Some(content.trim().to_string());
            }
        }
        env::var(key).ok()
    }

    pub fn load() -> Result<Self> {
        let jwt_secret = Self::get_env_or_file("JWT_SECRET").context("JWT_SECRET must be set")?;
        let app_username = Self::get_env_or_file("APP_USERNAME").unwrap_or_else(|| "shared-user".to_string());
        let app_password = Self::get_env_or_file("APP_PASSWORD").context("APP_PASSWORD must be set")?;
        // HTTP port for the internal Docker network listener (TLS is terminated by nginx)
        let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string()).parse()?;
        let oscar_base_url = url::Url::parse(&env::var("OSCAR_BASE_URL").unwrap_or_else(|_| "http://oscar:3000".to_string()))?;
        let auth_session_ttl_seconds = env::var("AUTH_SESSION_TTL_SECONDS").unwrap_or_else(|_| "3600".to_string()).parse()?;
        let oscar_idle_timeout_seconds = env::var("OSCAR_IDLE_TIMEOUT_SECONDS").unwrap_or_else(|_| "300".to_string()).parse()?;
        let upload_uid = env::var("UPLOAD_UID").unwrap_or_else(|_| "911".to_string()).parse()?;
        let upload_gid = env::var("UPLOAD_GID").unwrap_or_else(|_| "911".to_string()).parse()?;

        let max_upload_batch_bytes: usize = env::var("MAX_UPLOAD_BATCH_BYTES")
            .unwrap_or_else(|_| "1073741824".to_string())
            .parse()
            .context("Invalid MAX_UPLOAD_BATCH_BYTES")?;

        let app_encryption_private_key = if let Some(pem) = Self::get_env_or_file("APP_ENCRYPTION_PRIVATE_KEY") {
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
            oscar_idle_timeout_seconds,
            upload_uid,
            upload_gid,
            app_encryption_private_key,
            max_upload_batch_bytes,
            discord_client_id: Self::get_env_or_file("DISCORD_CLIENT_ID").unwrap_or_default(),
            discord_client_secret: Self::get_env_or_file("DISCORD_CLIENT_SECRET").unwrap_or_default(),
            discord_redirect_uri: Self::get_env_or_file("DISCORD_REDIRECT_URI").unwrap_or_default(),
            super_admin_id: Self::get_env_or_file("SUPER_ADMIN_ID").unwrap_or_default(),
            oscar_version: env::var("OSCAR_PROFILE_VERSION").unwrap_or_else(|_| "1.7.1+-plus".to_string()),
            oscar_docker_image: env::var("OSCAR_DOCKER_IMAGE").unwrap_or_else(|_| "ghcr.io/grumpysdb/oscar-shareable-oscar:latest".to_string()),
            app_config_root: env::var("APP_CONFIG_ROOT").unwrap_or_else(|_| "./data/app_config".to_string()),
            selkies_audio_enabled: env::var("SELKIES_AUDIO_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_gamepad_enabled: env::var("SELKIES_GAMEPAD_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_ui_sidebar_show_gamepads: env::var("SELKIES_UI_SIDEBAR_SHOW_GAMEPADS").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_ui_sidebar_show_audio_settings: env::var("SELKIES_UI_SIDEBAR_SHOW_AUDIO_SETTINGS").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_ui_sidebar_show_clipboard: env::var("SELKIES_UI_SIDEBAR_SHOW_CLIPBOARD").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_ui_sidebar_show_sharing: env::var("SELKIES_UI_SIDEBAR_SHOW_SHARING").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            puid: env::var("PUID").unwrap_or_else(|_| "911".to_string()),
            pgid: env::var("PGID").unwrap_or_else(|_| "911".to_string()),
            tz: env::var("TZ").unwrap_or_else(|_| "America/Chicago".to_string()),
            max_res: env::var("MAX_RES").unwrap_or_else(|_| "2560x1440".to_string()),
            title: env::var("TITLE").unwrap_or_else(|_| "OSCAR (Web)".to_string()),
            start_docker: env::var("START_DOCKER").map(|v| v.to_lowercase() == "true").unwrap_or(false),
            disable_ipv6: env::var("DISABLE_IPV6").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            no_decor: env::var("NO_DECOR").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            no_gamepad: env::var("NO_GAMEPAD").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            harden_desktop: env::var("HARDEN_DESKTOP").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            harden_openbox: env::var("HARDEN_OPENBOX").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_enable_cursors: env::var("SELKIES_ENABLE_CURSORS").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_microphone_enabled: env::var("SELKIES_MICROPHONE_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(false),
            selkies_clipboard_in_enabled: env::var("SELKIES_CLIPBOARD_IN_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(false),
            selkies_clipboard_out_enabled: env::var("SELKIES_CLIPBOARD_OUT_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_second_screen: env::var("SELKIES_SECOND_SCREEN").map(|v| v.to_lowercase() == "true").unwrap_or(false),
            selkies_enable_sharing: env::var("SELKIES_ENABLE_SHARING").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            selkies_ui_show_core_buttons: env::var("SELKIES_UI_SHOW_CORE_BUTTONS").map(|v| v.to_lowercase() == "true").unwrap_or(false),
            selkies_use_browser_cursors: env::var("SELKIES_USE_BROWSER_CURSORS").map(|v| v.to_lowercase() == "true").unwrap_or(true),
            max_resolution: env::var("MAX_RESOLUTION").unwrap_or_else(|_| "2560x1440".to_string()),
        })
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub db: Database,
    pub active_auth_sessions: DashMap<String, SessionInfo>,
    pub consumed_launch_tokens: DashMap<String, i64>,
    pub internal_client: Client,
    pub external_client: Client,
    pub docker: Docker,
    pub active_containers: DashMap<String, ContainerInfo>,
    pub auth_attempts: DashMap<String, (u32, i64)>, // IP -> (count, first_attempt_timestamp)
}

#[derive(Clone, Debug)]
pub struct ContainerInfo {
    pub container_id: String,
    pub ip_address: String,
    pub last_active: i64,
    pub owner_uuid: String,
}

#[derive(Clone)]
pub struct SessionInfo {
    pub uuid: String,
    pub expires_at: i64,
    pub is_guest: bool,
}

// UploadSession removed as dead code.

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        let internal_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let external_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
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
            active_auth_sessions: DashMap::new(),
            consumed_launch_tokens: DashMap::new(),
            internal_client,
            external_client,
            docker: if let Ok(host) = env::var("DOCKER_HOST") {
                Docker::connect_with_http(&host, 10, bollard::API_DEFAULT_VERSION).unwrap_or_else(|_| Docker::connect_with_local_defaults().unwrap())
            } else {
                Docker::connect_with_local_defaults().unwrap_or_else(|_| Docker::connect_with_unix_defaults().unwrap())
            },
            active_containers: DashMap::new(),
            auth_attempts: DashMap::new(),
        })
    }
}
