use rusqlite::{params, Connection, Result};
use std::sync::Mutex;
use std::path::Path;

pub struct Database {
    pub conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub uuid: String,
    pub username: Option<String>,
    pub provider: String,     // 'discord' or 'local'
    pub identifier: String,   // Discord ID or Local Username
    pub role: String,         // 'user' or 'admin'
    pub created_at: i64,
    pub last_accessed_at: Option<i64>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P, app_username: &str, app_password: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        
        // Initialize schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                username TEXT,
                provider TEXT NOT NULL,
                identifier TEXT NOT NULL UNIQUE,
                argon2_password_hash TEXT,
                role TEXT NOT NULL DEFAULT 'user',
                created_at INTEGER NOT NULL,
                last_accessed_at INTEGER
            )",
            [],
        )?;
        let _ = conn.execute("ALTER TABLE users ADD COLUMN last_accessed_at INTEGER", []);
        let _ = conn.execute("ALTER TABLE users ADD COLUMN argon2_recovery_phrase_hash TEXT", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                created_by_uuid TEXT NOT NULL,
                used_by_uuid TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                label TEXT,
                FOREIGN KEY(created_by_uuid) REFERENCES users(uuid) ON DELETE CASCADE,
                FOREIGN KEY(used_by_uuid) REFERENCES users(uuid) ON DELETE CASCADE
            )",
            [],
        )?;
        let _ = conn.execute("ALTER TABLE invites ADD COLUMN label TEXT", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS share_links (
                token TEXT PRIMARY KEY,
                owner_uuid TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(owner_uuid) REFERENCES users(uuid) ON DELETE CASCADE
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL UNIQUE,
                user_uuid TEXT NOT NULL,
                label TEXT,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER,
                scopes TEXT,
                FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON DELETE CASCADE
            )",
            [],
        )?;
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_uuid)", []);

        // Performance Indexes
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_invites_used_by ON invites(used_by_uuid)", []);
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_share_links_owner ON share_links(owner_uuid)", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                action TEXT NOT NULL,
                user_uuid TEXT,
                username TEXT,
                details TEXT,
                ip_address TEXT
            )",
            [],
        )?;
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS file_hashes (
                hash TEXT NOT NULL,
                user_uuid TEXT NOT NULL,
                file_path TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                PRIMARY KEY (user_uuid, file_path),
                FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON DELETE CASCADE
            )",
            [],
        )?;
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_file_hashes_hash ON file_hashes(hash)", []);
        
        // --- Migration: Force sync_sessions to INTEGER PRIMARY KEY ---
        // This is necessary if the table was previously created with the TEXT ID schema.
        let _ = conn.execute("DROP TABLE IF EXISTS sync_sessions", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sync_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uuid TEXT NOT NULL,
                device_id TEXT,
                import_type TEXT,
                subfolder TEXT,
                created_at INTEGER NOT NULL,
                last_active_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                files_processed INTEGER DEFAULT 0,
                FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON DELETE CASCADE
            )",
            [],
        )?;
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_sessions_user ON sync_sessions(user_uuid)", []);
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_sessions_status ON sync_sessions(status)", []);

        let db = Database {
            conn: Mutex::new(conn),
        };

        db.ensure_super_admin(app_username, app_password)?;

        Ok(db)
    }

    fn ensure_super_admin(&self, app_username: &str, app_password: &str) -> Result<()> {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
        use rand::rngs::OsRng;

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(app_password.as_bytes(), &salt)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string()))))?
            .to_string();

        let admin = self.get_user_by_identifier("local", app_username)?;
        if let Some(user) = admin {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "UPDATE users SET role = 'admin', argon2_password_hash = ?1 WHERE uuid = ?2 AND provider = 'local'",
                params![password_hash, user.uuid],
            )?;
            tracing::info!("Updated existing local user '{}' to Super Admin", app_username);
        } else {
            let uuid = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().timestamp();
            
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO users (uuid, username, provider, identifier, argon2_password_hash, role, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![uuid, app_username, "local", app_username, password_hash, "admin", now],
            )?;
            tracing::info!("Created local Super Admin user '{}' from .env", app_username);
        }
        Ok(())
    }

    pub fn get_user_by_identifier(&self, provider: &str, identifier: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, role, created_at, last_accessed_at FROM users WHERE provider = ?1 AND identifier = ?2")?;
        
        let mut rows = stmt.query(params![provider, identifier])?;
        if let Some(row) = rows.next()? {
            Ok(Some(User {
                uuid: row.get(0)?,
                username: row.get(1)?,
                provider: row.get(2)?,
                identifier: row.get(3)?,
                role: row.get(4)?,
                created_at: row.get(5)?,
                last_accessed_at: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_user_by_uuid(&self, uuid: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, role, created_at, last_accessed_at FROM users WHERE uuid = ?1")?;
        
        let mut rows = stmt.query(params![uuid])?;
        if let Some(row) = rows.next()? {
            Ok(Some(User {
                uuid: row.get(0)?,
                username: row.get(1)?,
                provider: row.get(2)?,
                identifier: row.get(3)?,
                role: row.get(4)?,
                created_at: row.get(5)?,
                last_accessed_at: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn create_user(&self, user: User, password_hash: Option<String>, recovery_phrase_hash: Option<String>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO users (uuid, username, provider, identifier, argon2_password_hash, argon2_recovery_phrase_hash, role, created_at, last_accessed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                user.uuid,
                user.username,
                user.provider,
                user.identifier,
                password_hash,
                recovery_phrase_hash,
                user.role,
                now,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn create_user_with_invite(&self, user: User, password_hash: Option<String>, recovery_phrase_hash: Option<String>, invite_code: &str) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        
        let now = chrono::Utc::now().timestamp();
        tx.execute(
            "INSERT INTO users (uuid, username, provider, identifier, argon2_password_hash, argon2_recovery_phrase_hash, role, created_at, last_accessed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                user.uuid,
                user.username,
                user.provider,
                user.identifier,
                password_hash,
                recovery_phrase_hash,
                user.role,
                now,
                now,
            ],
        )?;

        let affected = tx.execute(
            "UPDATE invites SET used_by_uuid = ?1 WHERE code = ?2 AND used_by_uuid IS NULL",
            params![user.uuid, invite_code],
        )?;

        if affected == 0 {
             return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        
        tx.commit()?;
        Ok(())
    }

    pub fn verify_password(&self, provider: &str, identifier: &str, password: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, argon2_password_hash, role, created_at, last_accessed_at FROM users WHERE provider = ?1 AND identifier = ?2")?;
        
        let mut rows = stmt.query(params![provider, identifier])?;
        if let Some(row) = rows.next()? {
            let hash: Option<String> = row.get(4)?;
            if let Some(h) = hash {
                use argon2::{
                    password_hash::{PasswordHash, PasswordVerifier},
                    Argon2,
                };
                if PasswordHash::new(&h).and_then(|parsed_hash| {
                    Argon2::default().verify_password(password.as_bytes(), &parsed_hash)
                }).is_ok() {
                    return Ok(Some(User {
                        uuid: row.get(0)?,
                        username: row.get(1)?,
                        provider: row.get(2)?,
                        identifier: row.get(3)?,
                        role: row.get(5)?,
                        created_at: row.get(6)?,
                        last_accessed_at: row.get(7)?,
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn touch_user_access(&self, uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE users SET last_accessed_at = ?1 WHERE uuid = ?2",
            params![now, uuid],
        )?;
        Ok(())
    }

    pub fn verify_recovery_phrase(&self, provider: &str, identifier: &str, recovery_phrase: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, argon2_recovery_phrase_hash, role, created_at, last_accessed_at FROM users WHERE provider = ?1 AND identifier = ?2")?;
        
        let mut rows = stmt.query(params![provider, identifier])?;
        if let Some(row) = rows.next()? {
            let hash: Option<String> = row.get(4)?;
            if let Some(h) = hash {
                use argon2::{
                    password_hash::{PasswordHash, PasswordVerifier},
                    Argon2,
                };
                if PasswordHash::new(&h).and_then(|parsed_hash| {
                    Argon2::default().verify_password(recovery_phrase.as_bytes(), &parsed_hash)
                }).is_ok() {
                    return Ok(Some(User {
                        uuid: row.get(0)?,
                        username: row.get(1)?,
                        provider: row.get(2)?,
                        identifier: row.get(3)?,
                        role: row.get(5)?,
                        created_at: row.get(6)?,
                        last_accessed_at: row.get(7)?,
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn validate_invite(&self, code: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut stmt = conn.prepare("SELECT 1 FROM invites WHERE code = ?1 AND used_by_uuid IS NULL AND expires_at > ?2")?;
        let exists = stmt.exists(params![code, now])?;
        Ok(exists)
    }

    pub fn check_invite(&self, code: &str) -> Result<InviteStatus> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut stmt = conn.prepare("SELECT used_by_uuid, expires_at FROM invites WHERE code = ?1")?;
        
        let mut rows = stmt.query(params![code])?;
        if let Some(row) = rows.next()? {
            let used_by_uuid: Option<String> = row.get(0)?;
            let expires_at: i64 = row.get(1)?;
            
            if used_by_uuid.is_some() {
                Ok(InviteStatus::Used)
            } else if expires_at <= now {
                Ok(InviteStatus::Expired)
            } else {
                Ok(InviteStatus::Valid)
            }
        } else {
            Ok(InviteStatus::NotFound)
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteStatus {
    Valid,
    Expired,
    Used,
    NotFound,
}

impl Database {

    pub fn use_invite(&self, code: &str, user_uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE invites SET used_by_uuid = ?1 WHERE code = ?2 AND used_by_uuid IS NULL",
            params![user_uuid, code],
        )?;
        Ok(())
    }

    pub fn delete_user(&self, uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        // Clear related records first in case foreign_keys PRAGMA is on and ON DELETE CASCADE isn't in schema
        let _ = conn.execute("DELETE FROM invites WHERE used_by_uuid = ?1 OR created_by_uuid = ?1", params![uuid]);
        let _ = conn.execute("DELETE FROM share_links WHERE owner_uuid = ?1", params![uuid]);

        let affected = conn.execute("DELETE FROM users WHERE uuid = ?1", params![uuid])?;
        if affected == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    pub fn reset_user_password(&self, uuid: &str, new_password_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE users SET argon2_password_hash = ?1 WHERE uuid = ?2 AND provider = 'local'",
            params![new_password_hash, uuid],
        )?;
        if affected == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    pub fn reset_user_credentials(&self, uuid: &str, new_password_hash: &str, new_recovery_phrase_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE users SET argon2_password_hash = ?1, argon2_recovery_phrase_hash = ?2 WHERE uuid = ?3 AND provider = 'local'",
            params![new_password_hash, new_recovery_phrase_hash, uuid],
        )?;
        if affected == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }


    pub fn create_invite(&self, code: &str, created_by_uuid: &str, expires_at: i64, label: Option<String>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO invites (code, created_by_uuid, created_at, expires_at, label) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![code, created_by_uuid, now, expires_at, label],
        )?;
        Ok(())
    }

    pub fn revoke_invite(&self, code: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute("DELETE FROM invites WHERE code = ?1", params![code])?;
        if affected == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    pub fn get_all_invites(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT code, created_by_uuid, used_by_uuid, created_at, expires_at, label FROM invites ORDER BY created_at DESC")?;
        
        let it = stmt.query_map([], |row| {
            let used: Option<String> = row.get(2)?;
            let label: Option<String> = row.get(5).unwrap_or(None);
            Ok(serde_json::json!({
                "code": row.get::<_, String>(0)?,
                "created_by_uuid": row.get::<_, String>(1)?,
                "used_by_uuid": used,
                "created_at": row.get::<_, i64>(3)?,
                "expires_at": row.get::<_, i64>(4)?,
                "label": label,
            }))
        })?;
        
        let mut res = Vec::new();
        for val in it {
            res.push(val?);
        }
        Ok(res)
    }



    pub fn get_all_users(&self) -> Result<Vec<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, role, created_at, last_accessed_at FROM users ORDER BY created_at DESC")?;
        let user_iter = stmt.query_map([], |row| {
            Ok(User {
                uuid: row.get(0)?,
                username: row.get(1)?,
                provider: row.get(2)?,
                identifier: row.get(3)?,
                role: row.get(4)?,
                created_at: row.get(5)?,
                last_accessed_at: row.get(6)?,
            })
        })?;
        
        let mut users = Vec::new();
        for user in user_iter {
            users.push(user?);
        }
        Ok(users)
    }

    pub fn create_share_link(&self, token: &str, owner_uuid: &str, expires_at: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO share_links (token, owner_uuid, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, owner_uuid, now, expires_at],
        )?;
        Ok(())
    }

    pub fn get_share_link_owner(&self, token: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut stmt = conn.prepare("SELECT owner_uuid FROM share_links WHERE token = ?1 AND expires_at > ?2")?;
        let mut iter = stmt.query_map(params![token, now], |row| row.get(0))?;
        if let Some(res) = iter.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }

    pub fn get_active_share_links_for_user(&self, owner_uuid: &str) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut stmt = conn.prepare("SELECT token, created_at, expires_at FROM share_links WHERE owner_uuid = ?1 AND expires_at > ?2 ORDER BY created_at DESC")?;
        
        let it = stmt.query_map(params![owner_uuid, now], |row| {
            Ok(serde_json::json!({
                "token": row.get::<_, String>(0)?,
                "created_at": row.get::<_, i64>(1)?,
                "expires_at": row.get::<_, i64>(2)?,
            }))
        })?;
        
        let mut res = Vec::new();
        for val in it {
            res.push(val?);
        }
        Ok(res)
    }

    pub fn delete_share_link(&self, token: &str, owner_uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute("DELETE FROM share_links WHERE token = ?1 AND owner_uuid = ?2", params![token, owner_uuid])?;
        if affected == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    // --- API Keys ---
    pub fn create_api_key(&self, user_uuid: &str, key_hash: &str, label: Option<String>, scopes: Option<String>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO api_keys (key_hash, user_uuid, label, created_at, scopes) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key_hash, user_uuid, label, now, scopes],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_api_keys(&self, user_uuid: &str) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, label, created_at, last_used_at, scopes FROM api_keys WHERE user_uuid = ?1 ORDER BY created_at DESC")?;
        
        let it = stmt.query_map(params![user_uuid], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "label": row.get::<_, Option<String>>(1)?,
                "created_at": row.get::<_, i64>(2)?,
                "last_used_at": row.get::<_, Option<i64>>(3)?,
                "scopes": row.get::<_, Option<String>>(4)?,
            }))
        })?;
        
        let mut res = Vec::new();
        for val in it {
            res.push(val?);
        }
        Ok(res)
    }

    pub fn revoke_api_key(&self, id: i64, user_uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute("DELETE FROM api_keys WHERE id = ?1 AND user_uuid = ?2", params![id, user_uuid])?;
        if affected == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    pub fn get_api_key_hash(&self, id: i64) -> Result<Option<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT key_hash, user_uuid FROM api_keys WHERE id = ?1")?;
        let mut iter = stmt.query_map(params![id], |row| {
             Ok((row.get(0)?, row.get(1)?))
        })?;
        if let Some(res) = iter.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }

    pub fn get_api_key_label(&self, id: i64) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT label FROM api_keys WHERE id = ?1")?;
        let row = stmt.query_row(params![id], |r| r.get(0))?;
        Ok(row)
    }

    pub fn get_api_key_by_hash(&self, hash: &str) -> Result<Option<(i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, user_uuid FROM api_keys WHERE key_hash = ?1")?;
        let mut iter = stmt.query_map(params![hash], |row| {
             Ok((row.get(0)?, row.get(1)?))
        })?;
        if let Some(res) = iter.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }
    
    pub fn touch_api_key(&self, id: i64) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2", params![now, id])?;
        Ok(())
    }

    pub fn revoke_stale_api_keys(&self, days: i64) -> Result<usize> {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - (days * 24 * 60 * 60);
        let conn = self.conn.lock().unwrap();
        // Delete keys where last_used_at (if it exists) or created_at is older than cutoff
        let affected = conn.execute(
            "DELETE FROM api_keys WHERE COALESCE(last_used_at, created_at) < ?1",
            params![cutoff],
        )?;
        if affected > 0 {
            tracing::info!("Revoked {} stale API keys older than {} days", affected, days);
        }
        Ok(affected)
    }

    // --- Audit Logging ---

    pub fn log_audit_event(&self, action: &str, user_uuid: Option<&str>, username: Option<&str>, details: Option<&str>, ip: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO audit_logs (timestamp, action, user_uuid, username, details, ip_address) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![now, action, user_uuid, username, details, ip],
        )?;
        Ok(())
    }

    pub fn get_audit_logs(&self, limit: i64, offset: i64) -> Result<(Vec<serde_json::Value>, i64)> {
        let conn = self.conn.lock().unwrap();
        
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM audit_logs", [], |r| r.get(0))?;
        
        let mut stmt = conn.prepare("SELECT id, timestamp, action, user_uuid, username, details, ip_address FROM audit_logs ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2")?;
        let log_iter = stmt.query_map(params![limit, offset], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "timestamp": row.get::<_, i64>(1)?,
                "action": row.get::<_, String>(2)?,
                "user_uuid": row.get::<_, Option<String>>(3)?,
                "username": row.get::<_, Option<String>>(4)?,
                "details": row.get::<_, Option<String>>(5)?,
                "ip_address": row.get::<_, Option<String>>(6)?,
            }))
        })?;

        let mut logs = Vec::new();
        for log in log_iter {
            logs.push(log?);
        }
        
        Ok((logs, total))
    }

    pub fn purge_old_audit_logs(&self, days: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let cutoff = chrono::Utc::now().timestamp() - (days * 24 * 60 * 60);
        let affected = conn.execute("DELETE FROM audit_logs WHERE timestamp < ?1", params![cutoff])?;
        if affected > 0 {
            tracing::info!("Purged {} audit log entries older than {} days", affected, days);
        }
        Ok(affected)
    }

    pub fn record_file_hash(&self, hash: &str, user_uuid: &str, file_path: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO file_hashes (hash, user_uuid, file_path, timestamp)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(user_uuid, file_path) DO UPDATE SET
                hash = excluded.hash,
                timestamp = excluded.timestamp",
            params![hash, user_uuid, file_path, now],
        )?;
        Ok(())
    }

    pub fn get_file_hash(&self, user_uuid: &str, file_path: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash FROM file_hashes WHERE user_uuid = ?1 AND file_path = ?2")?;
        let mut rows = stmt.query(params![user_uuid, file_path])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    // --- Sync Sessions ---

    pub fn create_sync_session(&self, user_uuid: &str, device_id: Option<&str>, import_type: &str, subfolder: Option<&str>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO sync_sessions (user_uuid, device_id, import_type, subfolder, created_at, last_active_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active')",
            params![user_uuid, device_id, import_type, subfolder, now, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_active_sync_session(&self, user_uuid: &str) -> Result<Option<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, device_id, import_type, created_at, last_active_at, status, files_processed 
             FROM sync_sessions 
             WHERE user_uuid = ?1 AND status = 'active'"
        )?;
        let mut rows = stmt.query(params![user_uuid])?;
        if let Some(row) = rows.next()? {
            Ok(Some(serde_json::json!({
                "files_processed": row.get::<_, i32>(6)?,
            })))
        } else {
            Ok(None)
        }
    }

    pub fn cancel_active_sync_sessions(&self, user_uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sync_sessions SET status = 'failed', last_active_at = ?1 WHERE user_uuid = ?2 AND status = 'active'",
            params![chrono::Utc::now().timestamp(), user_uuid],
        )?;
        Ok(())
    }

    pub fn get_sync_session_by_id(&self, id: i64) -> Result<Option<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user_uuid, device_id, import_type, created_at, last_active_at, status, files_processed, subfolder 
             FROM sync_sessions 
             WHERE id = ?1"
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "user_uuid": row.get::<_, String>(1)?,
                "device_id": row.get::<_, Option<String>>(2)?,
                "import_type": row.get::<_, String>(3)?,
                "created_at": row.get::<_, i64>(4)?,
                "last_active_at": row.get::<_, i64>(5)?,
                "status": row.get::<_, String>(6)?,
                "files_processed": row.get::<_, i32>(7)?,
                "subfolder": row.get::<_, Option<String>>(8)?,
            })))
        } else {
            Ok(None)
        }
    }

    pub fn update_sync_session_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE sync_sessions SET status = ?1, last_active_at = ?2 WHERE id = ?3",
            params![status, now, id],
        )?;
        Ok(())
    }

    pub fn touch_sync_session(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE sync_sessions SET last_active_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    pub fn increment_sync_session_files(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE sync_sessions SET files_processed = files_processed + 1, last_active_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    pub fn cleanup_expired_sync_sessions(&self, timeout_seconds: i64) -> Result<usize> {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - timeout_seconds;
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE sync_sessions SET status = 'failed' WHERE status = 'active' AND last_active_at < ?1",
            params![cutoff],
        )?;
        if affected > 0 {
            tracing::info!("Cleaned up {} expired sync sessions", affected);
        }
        Ok(affected)
    }
}
