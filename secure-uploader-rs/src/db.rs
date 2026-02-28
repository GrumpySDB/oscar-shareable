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
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                created_by_uuid TEXT NOT NULL,
                used_by_uuid TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(created_by_uuid) REFERENCES users(uuid),
                FOREIGN KEY(used_by_uuid) REFERENCES users(uuid)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS share_links (
                token TEXT PRIMARY KEY,
                owner_uuid TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(owner_uuid) REFERENCES users(uuid)
            )",
            [],
        )?;

        let db = Database {
            conn: Mutex::new(conn),
        };

        db.ensure_super_admin(app_username, app_password)?;

        Ok(db)
    }

    fn ensure_super_admin(&self, app_username: &str, app_password: &str) -> Result<()> {
        let admin = self.get_user_by_identifier("local", app_username)?;
        if admin.is_none() {
            use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
            use rand::rngs::OsRng;

            let salt = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::default()
                .hash_password(app_password.as_bytes(), &salt)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))))?
                .to_string();

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
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, role FROM users WHERE provider = ?1 AND identifier = ?2")?;
        
        let mut rows = stmt.query(params![provider, identifier])?;
        if let Some(row) = rows.next()? {
            Ok(Some(User {
                uuid: row.get(0)?,
                username: row.get(1)?,
                provider: row.get(2)?,
                identifier: row.get(3)?,
                role: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_user_by_uuid(&self, uuid: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, role FROM users WHERE uuid = ?1")?;
        
        let mut rows = stmt.query(params![uuid])?;
        if let Some(row) = rows.next()? {
            Ok(Some(User {
                uuid: row.get(0)?,
                username: row.get(1)?,
                provider: row.get(2)?,
                identifier: row.get(3)?,
                role: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn create_user(&self, user: User, password_hash: Option<String>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO users (uuid, username, provider, identifier, argon2_password_hash, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                user.uuid,
                user.username,
                user.provider,
                user.identifier,
                password_hash,
                user.role,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn verify_password(&self, provider: &str, identifier: &str, password: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, argon2_password_hash, role FROM users WHERE provider = ?1 AND identifier = ?2")?;
        
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

    pub fn use_invite(&self, code: &str, user_uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE invites SET used_by_uuid = ?1 WHERE code = ?2",
            params![user_uuid, code],
        )?;
        Ok(())
    }

    pub fn delete_user(&self, uuid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        // With PRAGMA foreign_keys = ON, this will cascade delete invites and share_links
        // However, we want to make sure it exists first
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

    pub fn create_invite(&self, code: &str, created_by_uuid: &str, expires_at: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO invites (code, created_by_uuid, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![code, created_by_uuid, now, expires_at],
        )?;
        Ok(())
    }

    pub fn get_all_invites(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT code, created_by_uuid, used_by_uuid, created_at, expires_at FROM invites ORDER BY created_at DESC")?;
        
        let it = stmt.query_map([], |row| {
            let used: Option<String> = row.get(2)?;
            Ok(serde_json::json!({
                "code": row.get::<_, String>(0)?,
                "created_by_uuid": row.get::<_, String>(1)?,
                "used_by_uuid": used,
                "created_at": row.get::<_, i64>(3)?,
                "expires_at": row.get::<_, i64>(4)?
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
        let mut stmt = conn.prepare("SELECT uuid, username, provider, identifier, role FROM users")?;
        let user_iter = stmt.query_map([], |row| {
            Ok(User {
                uuid: row.get(0)?,
                username: row.get(1)?,
                provider: row.get(2)?,
                identifier: row.get(3)?,
                role: row.get(4)?,
            })
        })?;
        
        let mut users = Vec::new();
        for user in user_iter {
            users.push(user?);
        }
        Ok(users)
    }
}
