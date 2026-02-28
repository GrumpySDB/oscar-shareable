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
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        
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

        Ok(Database {
            conn: Mutex::new(conn),
        })
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
}
