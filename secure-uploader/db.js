const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

const DB_DIR = path.join(__dirname, 'db');
const DB_PATH = path.join(DB_DIR, 'files.db');

// Ensure DB folder exists
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true, mode: 0o700 });

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("DB Error:", err);
  else console.log("SQLite DB opened at", DB_PATH);
});

// Create necessary tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    lastModified INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
});

// Insert or update default user
async function initDB(defaultUser, defaultPass) {
  if (!defaultUser || !defaultPass) return;
  const hash = await bcrypt.hash(defaultPass, 10);
  db.run(
    `INSERT INTO users (username, password) VALUES (?, ?)
     ON CONFLICT(username) DO UPDATE SET password=excluded.password`,
    [defaultUser, hash],
    (err) => {
      if (err) console.error("Error creating default user:", err);
      else console.log(`Default user '${defaultUser}' ready`);
    }
  );
}

// Find user by username
function findUser(username) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM users WHERE username=?`, [username], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Upsert uploaded file
async function upsertFile(filePath, lastModified) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO files (path, lastModified) VALUES (?, ?)
       ON CONFLICT(path) DO UPDATE SET lastModified=excluded.lastModified`,
      [filePath, lastModified],
      (err) => (err ? reject(err) : resolve())
    );
  });
}

module.exports = { db, initDB, findUser, upsertFile };
