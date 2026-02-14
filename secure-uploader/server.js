require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const https = require('https');

const { initDB, findUser, upsertFile, db } = require('./db');
const { authenticate } = require('./middleware');

const app = express();
app.use(express.json());
app.use(cors());

// ---------------- Helmet + CSP ----------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", 'https:'],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);

// ---------------- Initialize DB ----------------
initDB(process.env.DEFAULT_USER, process.env.DEFAULT_PASS);

const REQUIRED_FILES = ["config.json","manifest.xml","data.db","metadata.txt"];
const ALLOWED_EXT = ['edf','crc','tgt'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

// ---------------- Serve frontend ----------------
app.use(express.static(path.join(__dirname, 'public')));

// ---------------- Helpers ----------------
function sanitizePath(p) {
  return path.normalize(p).replace(/^(\.\.(\/|\\|$))+/, '');
}

// ---------------- Login ----------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await findUser(username);
  if (!user) return res.sendStatus(401);
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.sendStatus(401);

  const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

// ---------------- Upload ----------------
const upload = multer({ dest: "uploads/", limits: { fileSize: MAX_FILE_SIZE } });

app.post("/upload", authenticate, upload.single("file"), async (req, res) => {
  try {
    const relativePath = sanitizePath(req.body.relativePath);
    const lastModified = parseInt(req.body.lastModified);
    const username = sanitizePath(req.body.username) || "default";

    // Validate extension
    const ext = path.extname(req.file.originalname).slice(1).toLowerCase();
    if (!ALLOWED_EXT.includes(ext)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ status: "error", message: "Invalid file type" });
    }

    // Create user folder
    const userDir = path.join("uploads", username);
    fs.mkdirSync(userDir, { recursive: true, mode: 0o700 });

    // Destination path
    const dest = path.join(userDir, relativePath);
    fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });

    // Move file
    fs.renameSync(req.file.path, dest);

    // Update DB
    await upsertFile(path.join(username, relativePath), lastModified);

    res.json({ status: "uploaded" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

// ---------------- Existing files endpoint ----------------
app.get("/existing-files", authenticate, async (req, res) => {
  const username = sanitizePath(req.query.username || '');
  db.all(`SELECT path FROM files WHERE path LIKE ?`, [username + '/%'], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json([]);
    }
    res.json(rows.map(r => r.path));
  });
});

// ---------------- Delete user data ----------------
app.post("/delete-user", authenticate, async (req, res) => {
  const username = sanitizePath(req.body.username || '');
  const userDir = path.join("uploads", username);
  if (fs.existsSync(userDir)) fs.rmSync(userDir, { recursive: true, force: true });
  db.run(`DELETE FROM files WHERE path LIKE ?`, [username + '/%']);
  res.json({ status: "deleted" });
});

// ---------------- Catch-all for frontend ----------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------- HTTPS Server ----------------
const PORT = process.env.PORT || 3000;
const keyPath = process.env.SSL_KEY_PATH || path.join(__dirname, 'certs/key.pem');
const certPath = process.env.SSL_CERT_PATH || path.join(__dirname, 'certs/cert.pem');

for (const requiredPath of [keyPath, certPath]) {
  if (!fs.existsSync(requiredPath)) {
    console.error('TLS certificate files are missing.');
    console.error(`Missing file: ${requiredPath}`);
    console.error('If running with Docker Compose, ensure host certs are in ./certs relative to secure-uploader/docker-compose.yml, or override SSL_KEY_PATH/SSL_CERT_PATH.');
    process.exit(1);
  }
}

let key;
let cert;
try {
  fs.accessSync(keyPath, fs.constants.R_OK);
  fs.accessSync(certPath, fs.constants.R_OK);
  key = fs.readFileSync(keyPath);
  cert = fs.readFileSync(certPath);
} catch (err) {
  console.error('Failed to read TLS certificate files.');
  console.error(`Process UID:GID ${process.getuid?.() ?? 'n/a'}:${process.getgid?.() ?? 'n/a'}`);
  console.error(`Key path: ${keyPath}`);
  console.error(`Cert path: ${certPath}`);
  if (err && err.code) console.error(`Node error code: ${err.code}`);
  console.error('Likely causes: unreadable file permissions, missing execute permission on a parent directory, or SELinux/AppArmor bind-mount restrictions.');
  process.exit(1);
}

const server = https.createServer({ key, cert }, app);
server.listen(PORT, () => console.log(`Secure uploader running on https://0.0.0.0:${PORT}`));

// ---------------- Graceful Shutdown ----------------
function gracefulShutdown() {
  console.log("Shutting down gracefully...");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
  setTimeout(() => { console.error("Force shutdown!"); process.exit(1); }, 5000);
}
process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);
