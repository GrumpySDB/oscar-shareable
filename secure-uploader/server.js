require('dotenv').config();

const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const HTTPS_PORT = Number(process.env.HTTPS_PORT || process.env.PORT || 3443);
const HTTP_PORT = Number(process.env.HTTP_PORT || 3000);
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || path.join(__dirname, 'certs', 'key.pem');
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || path.join(__dirname, 'certs', 'cert.pem');
const JWT_SECRET = process.env.JWT_SECRET;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const REQUIRE_DOCKER = String(process.env.REQUIRE_DOCKER || 'true').toLowerCase() === 'true';

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const USERNAME_MAX_LENGTH = 128;
const PASSWORD_MAX_LENGTH = 256;
const ALLOWED_EXTENSIONS = new Set(['.crc', '.tgt', '.edf']);
const REQUIRED_ALWAYS = ['Identification.crc', 'Identification.tgt', 'STR.edf'];
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const UPLOAD_ROOT = path.join(__dirname, 'data', 'uploads');
const UPLOAD_UID = Number(process.env.UPLOAD_UID || 911);
const UPLOAD_GID = Number(process.env.UPLOAD_GID || 911);

if (REQUIRE_DOCKER && !fs.existsSync('/.dockerenv')) {
  console.error('Refusing to start outside Docker (REQUIRE_DOCKER=true).');
  process.exit(1);
}

if (!JWT_SECRET || !APP_USERNAME || !APP_PASSWORD) {
  console.error('Missing required environment variables: JWT_SECRET, APP_USERNAME, APP_PASSWORD.');
  process.exit(1);
}

fs.mkdirSync(UPLOAD_ROOT, { recursive: true, mode: 0o750 });

try {
  ensureOwnershipSync(UPLOAD_ROOT);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: false,
      preload: false,
    },
    crossOriginEmbedderPolicy: false,
  })
);



function createSimpleLimiter({ windowMs, max }) {
  const hits = new Map();
  return (req, res, next) => {
    const key = req.ip || 'unknown';
    const now = Date.now();
    const item = hits.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > item.resetAt) {
      item.count = 0;
      item.resetAt = now + windowMs;
    }
    item.count += 1;
    hits.set(key, item);
    if (item.count > max) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    return next();
  };
}

const authLimiter = createSimpleLimiter({ windowMs: 15 * 60 * 1000, max: 30 });
const apiLimiter = createSimpleLimiter({ windowMs: 15 * 60 * 1000, max: 300 });
app.use('/api', apiLimiter);

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function sanitizeFolderName(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(normalized)) return null;
  return normalized;
}

function sanitizeCredentialInput(value, { trim = false, maxLength }) {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC');
  const candidate = trim ? normalized.trim() : normalized;
  if (candidate.length === 0 || candidate.length > maxLength) return null;
  if (/[\u0000-\u001F\u007F]/.test(candidate)) return null;
  return candidate;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = payload;
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 500,
  },
});


function ownershipError(targetPath, stats) {
  return new Error(`Upload path ownership must be ${UPLOAD_UID}:${UPLOAD_GID}; found ${stats.uid}:${stats.gid} at ${targetPath}`);
}

function ensureOwnershipSync(targetPath) {
  const stats = fs.statSync(targetPath);
  if (stats.uid !== UPLOAD_UID || stats.gid !== UPLOAD_GID) {
    throw ownershipError(targetPath, stats);
  }
}

async function ensureOwnership(targetPath) {
  const stats = await fsp.stat(targetPath);
  if (stats.uid !== UPLOAD_UID || stats.gid !== UPLOAD_GID) {
    throw ownershipError(targetPath, stats);
  }
}

async function listFilenames(folderPath) {
  const entries = await fsp.readdir(folderPath, { withFileTypes: true });
  const names = [];
  for (const entry of entries) {
    if (entry.isFile()) names.push(entry.name);
  }
  return names;
}

app.post('/api/login', authLimiter, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const username = sanitizeCredentialInput(body.username, {
    trim: true,
    maxLength: USERNAME_MAX_LENGTH,
  });
  const password = sanitizeCredentialInput(body.password, {
    trim: false,
    maxLength: PASSWORD_MAX_LENGTH,
  });

  if (!username || !password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!safeEqual(username, APP_USERNAME) || !safeEqual(password, APP_PASSWORD)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ sub: 'shared-user' }, JWT_SECRET, { expiresIn: '8h' });
  return res.json({ token });
});

app.get('/api/session', authMiddleware, (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/folders/:folder/files', authMiddleware, async (req, res) => {
  const folder = sanitizeFolderName(req.params.folder);
  if (!folder) return res.status(400).json({ error: 'Invalid folder name' });

  const folderPath = path.join(UPLOAD_ROOT, folder);
  if (!fs.existsSync(folderPath)) return res.json({ filenames: [] });

  const filenames = await listFilenames(folderPath);
  return res.json({ filenames });
});

app.post('/api/upload', authMiddleware, upload.array('files'), async (req, res) => {
  try {
    const folder = sanitizeFolderName(req.body.folder);
    if (!folder) return res.status(400).json({ error: 'Invalid folder name' });

    const selectedDate = Number(req.body.selectedDateMs);
    if (!Number.isFinite(selectedDate)) return res.status(400).json({ error: 'Invalid selected date' });

    const today = new Date();
    today.setHours(23, 59, 59, 999);
    const minDate = Date.now() - ONE_YEAR_MS;
    if (selectedDate < minDate || selectedDate > today.getTime()) {
      return res.status(400).json({ error: 'Selected date out of range' });
    }

    const files = Array.isArray(req.files) ? req.files : [];
    if (files.length === 0) return res.status(400).json({ error: 'No files uploaded' });

    const incomingNames = files.map((file) => file.originalname);
    for (const requiredName of REQUIRED_ALWAYS) {
      if (!incomingNames.includes(requiredName)) {
        return res.status(400).json({ error: `Missing required file: ${requiredName}` });
      }
    }

    const dedupe = new Set();
    for (const file of files) {
      if (dedupe.has(file.originalname)) {
        return res.status(400).json({ error: `Duplicate filename in upload: ${file.originalname}` });
      }
      dedupe.add(file.originalname);

      const extension = path.extname(file.originalname).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(extension)) {
        return res.status(400).json({ error: `Invalid file extension: ${file.originalname}` });
      }

      if (file.size > MAX_FILE_SIZE) {
        return res.status(400).json({ error: `File exceeds 10MB: ${file.originalname}` });
      }
    }

    const folderPath = path.join(UPLOAD_ROOT, folder);
    await fsp.mkdir(folderPath, { recursive: true, mode: 0o750 });
    await ensureOwnership(UPLOAD_ROOT);
    await ensureOwnership(folderPath);

    for (const file of files) {
      const destination = path.join(folderPath, path.basename(file.originalname));
      if (fs.existsSync(destination)) {
        await ensureOwnership(destination);
      }
      await fsp.writeFile(destination, file.buffer, { mode: 0o640 });
      await ensureOwnership(destination);
    }

    return res.json({ uploaded: files.length });
  } catch (error) {
    return res.status(500).json({ error: 'Upload failed', detail: error.message });
  }
});

app.delete('/api/folders/:folder', authMiddleware, async (req, res) => {
  const folder = sanitizeFolderName(req.params.folder);
  if (!folder) return res.status(400).json({ error: 'Invalid folder name' });

  const folderPath = path.join(UPLOAD_ROOT, folder);
  await fsp.rm(folderPath, { recursive: true, force: true });
  return res.json({ deleted: folder });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/{*splat}', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File exceeds 10MB limit' });
  }
  return res.status(500).json({ error: 'Unexpected server error' });
});

if (!fs.existsSync(SSL_KEY_PATH) || !fs.existsSync(SSL_CERT_PATH)) {
  console.error(`TLS files not found. Expected:\n- key: ${SSL_KEY_PATH}\n- cert: ${SSL_CERT_PATH}`);
  process.exit(1);
}

const tlsOptions = {
  key: fs.readFileSync(SSL_KEY_PATH),
  cert: fs.readFileSync(SSL_CERT_PATH),
};

https.createServer(tlsOptions, app).listen(HTTPS_PORT, () => {
  console.log(`OSCAR uploader running on https://0.0.0.0:${HTTPS_PORT}`);
});

http
  .createServer((req, res) => {
    const hostHeader = String(req.headers.host || '');
    const host = hostHeader ? hostHeader.replace(/:\d+$/, '') : 'localhost';
    const httpsPortSuffix = HTTPS_PORT === 443 ? '' : `:${HTTPS_PORT}`;
    const location = `https://${host}${httpsPortSuffix}${req.url || '/'}`;
    res.writeHead(308, { Location: location });
    res.end();
  })
  .listen(HTTP_PORT, () => {
    console.log(`HTTP redirector running on http://0.0.0.0:${HTTP_PORT}`);
  });
