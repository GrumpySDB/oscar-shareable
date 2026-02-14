require('dotenv').config();

const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');
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
const OSCAR_BASE_URL = process.env.OSCAR_BASE_URL || 'http://oscar:3000';

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const USERNAME_MAX_LENGTH = 128;
const PASSWORD_MAX_LENGTH = 256;
const ALLOWED_EXTENSIONS = new Set(['.crc', '.tgt', '.edf']);
const REQUIRED_ALWAYS = ['Identification.crc', 'Identification.tgt', 'STR.edf'];
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const UPLOAD_ROOT = path.join(__dirname, 'data', 'uploads');
const UPLOAD_UID = Number(process.env.UPLOAD_UID || 911);
const UPLOAD_GID = Number(process.env.UPLOAD_GID || 911);
const OSCAR_LAUNCH_TTL_SECONDS = 120;
const OSCAR_SESSION_TTL_SECONDS = 8 * 60 * 60;

let oscarTarget;
try {
  oscarTarget = new URL(OSCAR_BASE_URL);
} catch (_error) {
  console.error(`Invalid OSCAR_BASE_URL: ${OSCAR_BASE_URL}`);
  process.exit(1);
}

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

function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  const map = new Map();
  for (const chunk of raw.split(';')) {
    const trimmed = chunk.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) continue;
    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    map.set(key, decodeURIComponent(value));
  }
  return map;
}

function issueOscarSessionCookie(res) {
  const token = jwt.sign({ sub: 'shared-user', scope: 'oscar' }, JWT_SECRET, {
    expiresIn: OSCAR_SESSION_TTL_SECONDS,
  });
  const isProd = process.env.NODE_ENV === 'production';
  const cookieParts = [
    `oscar_session=${encodeURIComponent(token)}`,
    'Path=/oscar',
    `Max-Age=${OSCAR_SESSION_TTL_SECONDS}`,
    'HttpOnly',
    'SameSite=Strict',
  ];
  if (isProd) cookieParts.push('Secure');
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function requireOscarSession(req, res, next) {
  const cookies = parseCookies(req);
  const sessionToken = cookies.get('oscar_session');
  if (!sessionToken) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const payload = jwt.verify(sessionToken, JWT_SECRET);
    if (payload.scope !== 'oscar') {
      return res.status(401).send('Unauthorized');
    }
    return next();
  } catch (_err) {
    return res.status(401).send('Unauthorized');
  }
}

function proxyOscarRequest(req, res) {
  const oscarPath = req.originalUrl.replace(/^\/oscar/, '') || '/';
  const options = {
    protocol: oscarTarget.protocol,
    hostname: oscarTarget.hostname,
    port: oscarTarget.port || (oscarTarget.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: oscarPath,
    headers: {
      ...req.headers,
      host: oscarTarget.host,
    },
  };

  delete options.headers.authorization;

  const requestLib = oscarTarget.protocol === 'https:' ? https : http;
  const proxyReq = requestLib.request(options, (proxyRes) => {
    for (const [headerName, headerValue] of Object.entries(proxyRes.headers)) {
      if (headerName.toLowerCase() === 'transfer-encoding') continue;
      if (headerValue !== undefined) {
        res.setHeader(headerName, headerValue);
      }
    }
    res.status(proxyRes.statusCode || 502);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', () => {
    if (!res.headersSent) {
      res.status(502).send('Unable to connect to OSCAR service');
    }
  });

  req.pipe(proxyReq);
}

const upload = multer({
  storage: multer.memoryStorage(),
  preservePath: true,
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
    const entryPath = path.join(folderPath, entry.name);
    if (entry.isDirectory()) {
      const children = await listFilenames(entryPath);
      for (const child of children) {
        names.push(path.posix.join(entry.name, child));
      }
    }
    if (entry.isFile()) names.push(entry.name);
  }
  return names;
}

function sanitizeUploadRelativePath(value) {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || value.length > 512) return null;
  if (/\0/.test(value)) return null;

  const slashNormalized = value.replace(/\\/g, '/');
  const normalized = path.posix.normalize(slashNormalized);
  if (normalized === '.' || normalized.startsWith('/') || normalized.startsWith('../') || normalized.includes('/../')) {
    return null;
  }

  const segments = normalized.split('/');
  for (const segment of segments) {
    if (!segment || segment === '.' || segment === '..') return null;
    if (segment.length > 255) return null;
    if (/[\u0000-\u001F\u007F]/.test(segment)) return null;
  }

  return segments.join('/');
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

app.post('/api/oscar-launch', authMiddleware, (_req, res) => {
  const launchToken = jwt.sign({ sub: 'shared-user', purpose: 'oscar-launch' }, JWT_SECRET, {
    expiresIn: OSCAR_LAUNCH_TTL_SECONDS,
  });
  res.json({ launchUrl: `/oscar/login?token=${encodeURIComponent(launchToken)}` });
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

    const incomingBasenames = files.map((file) => path.basename(file.originalname));
    for (const requiredName of REQUIRED_ALWAYS) {
      if (!incomingBasenames.includes(requiredName)) {
        return res.status(400).json({ error: `Missing required file: ${requiredName}` });
      }
    }

    const dedupe = new Set();
    for (const file of files) {
      const relativePath = sanitizeUploadRelativePath(file.originalname);
      if (!relativePath) {
        return res.status(400).json({ error: `Invalid file path: ${file.originalname}` });
      }

      if (dedupe.has(relativePath)) {
        return res.status(400).json({ error: `Duplicate filename in upload: ${relativePath}` });
      }
      dedupe.add(relativePath);
      file.safeRelativePath = relativePath;

      const extension = path.extname(relativePath).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(extension)) {
        return res.status(400).json({ error: `Invalid file extension: ${relativePath}` });
      }

      if (file.size > MAX_FILE_SIZE) {
        return res.status(400).json({ error: `File exceeds 10MB: ${relativePath}` });
      }
    }

    const folderPath = path.join(UPLOAD_ROOT, folder);
    await fsp.mkdir(folderPath, { recursive: true, mode: 0o750 });
    await ensureOwnership(UPLOAD_ROOT);
    await ensureOwnership(folderPath);

    for (const file of files) {
      const destination = path.join(folderPath, file.safeRelativePath);
      const destinationDir = path.dirname(destination);
      await fsp.mkdir(destinationDir, { recursive: true, mode: 0o750 });
      await ensureOwnership(destinationDir);
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

app.get('/oscar/login', (req, res) => {
  const launchToken = typeof req.query.token === 'string' ? req.query.token : '';
  if (!launchToken) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const payload = jwt.verify(launchToken, JWT_SECRET);
    if (payload.purpose !== 'oscar-launch') {
      return res.status(401).send('Unauthorized');
    }
    issueOscarSessionCookie(res);
    return res.redirect('/oscar/');
  } catch (_err) {
    return res.status(401).send('Unauthorized');
  }
});

app.use('/oscar', requireOscarSession, proxyOscarRequest);

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
