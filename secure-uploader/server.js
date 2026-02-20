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
const HTTPS_PORT = Number(process.env.HTTPS_PORT || process.env.PORT || 50710);
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || path.join(__dirname, 'certs', 'key.pem');
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || path.join(__dirname, 'certs', 'cert.pem');
const JWT_SECRET = process.env.JWT_SECRET;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const REQUIRE_DOCKER = String(process.env.REQUIRE_DOCKER || 'true').toLowerCase() === 'true';
const OSCAR_BASE_URL = process.env.OSCAR_BASE_URL || 'http://oscar:3000';
const OSCAR_DNS_FAMILY = Number(process.env.OSCAR_DNS_FAMILY || 4);

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const USERNAME_MAX_LENGTH = 128;
const PASSWORD_MAX_LENGTH = 256;
const REQUIRED_ALWAYS = ['Identification.crc', 'STR.edf'];
const UPLOAD_ROOT = path.join(__dirname, 'data', 'uploads');
const UPLOAD_UID = Number(process.env.UPLOAD_UID || 911);
const UPLOAD_GID = Number(process.env.UPLOAD_GID || 911);
const OSCAR_LAUNCH_TTL_SECONDS = 120;
const OSCAR_SESSION_TTL_SECONDS = 8 * 60 * 60;
const AUTH_SESSION_TTL_SECONDS = Number(process.env.AUTH_SESSION_TTL_SECONDS || 30 * 60);
const UPLOAD_SESSION_TTL_MS = 30 * 60 * 1000;

const activeAuthSessions = new Map();
const consumedLaunchTokens = new Map();
const pendingUploadSessions = new Map();

let oscarTarget;
try {
  oscarTarget = new URL(OSCAR_BASE_URL);
} catch (_error) {
  console.error(`Invalid OSCAR_BASE_URL: ${OSCAR_BASE_URL}`);
  process.exit(1);
}

if (oscarTarget.protocol !== 'http:' && oscarTarget.protocol !== 'https:') {
  console.error(`OSCAR_BASE_URL protocol must be http or https. Received: ${oscarTarget.protocol}`);
  process.exit(1);
}

if (![0, 4, 6].includes(OSCAR_DNS_FAMILY)) {
  console.error(`OSCAR_DNS_FAMILY must be 0, 4, or 6. Received: ${OSCAR_DNS_FAMILY}`);
  process.exit(1);
}

if (REQUIRE_DOCKER && !fs.existsSync('/.dockerenv')) {
  console.error('Refusing to start outside Docker (REQUIRE_DOCKER=true).');
  process.exit(1);
}


if (!Number.isFinite(AUTH_SESSION_TTL_SECONDS) || AUTH_SESSION_TTL_SECONDS < 60) {
  console.error('AUTH_SESSION_TTL_SECONDS must be a numeric value of at least 60 seconds.');
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
const securityHeaders = helmet({
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
});

app.use((req, res, next) => {
  if (req.path.startsWith('/oscar/')) {
    return next();
  }
  return securityHeaders(req, res, next);
});



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

function getSixMonthsAgo(referenceTime = Date.now()) {
  const date = new Date(referenceTime);
  date.setMonth(date.getMonth() - 6);
  return date;
}

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
    if (!isAuthSessionActive(payload)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.auth = payload;
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function cleanupExpiredSessions(referenceTime = Date.now()) {
  for (const [sid, session] of activeAuthSessions.entries()) {
    if (!session || !Number.isFinite(session.expiresAt) || session.expiresAt <= referenceTime) {
      activeAuthSessions.delete(sid);
    }
  }
}

function cleanupConsumedLaunchTokens(referenceTime = Date.now()) {
  for (const [jti, expiresAt] of consumedLaunchTokens.entries()) {
    if (!Number.isFinite(expiresAt) || expiresAt <= referenceTime) {
      consumedLaunchTokens.delete(jti);
    }
  }
}

function registerAuthSession({ sid, sub, now = Date.now() }) {
  const expiresAt = now + (AUTH_SESSION_TTL_SECONDS * 1000);
  activeAuthSessions.set(sid, { sub, expiresAt });
}

function isAuthSessionActive(payload) {
  if (!payload || typeof payload !== 'object') return false;
  if (typeof payload.sid !== 'string' || typeof payload.sub !== 'string') return false;
  cleanupExpiredSessions();
  const session = activeAuthSessions.get(payload.sid);
  return Boolean(session && session.sub === payload.sub);
}

function buildRequestFingerprint(req) {
  const userAgent = String(req.headers['user-agent'] || '');
  const acceptLanguage = String(req.headers['accept-language'] || '');
  return crypto.createHash('sha256').update(`${userAgent}\n${acceptLanguage}`).digest('base64url');
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

function issueOscarSessionCookie(res, { ownerId, sid, fingerprint }) {
  const token = jwt.sign({ sub: ownerId, sid, fp: fingerprint, scope: 'oscar' }, JWT_SECRET, {
    expiresIn: OSCAR_SESSION_TTL_SECONDS,
  });
  const cookieParts = [
    `oscar_session=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${OSCAR_SESSION_TTL_SECONDS}`,
    'HttpOnly',
    'SameSite=Strict',
    'Secure',
  ];
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function clearOscarSessionCookie(res) {
  res.setHeader('Set-Cookie', 'oscar_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure');
}

function requireOscarSession(req, res, next) {
  const cookies = parseCookies(req);
  const sessionToken = cookies.get('oscar_session');
  if (!sessionToken) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const payload = jwt.verify(sessionToken, JWT_SECRET);
    if (payload.scope !== 'oscar' || !isAuthSessionActive(payload)) {
      return res.status(401).send('Unauthorized');
    }
    if (payload.fp !== buildRequestFingerprint(req)) {
      return res.status(401).send('Unauthorized');
    }
    return next();
  } catch (_err) {
    return res.status(401).send('Unauthorized');
  }
}

function getOscarTargetPath(incomingPath) {
  const rawPath = typeof incomingPath === 'string' ? incomingPath : '/';
  if (rawPath.startsWith('/oscar')) {
    return rawPath.replace(/^\/oscar/, '') || '/';
  }
  return rawPath || '/';
}


const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function buildOscarProxyHeaders(req, { isWebSocket = false } = {}) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
    headers[name] = value;
  }

  headers.host = oscarTarget.host;
  headers['x-forwarded-for'] = req.ip || req.socket.remoteAddress || '';
  headers['x-forwarded-proto'] = 'https';
  if (req.headers.host) {
    headers['x-forwarded-host'] = req.headers.host;
  }

  if (isWebSocket) {
    headers.connection = 'Upgrade';
    headers.upgrade = 'websocket';
  }

  return headers;
}

function proxyOscarRequest(req, res) {
  const oscarPath = getOscarTargetPath(req.originalUrl);
  const options = {
    protocol: oscarTarget.protocol,
    hostname: oscarTarget.hostname,
    port: oscarTarget.port || (oscarTarget.protocol === 'https:' ? 443 : 80),
    family: OSCAR_DNS_FAMILY,
    method: req.method,
    path: oscarPath,
    headers: buildOscarProxyHeaders(req),
  };

  delete options.headers.authorization;

  const requestLib = oscarTarget.protocol === 'https:' ? https : http;
  const proxyReq = requestLib.request(options, (proxyRes) => {
    for (const [headerName, headerValue] of Object.entries(proxyRes.headers)) {
      if (headerName.toLowerCase() === 'transfer-encoding') continue;
      if (headerName.toLowerCase() === 'content-security-policy' && typeof headerValue === 'string') {
        const directives = headerValue
          .split(';')
          .map((directive) => directive.trim())
          .filter(Boolean)
          .filter((directive) => !directive.toLowerCase().startsWith('frame-ancestors'));
        directives.push("frame-ancestors 'self'");
        res.setHeader(headerName, directives.join('; '));
        continue;
      }
      if (headerValue !== undefined) {
        res.setHeader(headerName, headerValue);
      }
    }
    res.status(proxyRes.statusCode || 502);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (error) => {
    console.error(`OSCAR proxy request failed for ${req.method} ${oscarPath}: ${error.message}`);
    if (!res.headersSent) {
      res.status(502).send('Unable to connect to OSCAR service');
    }
  });

  req.pipe(proxyReq);
}

function proxyOscarWebSocket(req, socket, head) {
  const oscarPath = getOscarTargetPath(req.url);
  const targetPort = oscarTarget.port || (oscarTarget.protocol === 'https:' ? 443 : 80);
  const connectOptions = {
    protocol: oscarTarget.protocol,
    hostname: oscarTarget.hostname,
    port: targetPort,
    family: OSCAR_DNS_FAMILY,
    path: oscarPath,
    method: 'GET',
    headers: buildOscarProxyHeaders(req, { isWebSocket: true }),
  };

  const requestLib = oscarTarget.protocol === 'https:' ? https : http;
  const proxyReq = requestLib.request(connectOptions);

  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    const statusCode = proxyRes.statusCode || 101;
    const statusMessage = proxyRes.statusMessage || 'Switching Protocols';
    const headerLines = [`HTTP/1.1 ${statusCode} ${statusMessage}`];

    for (const [name, value] of Object.entries(proxyRes.headers)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          headerLines.push(`${name}: ${item}`);
        }
      } else if (value !== undefined) {
        headerLines.push(`${name}: ${value}`);
      }
    }

    socket.write(`${headerLines.join('\r\n')}\r\n\r\n`);
    if (proxyHead && proxyHead.length > 0) {
      socket.write(proxyHead);
    }
    if (head && head.length > 0) {
      proxySocket.write(head);
    }
    proxySocket.pipe(socket).pipe(proxySocket);
  });

  proxyReq.on('response', () => {
    socket.end();
  });

  proxyReq.on('error', (error) => {
    console.error(`OSCAR websocket proxy failed for ${oscarPath}: ${error.message}`);
    socket.destroy();
  });

  proxyReq.end();
}

const upload = multer({
  storage: multer.memoryStorage(),
  preservePath: true,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 5000,
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

function cleanupPendingUploadSessions() {
  const now = Date.now();
  for (const [sessionId, session] of pendingUploadSessions.entries()) {
    if (session.expiresAt <= now) {
      pendingUploadSessions.delete(sessionId);
    }
  }
}

function parseUploadBatchMetadata(body) {
  const uploadSessionId = typeof body.uploadSessionId === 'string' ? body.uploadSessionId.trim() : '';
  const totalBatches = Number(body.totalBatches ?? 1);
  const batchIndex = Number(body.batchIndex ?? 0);

  if (!Number.isInteger(totalBatches) || totalBatches < 1 || totalBatches > 200) {
    return { error: 'Invalid total batches value' };
  }
  if (!Number.isInteger(batchIndex) || batchIndex < 0 || batchIndex >= totalBatches) {
    return { error: 'Invalid batch index value' };
  }
  if (uploadSessionId.length > 128) {
    return { error: 'Invalid upload session id' };
  }
  if (totalBatches > 1 && uploadSessionId.length === 0) {
    return { error: 'Missing upload session id for multi-batch upload' };
  }

  return {
    uploadSessionId,
    totalBatches,
    batchIndex,
  };
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

  const sessionId = crypto.randomUUID();
  registerAuthSession({ sid: sessionId, sub: username });
  const token = jwt.sign({ sub: username, sid: sessionId }, JWT_SECRET, { expiresIn: AUTH_SESSION_TTL_SECONDS });
  return res.json({ token });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  if (req.auth && typeof req.auth.sid === 'string') {
    activeAuthSessions.delete(req.auth.sid);
  }
  clearOscarSessionCookie(res);
  return res.status(204).end();
});

app.get('/api/session', authMiddleware, (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/oscar-launch', authMiddleware, (req, res) => {
  const ownerId = String(req.auth.sub || 'unknown');
  const launchTokenId = crypto.randomUUID();
  const launchToken = jwt.sign({
    sub: ownerId,
    sid: req.auth.sid,
    fp: buildRequestFingerprint(req),
    jti: launchTokenId,
    purpose: 'oscar-launch',
  }, JWT_SECRET, {
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
    const minDate = getSixMonthsAgo().getTime();
    if (selectedDate < minDate || selectedDate > today.getTime()) {
      return res.status(400).json({ error: 'Selected date out of range' });
    }

    const files = Array.isArray(req.files) ? req.files : [];
    if (files.length === 0) return res.status(400).json({ error: 'No files uploaded' });

    const uploadMeta = parseUploadBatchMetadata(req.body || {});
    if (uploadMeta.error) {
      return res.status(400).json({ error: uploadMeta.error });
    }

    const {
      uploadSessionId,
      totalBatches,
      batchIndex,
    } = uploadMeta;

    cleanupPendingUploadSessions();

    let uploadSession = null;
    if (totalBatches > 1) {
      uploadSession = pendingUploadSessions.get(uploadSessionId);
      if (!uploadSession) {
        if (batchIndex !== 0) {
          return res.status(400).json({ error: 'Upload session not found or expired. Restart upload.' });
        }
        uploadSession = {
          folder,
          selectedDate,
          totalBatches,
          nextBatchIndex: 0,
          seenRequired: new Set(),
          seenPaths: new Set(),
          expiresAt: Date.now() + UPLOAD_SESSION_TTL_MS,
        };
        pendingUploadSessions.set(uploadSessionId, uploadSession);
      }

      if (
        uploadSession.folder !== folder
        || uploadSession.selectedDate !== selectedDate
        || uploadSession.totalBatches !== totalBatches
      ) {
        return res.status(400).json({ error: 'Upload session metadata mismatch. Restart upload.' });
      }

      if (uploadSession.nextBatchIndex !== batchIndex) {
        return res.status(400).json({ error: `Unexpected batch order. Expected batch ${uploadSession.nextBatchIndex + 1}.` });
      }

      uploadSession.expiresAt = Date.now() + UPLOAD_SESSION_TTL_MS;
    }

    const incomingBasenames = files.map((file) => path.basename(file.originalname));
    if (uploadSession) {
      for (const basename of incomingBasenames) {
        if (REQUIRED_ALWAYS.includes(basename)) {
          uploadSession.seenRequired.add(basename);
        }
      }
    } else {
      for (const requiredName of REQUIRED_ALWAYS) {
        if (!incomingBasenames.includes(requiredName)) {
          return res.status(400).json({ error: `Missing required file: ${requiredName}` });
        }
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
      if (uploadSession && uploadSession.seenPaths.has(relativePath)) {
        return res.status(400).json({ error: `Duplicate filename across batches: ${relativePath}` });
      }
      dedupe.add(relativePath);
      file.safeRelativePath = relativePath;

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

      if (uploadSession) {
        uploadSession.seenPaths.add(file.safeRelativePath);
      }
    }

    if (uploadSession) {
      const isFinalBatch = batchIndex === totalBatches - 1;
      uploadSession.nextBatchIndex += 1;

      if (isFinalBatch) {
        for (const requiredName of REQUIRED_ALWAYS) {
          if (!uploadSession.seenRequired.has(requiredName)) {
            pendingUploadSessions.delete(uploadSessionId);
            return res.status(400).json({ error: `Missing required file: ${requiredName}` });
          }
        }
        pendingUploadSessions.delete(uploadSessionId);
      }
    }

    return res.json({ uploaded: files.length, batchIndex, totalBatches });
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
    cleanupConsumedLaunchTokens();
    const payload = jwt.verify(launchToken, JWT_SECRET);
    if (
      payload.purpose !== 'oscar-launch'
      || typeof payload.sub !== 'string'
      || typeof payload.sid !== 'string'
      || typeof payload.fp !== 'string'
      || typeof payload.jti !== 'string'
      || consumedLaunchTokens.has(payload.jti)
      || !isAuthSessionActive(payload)
      || payload.fp !== buildRequestFingerprint(req)
    ) {
      return res.status(401).send('Unauthorized');
    }

    consumedLaunchTokens.set(payload.jti, Date.now() + (OSCAR_LAUNCH_TTL_SECONDS * 1000));
    issueOscarSessionCookie(res, { ownerId: payload.sub, sid: payload.sid, fingerprint: payload.fp });
    return res.redirect('/oscar/');
  } catch (_err) {
    return res.status(401).send('Unauthorized');
  }
});

app.use('/oscar', requireOscarSession, proxyOscarRequest);
app.use('/websockify', requireOscarSession, proxyOscarRequest);

app.use(express.static(path.join(__dirname, 'public')));
app.get('/{*splat}', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File exceeds 10MB limit' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files in one upload (max 5000)' });
    }
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

const httpsServer = https.createServer(tlsOptions, app);

httpsServer.on('upgrade', (req, socket, head) => {
  if (!req.url || (!req.url.startsWith('/oscar/') && !req.url.startsWith('/websockify'))) {
    socket.destroy();
    return;
  }

  const cookies = new Map();
  for (const chunk of String(req.headers.cookie || '').split(';')) {
    const trimmed = chunk.trim();
    if (!trimmed) continue;
    const sep = trimmed.indexOf('=');
    if (sep <= 0) continue;
    cookies.set(trimmed.slice(0, sep), decodeURIComponent(trimmed.slice(sep + 1)));
  }

  const sessionToken = cookies.get('oscar_session');
  if (!sessionToken) {
    socket.destroy();
    return;
  }

  try {
    const payload = jwt.verify(sessionToken, JWT_SECRET);
    if (payload.scope !== 'oscar' || !isAuthSessionActive(payload)) {
      socket.destroy();
      return;
    }
    if (payload.fp !== buildRequestFingerprint(req)) {
      socket.destroy();
      return;
    }
  } catch (_err) {
    socket.destroy();
    return;
  }

  proxyOscarWebSocket(req, socket, head);
});

httpsServer.listen(HTTPS_PORT, () => {
  console.log(`OSCAR uploader running on https://0.0.0.0:${HTTPS_PORT}`);
});
