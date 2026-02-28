const REQUIRED_ALWAYS = ['Identification.crc', 'STR.edf'];
const OPTIONAL_ALWAYS = ['Identification.tgt', 'Identification.json', 'journal.nl'];
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const OXIMETRY_MAX_FILE_SIZE = 200 * 1024;
const MAX_UPLOAD_FILES = 5000;
const CLOUDFLARE_UPLOAD_LIMIT_BYTES = 100 * 1024 * 1024;
const SAFE_BATCH_LIMIT_BYTES = 90 * 1024 * 1024;

let token = sessionStorage.getItem('authToken') || null;
let currentUsername = '';
let preparedFiles = [];
let preparedFolder = '';
let preparedSourceRootFolder = '';
let selectedDateMs = 0;
let preparedUploadType = 'sdcard';
let preparedWellueDbParents = [];

const loginCard = document.getElementById('loginCard');
const appCard = document.getElementById('appCard');
const loginError = document.getElementById('loginError');
const statusPanel = document.getElementById('summary') || document.getElementById('statusPanel');
const statusMessage = document.getElementById('appMessage') || document.getElementById('statusMessage');
const appMessage = statusMessage;
const summary = document.getElementById('summaryCounts');
const progressBar = document.getElementById('progressBar');
const uploadBtn = document.getElementById('uploadBtn');


const loginBanner = document.getElementById('loginBanner');
const uploadBanner = document.getElementById('uploadBanner');

async function loadRandomBanner(imageElement) {
  if (!imageElement) return;

  try {
    const response = await fetch('/images/manifest.json', { cache: 'no-store' });
    if (!response.ok) return;

    const data = await response.json();
    if (!Array.isArray(data.images) || data.images.length === 0) return;

    const index = Math.floor(Math.random() * data.images.length);
    const selected = String(data.images[index] || '').trim();
    if (!selected) return;

    imageElement.src = `/images/${encodeURIComponent(selected)}`;
    imageElement.classList.remove('hidden');
  } catch (_err) { }
}


function showLogin() {
  loginCard.classList.remove('hidden');
  appCard.classList.add('hidden');
}

function showApp() {
  loginCard.classList.add('hidden');
  appCard.classList.remove('hidden');
}

function setMessage(message, isError = false, details = '') {
  if (!statusPanel || !statusMessage) return;

  const normalizedMessage = typeof message === 'string' ? message.trim() : '';
  const normalizedDetails = typeof details === 'string' ? details.trim() : '';
  const hasMessage = Boolean(normalizedMessage) || Boolean(normalizedDetails);

  statusPanel.classList.toggle('has-message', hasMessage);
  statusMessage.classList.toggle('error-state', Boolean(isError));
  statusMessage.textContent = '';

  if (!hasMessage) return;

  const title = document.createElement('strong');
  title.textContent = normalizedMessage;
  statusMessage.appendChild(title);

  if (normalizedDetails) {
    statusMessage.appendChild(document.createElement('br'));
    const detailText = document.createElement('span');
    detailText.className = 'status-details';
    detailText.textContent = normalizedDetails;
    statusMessage.appendChild(detailText);
  }
}

function getSixMonthsAgo(referenceTime = Date.now()) {
  const date = new Date(referenceTime);
  date.setMonth(date.getMonth() - 6);
  return date;
}

function configureDateInput() {
  const input = document.getElementById('startDate');
  const today = new Date();
  const min = getSixMonthsAgo();
  const defaultDate = new Date(today);
  defaultDate.setDate(defaultDate.getDate() - 7);
  const todayIso = today.toISOString().slice(0, 10);
  input.max = todayIso;
  input.min = min.toISOString().slice(0, 10);
  input.value = defaultDate.toISOString().slice(0, 10);
}

function folderNameValid(value) {
  return /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

function sanitizeUsernameInput(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC').trim();
  if (normalized.length === 0 || normalized.length > 128) return null;
  if (/[\u0000-\u001F\u007F]/.test(normalized)) return null;
  return normalized;
}

function decodeJwtPayload(jwtToken) {
  if (typeof jwtToken !== 'string') return null;
  const parts = jwtToken.split('.');
  if (parts.length < 2) return null;
  const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
  try {
    const json = atob(padded);
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (_err) {
    return null;
  }
}

function getUsernameFromToken(jwtToken) {
  const payload = decodeJwtPayload(jwtToken);
  return payload && typeof payload.sub === 'string' ? payload.sub : '';
}

function getRoleFromToken(jwtToken) {
  const payload = decodeJwtPayload(jwtToken);
  return payload && typeof payload.role === 'string' ? payload.role : '';
}

function getSelectedRootFolderName(files) {
  if (!Array.isArray(files)) return '';

  for (const file of files) {
    const relativePath = getRelativePath(file);
    const segments = relativePath.split('/').filter(Boolean);
    if (segments.length > 1) return segments[0];
  }

  return '';
}

function isRequired(name) {
  return REQUIRED_ALWAYS.includes(name);
}

function isAlwaysIncluded(name) {
  return isRequired(name) || OPTIONAL_ALWAYS.includes(name);
}

function getRelativePath(file) {
  const rawPath = String(file?.webkitRelativePath || file?.name || '').trim();
  const slashNormalized = rawPath.replace(/\\/g, '/');
  return slashNormalized.replace(/^\.\//, '');
}

function getBasename(file) {
  const relativePath = getRelativePath(file);
  const segments = relativePath.split('/').filter(Boolean);
  if (segments.length > 0) {
    return segments[segments.length - 1];
  }
  return String(file?.name || '').split(/[\\/]/).pop() || '';
}

function isTinfoilHatModeEnabled() {
  return document.getElementById('encryptionToggle')?.checked === true;
}

function isSpo2Filename(name) {
  if (typeof name !== 'string') return false;
  const trimmed = name.trim();
  return /^.+\.spo2$/i.test(trimmed);
}


function extractDateFromPath(file) {
  const relativePath = getRelativePath(file);

  // OSCAR file structures commonly include YYYYMMDD or YYYY-MM-DD in file/folder names.
  const compact = relativePath.match(/(?:^|\D)((?:19|20)\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:\D|$)/);
  if (compact) {
    const year = Number(compact[1]);
    const month = Number(compact[2]);
    const day = Number(compact[3]);
    const parsed = new Date(year, month - 1, day).getTime();
    if (Number.isFinite(parsed)) return parsed;
  }

  const dashed = relativePath.match(/(?:^|\D)((?:19|20)\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?:\D|$)/);
  if (dashed) {
    const year = Number(dashed[1]);
    const month = Number(dashed[2]);
    const day = Number(dashed[3]);
    const parsed = new Date(year, month - 1, day).getTime();
    if (Number.isFinite(parsed)) return parsed;
  }

  return null;
}

function validateFile(file, startDateMs) {
  if (file.size > MAX_FILE_SIZE) return false;

  if (isAlwaysIncluded(getBasename(file))) return true;

  const inferredDate = extractDateFromPath(file);
  const modified = Number.isFinite(inferredDate) ? inferredDate : Number(file.lastModified || 0);
  const now = Date.now();
  const sixMonthsAgo = getSixMonthsAgo(now).getTime();
  if (modified < sixMonthsAgo || modified > now) return false;
  if (modified < startDateMs) return false;

  return true;
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let detail = 'Request failed';
    try {
      const body = await response.json();
      detail = body.error || detail;
    } catch (_err) { }

    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }

  if (response.status === 204) return null;
  return response.json();
}

async function checkSession() {
  if (!token) {
    showLogin();
    return;
  }

  try {
    await api('/api/session');

    if (getRoleFromToken(token) === 'admin') {
      window.location.href = '/admin';
      return;
    }

    currentUsername = getUsernameFromToken(token);
    showApp();
  } catch (_err) {
    token = null;
    currentUsername = '';
    sessionStorage.removeItem('authToken');
    showLogin();
  }
}

let loginInProgress = false;

async function login() {
  if (loginInProgress) return;

  loginInProgress = true;
  loginError.textContent = '';
  const usernameInput = document.getElementById('username');
  const username = sanitizeUsernameInput(usernameInput.value);
  const password = document.getElementById('password').value;

  if (!username) {
    loginError.textContent = 'Please enter a valid username.';
    loginInProgress = false;
    return;
  }

  usernameInput.value = username;

  try {
    const result = await api('/api/auth/local/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    token = result.token;
    sessionStorage.setItem('authToken', token);

    if (getRoleFromToken(token) === 'admin') {
      window.location.href = '/admin';
      return;
    }

    currentUsername = username;
    showApp();
  } catch (err) {
    loginError.textContent = err.message;
  } finally {
    loginInProgress = false;
  }
}

async function logout() {
  const currentToken = token;
  token = null;
  currentUsername = '';
  sessionStorage.removeItem('authToken');

  if (currentToken) {
    try {
      await fetch('/api/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${currentToken}` },
      });
    } catch (_err) { }
  }

  resetPreparedState(true);
  setMessage('');
  showLogin();
}

function resetPreparedState(clearProgress = false) {
  preparedFiles = [];
  preparedFolder = '';
  preparedSourceRootFolder = '';
  selectedDateMs = 0;
  preparedUploadType = 'sdcard';
  preparedWellueDbParents = [];
  uploadBtn.disabled = true;
  if (clearProgress) {
    progressBar.style.width = '0%';
  }
}

function getUploadCompleteMessage() {
  const destinationFolder = document.getElementById('folderName').value.trim() || preparedFolder;
  if (preparedUploadType === 'sdcard') {
    const uploadedFolder = preparedSourceRootFolder || preparedFolder || destinationFolder;
    return `Upload Complete.  Import your SD Card data from config>SDCARD>${destinationFolder}>${uploadedFolder}`;
  }

  return `Upload Complete.  Import your Oximetry data from config>SDCARD>${destinationFolder}>Oximetry`;
}

async function scanAndPrepare() {
  setMessage('');
  resetPreparedState(true);

  const folder = document.getElementById('folderName').value.trim();
  if (!folderNameValid(folder)) {
    setMessage('Folder name must be 1-64 chars, only letters/numbers/_/-.', true);
    return;
  }

  const files = Array.from(document.getElementById('directoryInput').files || []);
  if (files.length === 0) {
    setMessage('Please choose an SD card folder first.', true);
    return;
  }

  const selectedRootFolder = getSelectedRootFolderName(files);
  const selectedDate = new Date(document.getElementById('startDate').value);

  let existingNames = [];
  try {
    const data = await api('/api/files');
    existingNames = Array.isArray(data.filenames) ? data.filenames : [];
  } catch (err) {
    setMessage(`Unable to load existing files: ${err.message}`, true);
    return;
  }

  const existingSet = new Set(existingNames);
  const hasSpo2 = files.some((file) => isSpo2Filename(getBasename(file)));
  const dbO2Files = files.filter((file) => getBasename(file).toLowerCase() === 'db_o2.db');
  const isWellueOximetry = dbO2Files.length > 0;
  const wellueDbParents = Array.from(new Set(
    dbO2Files
      .map((file) => {
        const parts = getRelativePath(file).split('/');
        return parts.slice(0, -1).join('/');
      })
      .filter(Boolean),
  ));

  let uploadType = 'sdcard';
  if (isWellueOximetry) {
    uploadType = 'wellue-spo2';
  } else if (hasSpo2) {
    uploadType = 'spo2';
  }

  if (uploadType === 'sdcard') {
    if (Number.isNaN(selectedDate.getTime())) {
      setMessage('Please select a valid start date.', true);
      return;
    }

    const now = Date.now();
    if (selectedDate.getTime() < getSixMonthsAgo(now).getTime() || selectedDate.getTime() > now) {
      setMessage('Start date must be within the past 6 months.', true);
      return;
    }

    const requiredBasenames = new Set(files.map((file) => getBasename(file)));
    for (const required of REQUIRED_ALWAYS) {
      if (!requiredBasenames.has(required)) {
        setMessage(`Invalid data: missing required file ${required}.`, true);
        return;
      }
    }
  }

  const eligible = [];
  let skippedExisting = 0;
  let skippedInvalid = 0;

  for (const file of files) {
    const relativePath = getRelativePath(file);
    const basename = getBasename(file);

    if (uploadType === 'sdcard') {
      if (!validateFile(file, selectedDate.getTime())) {
        skippedInvalid += 1;
        continue;
      }

      if (!isAlwaysIncluded(basename) && existingSet.has(relativePath)) {
        skippedExisting += 1;
        continue;
      }

      eligible.push(file);
      continue;
    }

    if (uploadType === 'spo2') {
      if (!isSpo2Filename(basename) || file.size > OXIMETRY_MAX_FILE_SIZE) {
        skippedInvalid += 1;
        continue;
      }

      const destinationPath = `Oximetry/${basename}`;
      if (existingSet.has(destinationPath)) {
        skippedExisting += 1;
        continue;
      }

      eligible.push(file);
      continue;
    }

    const relativeParts = relativePath.split('/');
    const fileName = relativeParts[relativeParts.length - 1] || '';
    const parent = relativeParts.slice(0, -2).join('/');
    const directFolder = relativeParts.length >= 2 ? relativeParts[relativeParts.length - 2] : '';
    const hasExtension = fileName.includes('.');
    const isInNumberedFolder = /^\d+$/.test(directFolder);
    const dbSiblingExists = dbO2Files.some((dbFile) => {
      const dbParts = getRelativePath(dbFile).split('/');
      const dbParent = dbParts.slice(0, -1).join('/');
      return dbParent === parent;
    });
    if (!isInNumberedFolder || !dbSiblingExists || hasExtension || file.size > OXIMETRY_MAX_FILE_SIZE || basename.toLowerCase() === 'db_o2.db') {
      skippedInvalid += 1;
      continue;
    }

    const destinationPath = `Oximetry/${directFolder}/${fileName}`;
    if (existingSet.has(destinationPath)) {
      skippedExisting += 1;
      continue;
    }

    eligible.push(file);
  }

  const skippedTotal = skippedExisting + skippedInvalid;
  if (eligible.length === 0) {
    if (uploadType !== 'sdcard' && skippedExisting > 0 && skippedInvalid === 0) {
      setMessage(
        'No new oximetry files to upload. Existing files were skipped.',
        false,
        `Valid files to upload: 0 • Files skipped: ${skippedTotal}`,
      );
      return;
    }

    setMessage(
      uploadType === 'sdcard'
        ? 'Invalid or duplicate SD card data detected. Upload is disabled.'
        : 'Invalid or duplicate oximetry data detected. Upload is disabled.',
      true,
      `Valid files to upload: 0 • Files skipped: ${skippedTotal}`,
    );
    return;
  }

  if (eligible.length > MAX_UPLOAD_FILES) {
    setMessage(
      `Too many files selected after filtering (${eligible.length}). Please choose a later start date so no more than ${MAX_UPLOAD_FILES} files are uploaded at once.`,
      true,
    );
    return;
  }

  preparedFiles = eligible;
  preparedFolder = folder;
  preparedSourceRootFolder = selectedRootFolder;
  selectedDateMs = selectedDate.getTime();
  preparedUploadType = uploadType;
  preparedWellueDbParents = uploadType === 'wellue-spo2' ? wellueDbParents : [];
  uploadBtn.disabled = false;

  const detectionMessage = uploadType === 'spo2'
    ? 'SPO2 Data Detected'
    : uploadType === 'wellue-spo2'
      ? 'Wellue/Viatom SPO2 Data Detected'
      : 'Resmed SD card data detected.';

  setMessage(detectionMessage, false, `Valid files to upload: ${eligible.length} • Files skipped: ${skippedTotal}`);
}


function pemToArrayBuffer(pem) {
  const base64 = String(pem || '').replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function getEncryptionPublicKey() {
  const result = await api('/api/encryption-public-key');
  if (!result || typeof result.publicKeyPem !== 'string') {
    throw new Error('Unable to initialize Tinfoil Hat Mode encryption key.');
  }
  return window.crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(result.publicKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
}

async function buildEncryptedBatchPayload(files) {
  const encryptionKey = await getEncryptionPublicKey();
  const envelope = {};
  const encryptedFiles = [];

  for (const file of files) {
    const plaintext = await file.arrayBuffer();
    const aesKeyBytes = window.crypto.getRandomValues(new Uint8Array(32));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await window.crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
    const encryptedBytes = new Uint8Array(encrypted);
    const tag = encryptedBytes.slice(encryptedBytes.length - 16);
    const cipherText = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const wrappedKey = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, encryptionKey, aesKeyBytes);
    const relativePath = getRelativePath(file);

    envelope[relativePath] = {
      wrappedKey: btoa(String.fromCharCode(...new Uint8Array(wrappedKey))),
      iv: btoa(String.fromCharCode(...iv)),
      tag: btoa(String.fromCharCode(...tag)),
    };

    encryptedFiles.push(new File([cipherText], relativePath, { type: 'application/octet-stream', lastModified: file.lastModified }));
  }

  return { encryptedFiles, envelope };
}

function createUploadBatches(files) {
  const batches = [];
  let currentBatch = [];
  let currentSize = 0;

  for (const file of files) {
    const fileSize = Number(file.size || 0);
    const exceedsCurrent = currentBatch.length > 0 && (currentSize + fileSize) > SAFE_BATCH_LIMIT_BYTES;
    if (exceedsCurrent) {
      batches.push(currentBatch);
      currentBatch = [];
      currentSize = 0;
    }

    currentBatch.push(file);
    currentSize += fileSize;
  }

  if (currentBatch.length > 0) batches.push(currentBatch);
  return batches;
}

function uploadBatch({ files, batchIndex, totalBatches, sessionId, totalBytes, tinfoilHatMode, encryptionEnvelope }) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('folder', preparedFolder);
    form.append('selectedDateMs', String(selectedDateMs));
    form.append('uploadType', preparedUploadType);
    if (preparedUploadType === 'wellue-spo2' && preparedWellueDbParents.length > 0) {
      form.append('wellueDbParents', JSON.stringify(preparedWellueDbParents));
    }
    form.append('uploadSessionId', sessionId);
    form.append('batchIndex', String(batchIndex));
    form.append('totalBatches', String(totalBatches));
    form.append('tinfoilHatMode', tinfoilHatMode ? 'true' : 'false');
    if (tinfoilHatMode && encryptionEnvelope) {
      form.append('encryptionEnvelope', JSON.stringify(encryptionEnvelope));
    }
    for (const file of files) {
      form.append('files', file, getRelativePath(file));
    }

    const request = new XMLHttpRequest();
    request.open('POST', '/api/upload');
    request.setRequestHeader('Authorization', `Bearer ${token}`);

    request.upload.onprogress = (event) => {
      if (!event.lengthComputable || totalBatches <= 0) return;
      const priorBatches = (batchIndex / totalBatches) * 100;
      const withinBatch = (event.loaded / event.total) * (100 / totalBatches);
      const percent = Math.min(99, Math.round(priorBatches + withinBatch));
      progressBar.style.width = `${percent}%`;

      const loadedMb = (event.loaded / (1024 * 1024)).toFixed(1);
      const batchMb = (event.total / (1024 * 1024)).toFixed(1);
      const totalMb = (totalBytes / (1024 * 1024)).toFixed(1);
      setMessage(`Uploading batch ${batchIndex + 1}/${totalBatches} (${loadedMb}/${batchMb} MB, total ${totalMb} MB)...`);
    };

    request.onload = () => {
      if (request.status >= 200 && request.status < 300) {
        resolve();
        return;
      }

      let message = 'Upload failed';
      try {
        const body = JSON.parse(request.responseText);
        message = body.error || message;
      } catch (_err) { }

      if (request.status === 413 && message === 'Upload failed') {
        message = 'Upload rejected by size limit. Please try selecting a more recent start date to reduce the number of files per upload.';
      }

      reject(new Error(message));
    };

    request.onerror = () => {
      reject(new Error('Network error during upload.'));
    };

    request.send(form);
  });
}

async function uploadPreparedFiles() {
  if (preparedFiles.length === 0) {
    setMessage('Nothing to upload. Select an SD card folder first.', true);
    return;
  }

  const tinfoilHatModeEnabled = isTinfoilHatModeEnabled();
  uploadBtn.disabled = true;

  const totalBytes = preparedFiles.reduce((sum, file) => sum + Number(file.size || 0), 0);
  const totalMb = totalBytes / (1024 * 1024);
  const requiresChunking = totalBytes > CLOUDFLARE_UPLOAD_LIMIT_BYTES;
  const batches = createUploadBatches(preparedFiles);
  const sessionId = (window.crypto && window.crypto.randomUUID)
    ? window.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

  if (requiresChunking) {
    setMessage(`Selected files total ${totalMb.toFixed(1)} MB, above Cloudflare's 100 MB request limit. Upload will run in ${batches.length} batches.`);
  } else {
    setMessage(`Uploading ${preparedFiles.length} files (${totalMb.toFixed(1)} MB)${tinfoilHatModeEnabled ? ' with Tinfoil Hat Mode enabled' : ''}...`);
  }

  try {
    for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
      const batch = batches[batchIndex];
      let filesToUpload = batch;
      let encryptionEnvelope = null;
      if (tinfoilHatModeEnabled) {
        setMessage(`Preparing encryption for batch ${batchIndex + 1}/${batches.length}...`);
        const encryptedPayload = await buildEncryptedBatchPayload(batch);
        filesToUpload = encryptedPayload.encryptedFiles;
        encryptionEnvelope = encryptedPayload.envelope;
      }

      await uploadBatch({
        files: filesToUpload,
        batchIndex,
        totalBatches: batches.length,
        sessionId,
        totalBytes,
        tinfoilHatMode: tinfoilHatModeEnabled,
        encryptionEnvelope,
      });
    }

    progressBar.style.width = '100%';
    setMessage(getUploadCompleteMessage());
    resetPreparedState();
  } catch (error) {
    setMessage(error.message, true);
    uploadBtn.disabled = false;
  }
}


async function proceedToOscar() {
  if (!token) {
    setMessage('Please log in before opening OSCAR.', true);
    showLogin();
    return;
  }


  try {
    const result = await api('/api/oscar-launch', { method: 'POST' });
    if (!result || typeof result.launchUrl !== 'string') {
      throw new Error('Unable to open OSCAR right now.');
    }
    window.open(result.launchUrl, '_blank', 'noopener,noreferrer');
  } catch (err) {
    setMessage(`Unable to open OSCAR: ${err.message}`, true);
  }
}

async function deleteFolder() {
  const folder = document.getElementById('folderName').value.trim();
  if (!folderNameValid(folder)) {
    setMessage('Enter a valid folder name to delete.', true);
    return;
  }

  if (!window.confirm(`Delete all uploaded data for folder "${folder}"?`)) return;

  try {
    await api('/api/files', { method: 'DELETE' });
    resetPreparedState(true);
    setMessage(`Deleted uploaded data for folder "${folder}".`);
  } catch (err) {
    setMessage(`Delete failed: ${err.message}`, true);
  }
}

document.getElementById('loginForm').addEventListener('submit', (event) => {
  event.preventDefault();
  login();
});
document.getElementById('logoutBtn').addEventListener('click', logout);
document.getElementById('directoryInput').addEventListener('change', () => {
  scanAndPrepare();
});
document.getElementById('folderName').addEventListener('change', () => {
  if (document.getElementById('directoryInput').files.length > 0) scanAndPrepare();
});
document.getElementById('startDate').addEventListener('change', () => {
  if (document.getElementById('directoryInput').files.length > 0) scanAndPrepare();
});
document.getElementById('uploadBtn').addEventListener('click', uploadPreparedFiles);
document.getElementById('deleteBtn').addEventListener('click', deleteFolder);
document.getElementById('oscarBtn').addEventListener('click', proceedToOscar);

configureDateInput();
loadRandomBanner(loginBanner);
loadRandomBanner(uploadBanner);
checkSession();
