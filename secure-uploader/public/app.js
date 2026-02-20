const REQUIRED_ALWAYS = ['Identification.crc', 'STR.edf'];
const OPTIONAL_ALWAYS = ['Identification.tgt', 'Identification.json', 'journal.nl'];
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_UPLOAD_FILES = 5000;
const CLOUDFLARE_UPLOAD_LIMIT_BYTES = 100 * 1024 * 1024;
const SAFE_BATCH_LIMIT_BYTES = 90 * 1024 * 1024;

let token = sessionStorage.getItem('authToken') || null;
let preparedFiles = [];
let preparedFolder = '';
let selectedDateMs = 0;

const loginCard = document.getElementById('loginCard');
const appCard = document.getElementById('appCard');
const loginError = document.getElementById('loginError');
const summaryCounts = document.getElementById('summaryCounts');
const summaryStatus = document.getElementById('summaryStatus');
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
  } catch (_err) {}
}


function showLogin() {
  loginCard.classList.remove('hidden');
  appCard.classList.add('hidden');
}

function showApp() {
  loginCard.classList.add('hidden');
  appCard.classList.remove('hidden');
}

function setMessage(message, isError = false) {
  summaryStatus.classList.toggle('error-state', Boolean(isError));
  summaryStatus.textContent = message;
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
  const todayIso = today.toISOString().slice(0, 10);
  input.max = todayIso;
  input.min = min.toISOString().slice(0, 10);
  input.value = todayIso;
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

function isRequired(name) {
  return REQUIRED_ALWAYS.includes(name);
}

function isAlwaysIncluded(name) {
  return isRequired(name) || OPTIONAL_ALWAYS.includes(name);
}

function getRelativePath(file) {
  return file.webkitRelativePath || file.name;
}

function getBasename(file) {
  return file.name;
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
    } catch (_err) {}

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
    showApp();
  } catch (_err) {
    token = null;
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
    const result = await api('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    token = result.token;
    sessionStorage.setItem('authToken', token);
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
  sessionStorage.removeItem('authToken');

  if (currentToken) {
    try {
      await fetch('/api/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${currentToken}` },
      });
    } catch (_err) {}
  }

  resetPreparedState(true);
  setMessage('');
  showLogin();
}

function resetPreparedState(clearProgress = false) {
  preparedFiles = [];
  preparedFolder = '';
  selectedDateMs = 0;
  uploadBtn.disabled = true;
  summaryCounts.textContent = '';
  if (clearProgress) {
    progressBar.style.width = '0%';
  }
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

  const selectedDate = new Date(document.getElementById('startDate').value);
  if (Number.isNaN(selectedDate.getTime())) {
    setMessage('Please select a valid start date.', true);
    return;
  }

  const now = Date.now();
  if (selectedDate.getTime() < getSixMonthsAgo(now).getTime() || selectedDate.getTime() > now) {
    setMessage('Start date must be within the past 6 months.', true);
    return;
  }

  let existingNames = [];
  try {
    const data = await api(`/api/folders/${encodeURIComponent(folder)}/files`);
    existingNames = Array.isArray(data.filenames) ? data.filenames : [];
  } catch (err) {
    setMessage(`Unable to load existing files: ${err.message}`, true);
    return;
  }

  const existingSet = new Set(existingNames);
  const requiredBasenames = new Set(files.map((file) => getBasename(file)));

  for (const required of REQUIRED_ALWAYS) {
    if (!requiredBasenames.has(required)) {
      setMessage(`Invalid data: missing required file ${required}.`, true);
      return;
    }
  }

  const eligible = [];
  let skippedExisting = 0;
  let skippedInvalid = 0;

  for (const file of files) {
    if (!validateFile(file, selectedDate.getTime())) {
      skippedInvalid += 1;
      continue;
    }

    const relativePath = getRelativePath(file);
    if (!isAlwaysIncluded(getBasename(file)) && existingSet.has(relativePath)) {
      skippedExisting += 1;
      continue;
    }

    eligible.push(file);
  }

  const skippedTotal = skippedExisting + skippedInvalid;
  if (eligible.length === 0) {
    summaryCounts.innerHTML = [
      `<strong>Valid files to upload:</strong> 0`,
      `<br><strong>Files skipped:</strong> ${skippedTotal}`,
    ].join('');
    setMessage('Invalid or duplicate SD card data detected. Upload is disabled.', true);
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
  selectedDateMs = selectedDate.getTime();
  uploadBtn.disabled = false;

  summaryCounts.innerHTML = [
    `<strong>Valid files to upload:</strong> ${eligible.length}`,
    `<br><strong>Files skipped:</strong> ${skippedTotal}`,
  ].join('');
  setMessage('Resmed SD card data detected.');
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

function uploadBatch({ files, batchIndex, totalBatches, sessionId, totalBytes }) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('folder', preparedFolder);
    form.append('selectedDateMs', String(selectedDateMs));
    form.append('uploadSessionId', sessionId);
    form.append('batchIndex', String(batchIndex));
    form.append('totalBatches', String(totalBatches));
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
      } catch (_err) {}

      if (request.status === 413) {
        message = 'Upload rejected by gateway size limit. Reduce batch size and retry.';
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
    setMessage(`Uploading ${preparedFiles.length} files (${totalMb.toFixed(1)} MB)...`);
  }

  try {
    for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
      const batch = batches[batchIndex];
      await uploadBatch({
        files: batch,
        batchIndex,
        totalBatches: batches.length,
        sessionId,
        totalBytes,
      });
    }

    progressBar.style.width = '100%';
    setMessage('Upload complete.');
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
    await api(`/api/folders/${encodeURIComponent(folder)}`, { method: 'DELETE' });
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
