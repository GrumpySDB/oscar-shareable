const REQUIRED_ALWAYS = ['Identification.crc', 'Identification.tgt', 'STR.edf'];
const ALLOWED_EXTENSIONS = new Set(['.crc', '.tgt', '.edf']);
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

let token = sessionStorage.getItem('authToken') || null;
let preparedFiles = [];
let preparedFolder = '';
let selectedDateMs = 0;

const loginCard = document.getElementById('loginCard');
const appCard = document.getElementById('appCard');
const loginError = document.getElementById('loginError');
const appMessage = document.getElementById('appMessage');
const summary = document.getElementById('summary');
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
  appMessage.style.color = isError ? '#c93d3d' : '#13865b';
  appMessage.textContent = message;
}

function configureDateInput() {
  const input = document.getElementById('startDate');
  const today = new Date();
  const min = new Date(Date.now() - ONE_YEAR_MS);
  input.max = today.toISOString().slice(0, 10);
  input.min = min.toISOString().slice(0, 10);
  input.value = min.toISOString().slice(0, 10);
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

function getRelativePath(file) {
  return file.webkitRelativePath || file.name;
}

function getBasename(file) {
  return file.name;
}

function validateFile(file, startDateMs) {
  const relativePath = getRelativePath(file);
  const extension = relativePath.slice(relativePath.lastIndexOf('.')).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(extension)) return false;
  if (file.size > MAX_FILE_SIZE) return false;

  if (isRequired(getBasename(file))) return true;

  const modified = Number(file.lastModified || 0);
  const now = Date.now();
  const oneYearAgo = now - ONE_YEAR_MS;
  if (modified < oneYearAgo || modified > now) return false;
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
    throw new Error(detail);
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

function logout() {
  token = null;
  sessionStorage.removeItem('authToken');
  preparedFiles = [];
  uploadBtn.disabled = true;
  summary.textContent = '';
  progressBar.style.width = '0%';
  setMessage('');
  showLogin();
}

async function scanAndPrepare() {
  setMessage('');
  summary.textContent = '';
  uploadBtn.disabled = true;
  progressBar.style.width = '0%';

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
  if (selectedDate.getTime() < now - ONE_YEAR_MS || selectedDate.getTime() > now) {
    setMessage('Start date must be within the past year.', true);
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
      setMessage(`Missing required file in selected folder: ${required}`, true);
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
    if (!isRequired(getBasename(file)) && existingSet.has(relativePath)) {
      skippedExisting += 1;
      continue;
    }

    eligible.push(file);
  }

  if (eligible.length === 0) {
    setMessage('No new valid files to upload after filtering.', true);
    return;
  }

  preparedFiles = eligible;
  preparedFolder = folder;
  selectedDateMs = selectedDate.getTime();
  uploadBtn.disabled = false;

  summary.innerHTML = [
    `<strong>Ready:</strong> ${eligible.length} files`,
    `<br><strong>Skipped existing:</strong> ${skippedExisting}`,
    `<br><strong>Skipped invalid:</strong> ${skippedInvalid}`,
  ].join('');
}

function uploadPreparedFiles() {
  if (preparedFiles.length === 0) {
    setMessage('Nothing to upload. Use Scan first.', true);
    return;
  }

  uploadBtn.disabled = true;
  setMessage('Uploading...');

  const form = new FormData();
  form.append('folder', preparedFolder);
  form.append('selectedDateMs', String(selectedDateMs));
  for (const file of preparedFiles) {
    form.append('files', file, getRelativePath(file));
  }

  const request = new XMLHttpRequest();
  request.open('POST', '/api/upload');
  request.setRequestHeader('Authorization', `Bearer ${token}`);

  request.upload.onprogress = (event) => {
    if (!event.lengthComputable) return;
    const percent = Math.round((event.loaded / event.total) * 100);
    progressBar.style.width = `${percent}%`;
  };

  request.onload = () => {
    if (request.status >= 200 && request.status < 300) {
      progressBar.style.width = '100%';
      setMessage('Upload complete.');
      preparedFiles = [];
      uploadBtn.disabled = true;
    } else {
      let message = 'Upload failed';
      try {
        message = JSON.parse(request.responseText).error || message;
      } catch (_err) {}
      setMessage(message, true);
      uploadBtn.disabled = false;
    }
  };

  request.onerror = () => {
    setMessage('Network error during upload.', true);
    uploadBtn.disabled = false;
  };

  request.send(form);
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
    window.location.assign(result.launchUrl);
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
document.getElementById('scanBtn').addEventListener('click', scanAndPrepare);
document.getElementById('uploadBtn').addEventListener('click', uploadPreparedFiles);
document.getElementById('deleteBtn').addEventListener('click', deleteFolder);
document.getElementById('oscarBtn').addEventListener('click', proceedToOscar);

configureDateInput();
loadRandomBanner(loginBanner);
loadRandomBanner(uploadBanner);
checkSession();
