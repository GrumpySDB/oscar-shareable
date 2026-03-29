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

const deleteConfirmOverlay = document.getElementById('deleteConfirmOverlay');
const closeDeleteModalBtn = document.getElementById('closeDeleteModalBtn');
const confirmDeleteData = document.getElementById('confirmDeleteData');
const confirmDeleteAccount = document.getElementById('confirmDeleteAccount');
const finalDeleteBtn = document.getElementById('finalDeleteBtn');
const footerActions = document.querySelector('.footer-actions');

const urlParams = new URLSearchParams(window.location.search);

const errParam = urlParams.get('error');
if (errParam && loginError) {
  loginError.textContent = errParam;
  window.history.replaceState({}, document.title, window.location.pathname);
}

const loginTokenParam = urlParams.get('login_token');
if (loginTokenParam) {
  token = loginTokenParam;
  sessionStorage.setItem('authToken', token);
  window.history.replaceState({}, document.title, window.location.pathname);
}

const legacyInviteCode = urlParams.get('invite');
if (legacyInviteCode) {
  window.location.href = `/invite?code=${encodeURIComponent(legacyInviteCode)}`;
}

let isTimeoutFlow = false;
const timeoutParam = urlParams.get('timeout');
if (timeoutParam) {
  isTimeoutFlow = true;
  window.history.replaceState({}, document.title, window.location.pathname);
}

function handleShareLinkRouting() {
  const path = window.location.pathname;
  if (path.startsWith('/share/')) {
    const tokenPart = path.replace('/share/', '').trim();
    if (tokenPart) {
      sessionStorage.setItem('pendingShareLaunchToken', tokenPart);
      sessionStorage.setItem('pendingShareLaunchTimestamp', Date.now().toString());
      window.history.replaceState({}, document.title, '/');
    }
  }
}
handleShareLinkRouting();

function enforceShareTokenExpiry() {
  const timestamp = sessionStorage.getItem('pendingShareLaunchTimestamp');
  if (timestamp) {
    const ageMs = Date.now() - Number(timestamp);
    const twoHours = 2 * 60 * 60 * 1000;
    if (ageMs > twoHours) {
      sessionStorage.removeItem('pendingShareLaunchToken');
      sessionStorage.removeItem('pendingShareLaunchTimestamp');
    }
  }
}
enforceShareTokenExpiry();

const loginBanner = document.getElementById('loginBanner');
const uploadBanner = document.getElementById('uploadBanner');

async function loadRandomBanner(imageElement) {
  if (!imageElement) return;

  try {
    const response = await fetch('/api/banner-images', { cache: 'no-store' });
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
  footerActions?.classList.add('hidden');

  const warning = document.getElementById('shareLinkWarning');
  if (warning) {
    if (sessionStorage.getItem('pendingShareLaunchToken')) {
      warning.classList.remove('hidden');
    } else {
      warning.classList.add('hidden');
    }
  }
}

function showApp() {
  loginCard.classList.add('hidden');
  appCard.classList.remove('hidden');
  footerActions?.classList.remove('hidden');

  const welcomeBox = document.getElementById('welcomeBox');
  const welcomeUsername = document.getElementById('welcomeUsername');
  if (welcomeBox && welcomeUsername) {
    welcomeUsername.textContent = currentUsername;
    welcomeBox.classList.remove('hidden');
  }
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
  const minDate = getSixMonthsAgo();
  minDate.setDate(minDate.getDate() + 1);

  const defaultDate = new Date(today);
  defaultDate.setDate(defaultDate.getDate() - 7);

  if (typeof flatpickr === 'function') {
    try {
      flatpickr(input, {
        dateFormat: "Y-m-d",
        maxDate: today,
        minDate: minDate,
        defaultDate: defaultDate,
        disableMobile: "true",
        onChange: function (selectedDates, dateStr, instance) {
          if (document.getElementById('directoryInput').files.length > 0) scanAndPrepare();
        }
      });
    } catch (e) {
      console.error("Flatpickr init failed:", e);
      setupBasicDateInput(input, today, minDate, defaultDate);
    }
  } else {
    setupBasicDateInput(input, today, minDate, defaultDate);
  }
}

function setupBasicDateInput(input, today, minDate, defaultDate) {
  input.type = 'date';
  input.max = today.toISOString().slice(0, 10);
  input.min = minDate.toISOString().slice(0, 10);
  input.value = defaultDate.toISOString().slice(0, 10);
  input.readOnly = false;
  input.addEventListener('change', () => {
    if (document.getElementById('directoryInput').files.length > 0) scanAndPrepare();
  });
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
  const nameLower = name.toLowerCase();
  return REQUIRED_ALWAYS.some(r => r.toLowerCase() === nameLower);
}

function isAlwaysIncluded(name) {
  const nameLower = name.toLowerCase();
  return isRequired(name) || OPTIONAL_ALWAYS.some(o => o.toLowerCase() === nameLower);
}

function getRelativePath(file) {
  const rawPath = String(file?.webkitRelativePath || file?.name || '').trim();
  const slashNormalized = rawPath.replace(/\\/g, '/');
  return slashNormalized.replace(/^\.\//, '');
}

function getStandardizedRelativePath(file) {
  let relativePath = getRelativePath(file);
  if (preparedUploadType === 'sdcard') {
    const parts = relativePath.split('/');
    if (parts.length > 1) {
      parts[0] = 'SD_CARD';
      return parts.join('/');
    }
  }
  return relativePath;
}

function getBasename(file) {
  const relativePath = getRelativePath(file);
  const segments = relativePath.split('/').filter(Boolean);
  if (segments.length > 0) {
    return segments[segments.length - 1];
  }
  return String(file?.name || '').split(/[\\/]/).pop() || '';
}

async function getAllFilesFromEntries(entries) {
  const files = [];
  async function process(entry) {
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      // Preserve the virtual path for later getRelativePath calls
      // webkitRelativePath is normally read-only on File, so we'll 
      // rely on a custom property if needed, but for drag-and-drop
      // the relative path is typically what we want to reconstruct.
      Object.defineProperty(file, 'webkitRelativePath', {
        value: entry.fullPath.replace(/^\//, ''),
        writable: false
      });
      files.push(file);
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const subEntries = await new Promise((resolve, reject) => {
        let allEntries = [];
        function readDir() {
          reader.readEntries((results) => {
            if (results.length === 0) {
              resolve(allEntries);
            } else {
              allEntries = allEntries.concat(results);
              readDir();
            }
          }, reject);
        }
        readDir();
      });
      for (const subEntry of subEntries) {
        await process(subEntry);
      }
    }
  }
  for (const entry of entries) {
    await process(entry);
  }
  return files;
}

function isTinfoilHatModeEnabled() {
  return document.getElementById('encryptionToggle')?.checked === true;
}

function isSpo2Filename(name) {
  if (typeof name !== 'string') return false;
  const trimmed = name.trim();
  return /^.+\.spo2$/i.test(trimmed);
}

function is14DigitOximetryFilename(name) {
  if (typeof name !== 'string') return false;
  const trimmed = name.trim();
  return /^\d{14}$/.test(trimmed);
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
  const response = await fetch(path, { ...options, headers, cache: 'no-store' });
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

async function proceedToAppFlow() {
  const pendingToken = sessionStorage.getItem('pendingShareLaunchToken');
  if (pendingToken) {
    const overlay = document.getElementById('oscarLoadingOverlay');
    const mainAppCard = document.getElementById('appCard');
    const loginCardMain = document.getElementById('loginCard');

    if (mainAppCard) mainAppCard.classList.add('hidden');
    if (loginCardMain) loginCardMain.classList.add('hidden');
    if (overlay) overlay.classList.remove('hidden');

    try {
      const result = await api(`/api/share/${pendingToken}`, { method: 'GET' });
      if (!result || typeof result.launchUrl !== 'string') {
        throw new Error('Unable to open shared profile right now.');
      }

      sessionStorage.setItem('lastShareLaunchToken', pendingToken);
      sessionStorage.removeItem('pendingShareLaunchToken');
      window.history.replaceState({}, document.title, '/?timeout=1');

      setTimeout(() => {
        window.location.href = result.launchUrl;
      }, 3000);
    } catch (err) {
      if (overlay) overlay.classList.add('hidden');
      if (mainAppCard) mainAppCard.classList.remove('hidden');
      setMessage(`Unable to open shared profile: ${err.message}`, true);
    }
  } else {
    // If we're entering the normal app flow, clear any stale share tokens
    sessionStorage.removeItem('lastShareLaunchToken');
    showApp();
  }
}

function showShareModal() {
  const overlay = document.getElementById('genLinkOverlay');
  if (overlay) overlay.classList.remove('hidden');
}

function hideShareModal() {
  const overlay = document.getElementById('genLinkOverlay');
  if (overlay) overlay.classList.add('hidden');
}

async function checkSession() {
  try {
    const result = await api('/api/session');

    if (result.authenticated !== true) {
      throw new Error('Not authenticated');
    }

    const role = result.role || getRoleFromToken(token);
    if (role === 'admin') {
      window.location.href = '/admin';
      return;
    }

    currentUsername = result.username || getUsernameFromToken(token);

    if (isTimeoutFlow) {
      const overlay = document.getElementById('timeoutOverlay');
      const mainAppCard = document.getElementById('appCard');
      const loginCardMain = document.getElementById('loginCard');
      if (mainAppCard) mainAppCard.classList.add('hidden');
      if (loginCardMain) loginCardMain.classList.add('hidden');
      if (footerActions) footerActions.classList.add('hidden');
      if (overlay) {
        overlay.classList.remove('hidden');
      }
      isTimeoutFlow = false;
    } else {
      proceedToAppFlow();
    }
  } catch (_err) {
    if (isTimeoutFlow) {
      loginError.textContent = 'Your session has timed out. Please log in again.';
    }

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
    proceedToAppFlow();
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
  sessionStorage.removeItem('pendingShareLaunchToken');
  sessionStorage.removeItem('lastShareLaunchToken');

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
  if (preparedUploadType === 'sdcard') {
    const uploadedFolder = preparedSourceRootFolder || currentUsername;
    return `Upload Complete.  Import your SD Card data from /config/Documents/SDCARD/${uploadedFolder}`;
  }

  return `Upload Complete.  Import your Oximetry data from /config/Documents/SDCARD/Oximetry`;
}

async function scanAndPrepare(manualFiles = null) {
  resetPreparedState(true);

  let files = manualFiles;
  if (!files) {
    files = Array.from(document.getElementById('directoryInput').files || []);
  }

  if (files.length === 0) {
    setMessage('Please choose an SD card folder first.', true);
    return;
  }

  const selectedRootFolder = getSelectedRootFolderName(files);
  const selectedDate = new Date(document.getElementById('startDate').value);

  let existingNames = [];
  try {
    const data = await api(`/api/files?_=${Date.now()}`);
    existingNames = Array.isArray(data.filenames) ? data.filenames : [];
  } catch (err) {
    setMessage(`Unable to load existing files: ${err.message}`, true);
    return;
  }

  const existingSet = new Set(existingNames);
  const hasSpo2 = files.some((file) => isSpo2Filename(getBasename(file)));
  const dbO2Files = files.filter((file) => getBasename(file).toLowerCase() === 'db_o2.db');
  const fourteenDigitFiles = files.filter((file) => is14DigitOximetryFilename(getBasename(file)) && file.size < 250 * 1024);
  const isWellueOximetry = dbO2Files.length > 0 || fourteenDigitFiles.length > 0;
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
  preparedUploadType = uploadType;

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

    const basenamesLower = new Set(files.map((file) => getBasename(file).toLowerCase()));
    
    const isResMed = basenamesLower.has('str.edf') || basenamesLower.has('identification.crc') || basenamesLower.has('identification.tgt');
    const isPhilips = basenamesLower.has('p-series') || basenamesLower.has('prop.txt') || basenamesLower.has('properties.xml');

    if (!isResMed && !isPhilips) {
       setMessage('Unrecognized SD card data format. Only ResMed and Philips data are supported.', true);
       return;
    }

    if (isResMed) {
      for (const required of REQUIRED_ALWAYS) {
        if (!basenamesLower.has(required.toLowerCase())) {
          setMessage(`Invalid ResMed data: missing required file ${required}.`, true);
          return;
        }
      }
    }
  }

  let eligible = [];
  let skippedExisting = 0;
  let skippedInvalid = 0;

  for (const file of files) {
    const relativePath = getStandardizedRelativePath(file);
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

    if (uploadType === 'wellue-spo2' && is14DigitOximetryFilename(basename) && file.size < 250 * 1024) {
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

  const checkPayload = {
    deviceId: null,
    files: eligible.map(f => ({
      path: getStandardizedRelativePath(f),
      size: f.size,
      md5: null
    }))
  };

  if (eligible.length > 0) {
    try {
      const checkRes = await api('/api/upload/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(checkPayload)
      });
      
      const statusMap = new Map();
      if (checkRes && checkRes.status) {
        checkRes.status.forEach(s => statusMap.set(s.path, s.action));
      }

      const finalEligible = [];
      let serverSkipped = 0;
      for (const f of eligible) {
         if (statusMap.get(getStandardizedRelativePath(f)) === 'UPLOAD') {
            finalEligible.push(f);
         } else {
            serverSkipped += 1;
         }
      }
      
      // We already skipped some locally via existingSet, but if the server
      // skipped more, we add that to skippedExisting
      if (serverSkipped > 0) {
          // Because existingSet was loaded at the beginning, the server might have caught
          // duplicates we missed, or it might just overlap. Just use serverSkipped + local duplicates.
          // Wait, if existingSet caught it, it wasn't in list anyway. So we just add serverSkipped.
          skippedExisting += serverSkipped;
      }
      eligible = finalEligible;
    } catch(err) {
       console.error("Deduplication check error:", err);
    }
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
  preparedSourceRootFolder = uploadType === 'sdcard' ? 'SD_CARD' : selectedRootFolder;
  selectedDateMs = selectedDate.getTime();
  preparedUploadType = uploadType;
  preparedWellueDbParents = uploadType === 'wellue-spo2' ? wellueDbParents : [];
  uploadBtn.disabled = false;

  const basenamesLower = new Set(preparedFiles.map((file) => getBasename(file).toLowerCase()));
  const isResMed = basenamesLower.has('str.edf') || basenamesLower.has('identification.crc') || basenamesLower.has('identification.tgt');
  const isPhilips = basenamesLower.has('p-series') || basenamesLower.has('prop.txt') || basenamesLower.has('properties.xml');

  let detectionMessage = '';
  if (uploadType === 'spo2') {
    detectionMessage = 'SPO2 Data Detected';
  } else if (uploadType === 'wellue-spo2') {
    detectionMessage = 'Wellue/Viatom SPO2 Data Detected';
  } else if (isPhilips) {
    detectionMessage = 'Philips SD card data detected.';
  } else if (isResMed) {
    detectionMessage = 'Resmed SD card data detected.';
  } else {
    detectionMessage = 'SD card data detected.'; // Fallback
  }

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
    const relativePath = getStandardizedRelativePath(file);

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

function uploadBatch({ files, batchIndex, totalBatches, sessionId, totalBytes, totalFiles, tinfoilHatMode, encryptionEnvelope }) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('selectedDateMs', String(selectedDateMs));
    form.append('uploadType', preparedUploadType);
    if (preparedUploadType === 'wellue-spo2' && preparedWellueDbParents.length > 0) {
      form.append('wellueDbParents', JSON.stringify(preparedWellueDbParents));
    }
    form.append('uploadSessionId', sessionId);
    form.append('batchIndex', String(batchIndex));
    form.append('totalBatches', String(totalBatches));
    form.append('totalFiles', String(totalFiles));
    form.append('totalBytes', String(totalBytes));
    form.append('tinfoilHatMode', tinfoilHatMode ? 'true' : 'false');
    if (tinfoilHatMode && encryptionEnvelope) {
      form.append('encryptionEnvelope', JSON.stringify(encryptionEnvelope));
    }
    for (const file of files) {
      let relativePath = getStandardizedRelativePath(file);
      if (preparedUploadType === 'spo2') {
        relativePath = `Oximetry/${getBasename(file)}`;
      } else if (preparedUploadType === 'wellue-spo2') {
        const basename = getBasename(file);
        if (is14DigitOximetryFilename(basename)) {
          relativePath = `Oximetry/${basename}`;
        } else {
          const parts = relativePath.split('/');
          const fileName = parts[parts.length - 1] || '';
          const directFolder = parts.length >= 2 ? parts[parts.length - 2] : '';
          relativePath = `Oximetry/${directFolder}/${fileName}`;
        }
      }
      form.append('files', file, relativePath);
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
    setMessage(`Selected files total ${totalMb.toFixed(1)} MB, above the 100 MB network threshold. Upload will run in ${batches.length} batches.`);
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

      let attempt = 0;
      let success = false;
      let lastError = null;

      while (attempt < 3 && !success) {
        if (attempt > 0) {
          const delay = 1000 * Math.pow(2, attempt);
          setMessage(`Interruption detected. Retrying batch ${batchIndex + 1}/${batches.length} (Attempt ${attempt + 1}/3)... waiting ${delay / 1000}s`);
          await new Promise(r => setTimeout(r, delay));
        } else {
          setMessage(`Starting upload of batch ${batchIndex + 1}/${batches.length}...`);
        }

        try {
          await uploadBatch({
            files: filesToUpload,
            batchIndex,
            totalBatches: batches.length,
            sessionId,
            totalBytes,
            totalFiles: preparedFiles.length,
            tinfoilHatMode: tinfoilHatModeEnabled,
            encryptionEnvelope,
          });
          success = true;
        } catch (error) {
          lastError = error;
          // Abort retries for deterministic rule-based failures (limits, validation)
          if (error.message.includes('exceeds') || error.message.includes('rejected')) {
            break;
          }
          console.warn("Batch failed on attempt:", batchIndex + 1, attempt + 1, error.message);
          attempt += 1;
        }
      }

      if (!success) {
        throw new Error(lastError?.message || `Failed to definitively upload batch ${batchIndex + 1} after 3 attempts. Upload aborted.`);
      }
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

  const overlay = document.getElementById('oscarLoadingOverlay');
  const mainAppCard = document.getElementById('appCard');
  const timeoutOverlay = document.getElementById('timeoutOverlay');

  if (mainAppCard) mainAppCard.classList.add('hidden');
  if (footerActions) footerActions.classList.add('hidden');
  if (timeoutOverlay) timeoutOverlay.classList.add('hidden');
  if (overlay) overlay.classList.remove('hidden');

  try {
    // Only use a share token if one was explicitly pending for this specific flow.
    // We should NOT fall back to lastShareLaunchToken here, as that is only for UI badges/persistence
    // of an already-launched shared session.
    const pendingShareToken = sessionStorage.getItem('pendingShareLaunchToken');
    const lastShareToken = sessionStorage.getItem('lastShareLaunchToken');
    const shareToken = pendingShareToken || lastShareToken;
    
    if (!shareToken) {
      // Ensure we clear any legacy share tokens when performing a personal launch
      sessionStorage.removeItem('lastShareLaunchToken');
    }
    const endpoint = shareToken ? `/api/share/${shareToken}` : '/api/oscar-launch';
    const method = shareToken ? 'GET' : 'POST';
    const result = await api(endpoint, { method });

    if (!result || typeof result.launchUrl !== 'string') {
      throw new Error('Unable to open OSCAR right now.');
    }

    if (shareToken) {
      sessionStorage.setItem('lastShareLaunchToken', shareToken);
      sessionStorage.removeItem('pendingShareLaunchToken');
    }
    window.history.replaceState({}, document.title, '/?timeout=1');

    // Hold the loading screen for 3 seconds to let VNC boot fully
    setTimeout(() => {
      window.location.href = result.launchUrl;
    }, 3000);

  } catch (err) {
    if (overlay) overlay.classList.add('hidden');

    if (err.status === 401) {
      // Hide timeout overlay if it was showing
      document.getElementById('timeoutOverlay')?.classList.add('hidden');

      // Remove ?timeout=1 from URL to prevent looping
      const url = new URL(window.location.href);
      if (url.searchParams.has('timeout')) {
        url.searchParams.delete('timeout');
        window.history.replaceState({}, document.title, url.pathname + url.search);
      }

      // Show uploader window
      appCard.classList.remove('hidden');
      const timeoutOverlay = document.getElementById('timeoutOverlay');
      if (timeoutOverlay) {
        timeoutOverlay.classList.remove('hidden');
        const msgPara = timeoutOverlay.querySelector('p');
        if (msgPara) msgPara.textContent = 'Login timeout, redirecting you back to the login screen...';

        const btn = document.getElementById('recreateSessionBtn');
        if (btn) btn.style.display = 'none';

        setTimeout(() => {
          timeoutOverlay.classList.add('hidden');
          logout();
        }, 3000);
      }
      return;
    }

    if (mainAppCard) mainAppCard.classList.remove('hidden');
    setMessage(`Unable to open OSCAR: ${err.message}`, true);
  }
}

function showDeleteModal() {
  if (deleteConfirmOverlay) deleteConfirmOverlay.classList.remove('hidden');
}

function hideDeleteModal() {
  if (deleteConfirmOverlay) {
    deleteConfirmOverlay.classList.add('hidden');
    confirmDeleteData.checked = false;
    confirmDeleteAccount.checked = false;
    confirmDeleteData.disabled = false;
    finalDeleteBtn.disabled = true;
  }
}

function handleToggleChanges() {
  if (confirmDeleteAccount.checked) {
    confirmDeleteData.checked = true;
    confirmDeleteData.disabled = true;
  } else {
    confirmDeleteData.disabled = false;
  }
  finalDeleteBtn.disabled = !(confirmDeleteData.checked || confirmDeleteAccount.checked);
}

async function handleFinalDeletion() {
  const accountDelete = confirmDeleteAccount.checked;
  const originalFinalText = finalDeleteBtn.textContent;

  try {
    finalDeleteBtn.disabled = true;
    finalDeleteBtn.textContent = 'Deleting...';

    if (accountDelete) {
      await api('/api/account', { method: 'DELETE' });
      hideDeleteModal();
      setMessage('Your account and all data have been deleted. Logging out...');
      setTimeout(() => logout(), 2500);
    } else if (confirmDeleteData.checked) {
      await api('/api/files', { method: 'DELETE' });
      resetPreparedState(true);
      hideDeleteModal();
      setMessage('Your uploaded data has been deleted.');
    }
  } catch (err) {
    setMessage(`Deletion failed: ${err.message}`, true);
    finalDeleteBtn.disabled = false;
    finalDeleteBtn.textContent = originalFinalText;
  }
}

// --- Share Link Logic ---

async function handleGenerateShareLink() {
  const genBtn = document.getElementById('genLinkBtn');
  if (!genBtn) return;
  const ogText = genBtn.innerText;
  try {
    genBtn.innerText = 'Generating...';
    genBtn.disabled = true;

    const result = await api('/api/share-links', { method: 'POST' });
    const shareUrl = `${window.location.origin}/share/${result.token}`;

    const output = document.getElementById('genLinkOutputSpan');
    if (output) output.textContent = shareUrl;

    showShareModal();
    setMessage('');
  } catch (err) {
    setMessage(`Failed to generate link: ${err.message}`, true);
  } finally {
    genBtn.innerText = ogText;
    genBtn.disabled = false;
  }
}

const mainGenBtn = document.getElementById('genLinkBtn');
if (mainGenBtn) mainGenBtn.addEventListener('click', handleGenerateShareLink);

const copyBtn = document.getElementById('copyGenLinkBtn');
if (copyBtn) {
  copyBtn.addEventListener('click', () => {
    const span = document.getElementById('genLinkOutputSpan');
    if (span) {
      navigator.clipboard.writeText(span.textContent);

      const feedback = document.getElementById('genLinkCopyFeedback');
      if (feedback) {
        feedback.classList.add('visible');
        setTimeout(() => {
          feedback.classList.remove('visible');
        }, 2000);
      }
    }
  });
}

const closeGenLinkBtn = document.getElementById('closeGenLinkBtn');
if (closeGenLinkBtn) {
  closeGenLinkBtn.addEventListener('click', hideShareModal);
}

const genLinkOverlay = document.getElementById('genLinkOverlay');
if (genLinkOverlay) {
  genLinkOverlay.addEventListener('click', (e) => {
    if (e.target === genLinkOverlay) hideShareModal();
  });
}

// --- Drag and Drop Logic ---

const dragOverlay = document.getElementById('dragOverlay');
let dragCounter = 0;

function showDrag() {
  dragOverlay?.classList.remove('hidden');
  document.body.classList.add('drag-active');
}

function hideDrag() {
  dragOverlay?.classList.add('hidden');
  document.body.classList.remove('drag-active');
}

window.addEventListener('dragenter', (e) => {
  e.preventDefault();
  dragCounter++;
  if (dragCounter === 1) showDrag();
});

window.addEventListener('dragover', (e) => {
  e.preventDefault();
});

window.addEventListener('dragleave', (e) => {
  e.preventDefault();
  dragCounter--;
  if (dragCounter === 0) hideDrag();
});

window.addEventListener('drop', async (e) => {
  e.preventDefault();
  dragCounter = 0;
  hideDrag();

  const items = e.dataTransfer.items;
  if (!items) return;

  setMessage('Processing dropped items...');
  const entries = Array.from(items)
    .map(item => item.webkitGetAsEntry())
    .filter(Boolean);

  try {
    const droppedFiles = await getAllFilesFromEntries(entries);
    if (droppedFiles.length > 0) {
      scanAndPrepare(droppedFiles);
    } else {
      setMessage('No files found in dropped items.', true);
    }
  } catch (err) {
    setMessage(`Error processing dropped items: ${err.message}`, true);
  }
});

document.getElementById('loginForm').addEventListener('submit', (event) => {
  event.preventDefault();
  login();
});

document.getElementById('logoutBtn').addEventListener('click', logout);
document.getElementById('directoryInput').addEventListener('click', () => {
  setMessage('Scanning folder, please wait...');
});
document.getElementById('directoryInput').addEventListener('change', () => {
  scanAndPrepare();
});
document.getElementById('uploadBtn').addEventListener('click', uploadPreparedFiles);
document.getElementById('deleteBtn').addEventListener('click', showDeleteModal);
closeDeleteModalBtn?.addEventListener('click', hideDeleteModal);
confirmDeleteData?.addEventListener('change', handleToggleChanges);
confirmDeleteAccount?.addEventListener('change', handleToggleChanges);
finalDeleteBtn?.addEventListener('click', handleFinalDeletion);

deleteConfirmOverlay?.addEventListener('click', (e) => {
  if (e.target === deleteConfirmOverlay) hideDeleteModal();
});

document.getElementById('oscarBtn').addEventListener('click', proceedToOscar);
document.getElementById('recreateSessionBtn')?.addEventListener('click', proceedToOscar);
document.getElementById('backToUploaderBtn')?.addEventListener('click', () => {
  sessionStorage.removeItem('pendingShareLaunchToken');
  sessionStorage.removeItem('pendingShareLaunchTimestamp');
  sessionStorage.removeItem('lastShareLaunchToken');
  const overlay = document.getElementById('timeoutOverlay');
  if (overlay) overlay.classList.add('hidden');

  // Remove ?timeout=1 from URL to prevent looping
  const url = new URL(window.location.href);
  if (url.searchParams.has('timeout')) {
    url.searchParams.delete('timeout');
    window.history.replaceState({}, document.title, url.pathname + url.search);
  }

  checkSession(); // Re-check session to update UI for regular user
});
document.getElementById('timeoutLogoutBtn')?.addEventListener('click', () => {
  document.getElementById('timeoutOverlay')?.classList.add('hidden');
  logout();
});

// Safe initialization sequence
async function initApp() {
  // 1. Always try to load banners first
  try { await loadRandomBanner(loginBanner); } catch (e) { console.error("Banner load failed:", e); }
  try { await loadRandomBanner(uploadBanner); } catch (e) { console.error("Banner load failed:", e); }

  // 2. Auth/Session check
  try { await checkSession(); } catch (e) { console.error("Session check failed:", e); }

  // 3. UI Components
  try { configureDateInput(); } catch (e) { console.error("Date input config failed:", e); }
}

initApp();
