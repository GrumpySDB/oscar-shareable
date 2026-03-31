import { showCursorNotification } from './theme.js';

let token = sessionStorage.getItem('authToken');
if (!token) window.location.href = '/';

async function api(path, options = {}) {
    const headers = options.headers || {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
        if (response.status === 401) {
            sessionStorage.removeItem('authToken');
            window.location.href = '/';
            return;
        }
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'API Request Failed');
    }
    return response.json();
}

const tableBody = document.querySelector('#apiKeysTable tbody');
const generateBtn = document.getElementById('generateApiKeyBtn');
const labelInput = document.getElementById('apiKeyLabel');

async function loadKeys() {
    try {
        tableBody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';
        const res = await api('/api/account/api-keys');
        const keys = res.api_keys || [];
        tableBody.innerHTML = '';
        if (keys.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No active API keys found.</td></tr>';
            return;
        }
        for (const k of keys) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${k.label || '-'}</td>
                <td>${new Date(k.created_at * 1000).toLocaleString()}</td>
                <td>${k.last_used_at ? new Date(k.last_used_at * 1000).toLocaleString() : 'Never'}</td>
                <td><button class="danger-small revoke-trigger-btn" data-id="${k.id}">Revoke</button></td>
            `;
            tableBody.appendChild(tr);
        }
        
        document.querySelectorAll('.revoke-trigger-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.target.getAttribute('data-id');
                showRevokeConfirm(id, e.target);
            });
        });
    } catch (err) {
        tableBody.innerHTML = '<tr><td colspan="4" class="error">Failed to load API keys</td></tr>';
    }
}

let keyToRevoke = null;
let btnToDisable = null;

function showRevokeConfirm(id, btn) {
    keyToRevoke = id;
    btnToDisable = btn;
    document.getElementById('revokeConfirmModal').classList.remove('hidden');
}

document.getElementById('cancelRevokeBtn').addEventListener('click', () => {
    document.getElementById('revokeConfirmModal').classList.add('hidden');
    keyToRevoke = null;
    btnToDisable = null;
});

document.getElementById('confirmRevokeBtn').addEventListener('click', async () => {
    if (!keyToRevoke) return;
    
    const confirmBtn = document.getElementById('confirmRevokeBtn');
    const cancelBtn = document.getElementById('cancelRevokeBtn');
    
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Revoking...';
    cancelBtn.disabled = true;

    try {
        await api(`/api/account/api-keys/${keyToRevoke}`, { method: 'DELETE' });
        document.getElementById('revokeConfirmModal').classList.add('hidden');
        loadKeys();
    } catch (err) {
        alert('Failed to revoke API key');
    } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Revoke Key';
        cancelBtn.disabled = false;
        keyToRevoke = null;
        btnToDisable = null;
    }
});

generateBtn.addEventListener('click', async () => {
    const labelInput = document.getElementById('apiKeyLabel');
    const errorMsg = document.getElementById('apiKeyError');
    const label = labelInput.value.trim();
    
    // Frontend Validation
    if (label) {
        if (label.length > 30) {
            showError("Label is too long (max 30).");
            return;
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(label)) {
            showError("Invalid characters. Use A-Z, 0-9, - and _ only.");
            return;
        }
    }

    function showError(msg) {
        labelInput.classList.add('invalid-input');
        errorMsg.textContent = msg;
        errorMsg.classList.remove('hidden');
        setTimeout(() => labelInput.classList.remove('invalid-input'), 500);
    }

    // Clear previous errors
    labelInput.classList.remove('invalid-input');
    errorMsg.classList.add('hidden');

    generateBtn.disabled = true;
    generateBtn.textContent = 'Creating...';
    try {
        const res = await api('/api/account/api-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label: label || null, scopes: null })
        });
        
        document.getElementById('newApiKeyText').textContent = res.key;
        document.getElementById('newApiKeyFolder').textContent = `api-${res.label}`;
        document.getElementById('newApiKeyModal').classList.remove('hidden');
        labelInput.value = '';
        loadKeys();
    } catch (err) {
        showError(err.message || 'Failed to create API key.');
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = 'Create API Key';
    }
});

// Clear error on type
labelInput.addEventListener('input', () => {
    labelInput.classList.remove('invalid-input');
    document.getElementById('apiKeyError').classList.add('hidden');
});

document.getElementById('closeApiKeyBtn').addEventListener('click', () => {
    document.getElementById('newApiKeyModal').classList.add('hidden');
    document.getElementById('newApiKeyText').textContent = '';
});

const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('authToken');
        window.location.href = '/';
    });
}

const copyApiKeyBtn = document.getElementById('copyApiKey');
if (copyApiKeyBtn) {
    copyApiKeyBtn.addEventListener('click', async (e) => {
        const text = document.getElementById('newApiKeyText').textContent;
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            showCursorNotification(e, 'Copied!');
        } catch (err) {
            console.error('Failed to copy', err);
        }
    });
}

loadKeys();
