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
        throw new Error('API Request Failed');
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
    const label = labelInput.value.trim();
    generateBtn.disabled = true;
    generateBtn.textContent = 'Creating...';
    try {
        const res = await api('/api/account/api-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label: label || null, scopes: null })
        });
        
        document.getElementById('newApiKeyText').textContent = res.key;
        document.getElementById('newApiKeyModal').classList.remove('hidden');
        labelInput.value = '';
        loadKeys();
    } catch (err) {
        // Handle specific limit error if backend returns JSON
        if (err.message.includes('Limit reached') || err.message.includes('409') || err.message.includes('Maximum 3 keys')) {
            alert('API Key Limit Reached: You can only have up to 3 active API keys at once. Please revoke an old key first.');
        } else {
            // Check if we can extract the error from the response (api helper might need change)
            alert('Failed to create API key. Ensure you have fewer than 3 active keys.');
        }
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = 'Create API Key';
    }
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
