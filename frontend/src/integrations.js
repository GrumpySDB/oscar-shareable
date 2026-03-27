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
        tableBody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';
        const res = await api('/api/account/api-keys');
        const keys = res.api_keys || [];
        tableBody.innerHTML = '';
        if (keys.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active API keys found.</td></tr>';
            return;
        }
        for (const k of keys) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${k.id}</td>
                <td>${k.label || '-'}</td>
                <td>${new Date(k.created_at * 1000).toLocaleString()}</td>
                <td>${k.last_used_at ? new Date(k.last_used_at * 1000).toLocaleString() : 'Never'}</td>
                <td><button class="danger-small revoke-btn" data-id="${k.id}">Revoke</button></td>
            `;
            tableBody.appendChild(tr);
        }
        
        document.querySelectorAll('.revoke-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                if (!confirm('Are you sure you want to revoke this API key? This will permanently break any integrations using it.')) return;
                const id = e.target.getAttribute('data-id');
                e.target.disabled = true;
                e.target.textContent = 'Revoking...';
                try {
                    await api(`/api/account/api-keys/${id}`, { method: 'DELETE' });
                    loadKeys();
                } catch (err) {
                    alert('Failed to revoke API key');
                    e.target.disabled = false;
                    e.target.textContent = 'Revoke';
                }
            });
        });
    } catch (err) {
        tableBody.innerHTML = '<tr><td colspan="5" class="error">Failed to load API keys</td></tr>';
    }
}

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
        alert('Failed to create API key');
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
    copyApiKeyBtn.addEventListener('click', async () => {
        const text = document.getElementById('newApiKeyText').textContent;
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            const originalIcon = copyApiKeyBtn.innerHTML;
            copyApiKeyBtn.innerHTML = '<span class="text-content">Copied!</span>';
            setTimeout(() => {
                copyApiKeyBtn.innerHTML = originalIcon;
                // re-insert the text since we overwrote innerHTML
                document.getElementById('newApiKeyText') ? document.getElementById('newApiKeyText').textContent = text : null;
            }, 2000);
        } catch (err) {
            console.error('Failed to copy', err);
        }
    });
}

loadKeys();
