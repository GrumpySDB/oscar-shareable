const token = sessionStorage.getItem('authToken');
if (!token) {
    window.location.href = '/';
}

const statusMessage = document.getElementById('appMessage');

async function api(path, options = {}) {
    const headers = options.headers || {};
    if (token) headers.Authorization = `Bearer ${token}`;

    if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
            sessionStorage.removeItem('authToken');
            window.location.href = '/';
            return;
        }
        let detail = 'Request failed';
        try {
            const body = await response.json();
            detail = body.error || detail;
        } catch (_err) { }
        throw new Error(detail);
    }
    if (response.status === 204) return null;
    return response.json();
}

document.getElementById('tabUsers').addEventListener('click', () => {
    document.getElementById('tabUsers').classList.add('active');
    document.getElementById('tabInvites').classList.remove('active');
    document.getElementById('usersPanel').classList.add('active');
    document.getElementById('usersPanel').classList.remove('hidden');
    document.getElementById('invitesPanel').classList.remove('active');
    document.getElementById('invitesPanel').classList.add('hidden');
    statusMessage.textContent = '';
    loadUsers();
});

document.getElementById('tabInvites').addEventListener('click', () => {
    document.getElementById('tabInvites').classList.add('active');
    document.getElementById('tabUsers').classList.remove('active');
    document.getElementById('invitesPanel').classList.add('active');
    document.getElementById('invitesPanel').classList.remove('hidden');
    document.getElementById('usersPanel').classList.remove('active');
    document.getElementById('usersPanel').classList.add('hidden');
    statusMessage.textContent = '';
    loadInvites();
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
        await api('/api/logout', { method: 'POST' });
    } catch (e) { }
    sessionStorage.removeItem('authToken');
    window.location.href = '/';
});

async function loadUsers() {
    try {
        const res = await api('/api/admin/users');
        const tbody = document.querySelector('#usersTable tbody');
        tbody.innerHTML = '';

        for (const u of res.users) {
            const tr = document.createElement('tr');

            const tdName = document.createElement('td');
            tdName.textContent = u.username || u.uuid;

            const tdProvider = document.createElement('td');
            tdProvider.textContent = u.provider;

            const tdRole = document.createElement('td');
            tdRole.textContent = u.role;

            const tdActions = document.createElement('td');
            if (u.role !== 'admin') {
                const delBtn = document.createElement('button');
                delBtn.textContent = 'Delete';
                delBtn.className = 'danger';
                delBtn.style.padding = '5px 10px';
                delBtn.style.fontSize = '0.85em';
                delBtn.onclick = () => deleteUser(u.uuid, u.username || u.uuid);
                tdActions.appendChild(delBtn);
            }
            if (u.provider === 'local' && u.role !== 'admin') {
                const resetBtn = document.createElement('button');
                resetBtn.textContent = 'Reset Password';
                resetBtn.className = 'ghost';
                resetBtn.style.padding = '5px 10px';
                resetBtn.style.fontSize = '0.85em';
                resetBtn.style.marginLeft = '10px';
                resetBtn.onclick = () => resetPassword(u.uuid, u.username || u.uuid);
                tdActions.appendChild(resetBtn);
            }

            tr.appendChild(tdName);
            tr.appendChild(tdProvider);
            tr.appendChild(tdRole);
            tr.appendChild(tdActions);
            tbody.appendChild(tr);
        }
    } catch (err) {
        statusMessage.textContent = 'Error loading users: ' + err.message;
    }
}

async function deleteUser(uuid, name) {
    if (!confirm(`Are you sure you want to delete user ${name}? This will permanently wipe all their uploads and OSCAR data.`)) return;
    try {
        await api(`/api/admin/users/${uuid}`, { method: 'DELETE' });
        statusMessage.textContent = `User ${name} deleted successfully.`;
        loadUsers();
    } catch (err) {
        statusMessage.textContent = 'Delete failed: ' + err.message;
    }
}

async function resetPassword(uuid, name) {
    if (!confirm(`Reset anonymous password for ${name}? They will be logged out and need the new password.`)) return;
    try {
        const res = await api(`/api/admin/users/${uuid}/reset-password`, { method: 'POST' });
        prompt(`Password successfully reset for ${name}. Please copy the new password:`, res.new_password);
        statusMessage.textContent = `Password reset for ${name}.`;
    } catch (err) {
        statusMessage.textContent = 'Reset failed: ' + err.message;
    }
}

async function loadInvites() {
    try {
        const res = await api('/api/admin/invites');
        const tbody = document.querySelector('#invitesTable tbody');
        tbody.innerHTML = '';

        for (const inv of res.invites) {
            const tr = document.createElement('tr');

            const tdCode = document.createElement('td');
            tdCode.textContent = inv.code;

            const tdCreator = document.createElement('td');
            // Slice the UUID for brevity
            tdCreator.textContent = inv.created_by_uuid.split('-')[0];

            const tdStatus = document.createElement('td');
            const isExpired = (Date.now() / 1000) > inv.expires_at;
            if (inv.used_by_uuid) {
                tdStatus.textContent = 'Used';
                tdStatus.style.color = 'var(--text-subtle)';
            } else if (isExpired) {
                tdStatus.textContent = 'Expired';
                tdStatus.style.color = 'var(--error-color)';
            } else {
                tdStatus.textContent = 'Valid';
                tdStatus.style.color = 'var(--success-color)';
            }

            const tdExpires = document.createElement('td');
            tdExpires.textContent = new Date(inv.expires_at * 1000).toLocaleString();

            tr.appendChild(tdCode);
            tr.appendChild(tdCreator);
            tr.appendChild(tdStatus);
            tr.appendChild(tdExpires);
            tbody.appendChild(tr);
        }
    } catch (err) {
        statusMessage.textContent = 'Error loading invites: ' + err.message;
    }
}

document.getElementById('generateInviteBtn').addEventListener('click', async () => {
    const days = parseInt(document.getElementById('inviteExpireDays').value, 10) || 7;
    try {
        const res = await api('/api/admin/invites', {
            method: 'POST',
            body: JSON.stringify({ expire_days: days })
        });

        prompt('Generated new invite code! Ready to copy:', res.code);
        statusMessage.textContent = 'Created new invite: ' + res.code;
        loadInvites();
    } catch (err) {
        statusMessage.textContent = 'Error generating invite: ' + err.message;
    }
});

// Init
loadUsers();
