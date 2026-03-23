const token = sessionStorage.getItem('authToken');
// Session is now also verified server-side before this page is served.
// The api() helper will use the token if present, or fallback to the secure cookie.

const statusMessage = document.getElementById('appMessage');

// State trackers for bulk actions
let usersStatus = [];
let invitesStatus = [];
let logsStatus = [];
let logsPage = 0;
let logsPerPage = 50;
let totalLogs = 0;

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

// Tab Switching
document.getElementById('tabUsers').addEventListener('click', () => {
    document.getElementById('tabUsers').classList.add('active');
    document.getElementById('tabInvites').classList.remove('active');
    document.getElementById('tabLogs').classList.remove('active');
    document.getElementById('usersPanel').classList.add('active');
    document.getElementById('invitesPanel').classList.remove('active');
    document.getElementById('logsPanel').classList.remove('active');
    statusMessage.textContent = '';
    loadUsers();
});

document.getElementById('tabInvites').addEventListener('click', () => {
    document.getElementById('tabInvites').classList.add('active');
    document.getElementById('tabUsers').classList.remove('active');
    document.getElementById('tabLogs').classList.remove('active');
    document.getElementById('invitesPanel').classList.add('active');
    document.getElementById('usersPanel').classList.remove('active');
    document.getElementById('logsPanel').classList.remove('active');
    statusMessage.textContent = '';
    loadInvites();
});

document.getElementById('tabLogs').addEventListener('click', () => {
    document.getElementById('tabLogs').classList.add('active');
    document.getElementById('tabUsers').classList.remove('active');
    document.getElementById('tabInvites').classList.remove('active');
    document.getElementById('logsPanel').classList.add('active');
    document.getElementById('usersPanel').classList.remove('active');
    document.getElementById('invitesPanel').classList.remove('active');
    statusMessage.textContent = '';
    loadAuditLogs();
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
        await api('/api/logout', { method: 'POST' });
    } catch (e) { }
    sessionStorage.removeItem('authToken');
    window.location.href = '/';
});

// Format Date
function formatDate(timestamp) {
    if (!timestamp) return 'Never';
    return new Date(timestamp * 1000).toLocaleString();
}

// --- USERS ---
async function loadUsers() {
    try {
        const res = await api('/api/admin/users');
        usersStatus = res.users;
        renderUsers();
    } catch (err) {
        statusMessage.textContent = 'Error loading users: ' + err.message;
    }
}

function renderUsers() {
    const tbody = document.querySelector('#usersTable tbody');
    tbody.replaceChildren();
    const filter = document.getElementById('userSearch').value.toLowerCase();

    document.getElementById('userSelectAll').checked = false;
    updateUserBulkActions();

    for (const u of usersStatus) {
        // Search filter
        const textToSearch = `${u.username || ''} ${u.uuid} ${u.provider} ${u.role}`.toLowerCase();
        if (filter && !textToSearch.includes(filter)) continue;

        const tr = document.createElement('tr');

        // Checkbox
        const tdCheck = document.createElement('td');
        tdCheck.className = 'col-checkbox';
        if (u.role !== 'admin') {
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'userRowCheck';
            cb.dataset.uuid = u.uuid;
            cb.dataset.name = u.username || u.uuid;
            cb.dataset.provider = u.provider;
            cb.addEventListener('change', updateUserBulkActions);
            tdCheck.appendChild(cb);
        }
        tr.appendChild(tdCheck);

        const tdName = document.createElement('td');
        tdName.textContent = u.username || u.uuid;

        const tdProvider = document.createElement('td');
        tdProvider.textContent = u.provider;

        const tdRole = document.createElement('td');
        tdRole.textContent = u.role;

        const tdCreated = document.createElement('td');
        tdCreated.textContent = formatDate(u.created_at);
        tdCreated.className = 'subtle';

        const tdAccessed = document.createElement('td');
        tdAccessed.textContent = formatDate(u.last_accessed_at);
        tdAccessed.className = 'subtle';

        tr.appendChild(tdName);
        tr.appendChild(tdProvider);
        tr.appendChild(tdRole);
        tr.appendChild(tdCreated);
        tr.appendChild(tdAccessed);
        tbody.appendChild(tr);
    }
}

document.getElementById('userSearch').addEventListener('input', renderUsers);

document.getElementById('userSelectAll').addEventListener('change', (e) => {
    const isChecked = e.target.checked;
    document.querySelectorAll('.userRowCheck').forEach(cb => {
        cb.checked = isChecked;
    });
    updateUserBulkActions();
});

function updateUserBulkActions() {
    const checked = document.querySelectorAll('.userRowCheck:checked');
    const deleteBtn = document.getElementById('bulkDeleteBtn');
    const resetBtn = document.getElementById('bulkResetBtn');

    deleteBtn.disabled = checked.length === 0;

    // Reset password is only allowed for EXACTLY ONE Local User
    if (checked.length === 1 && checked[0].dataset.provider === 'local') {
        resetBtn.disabled = false;
    } else {
        resetBtn.disabled = true;
    }
}

// Bulk Delete Users
document.getElementById('bulkDeleteBtn').addEventListener('click', async () => {
    const checked = Array.from(document.querySelectorAll('.userRowCheck:checked'));
    if (checked.length === 0) return;

    if (!confirm(`Permanently delete ${checked.length} selected users? This will wipe all their uploads and OSCAR data.`)) return;

    statusMessage.textContent = 'Deleting users...';
    try {
        await Promise.all(checked.map(cb => api(`/api/admin/users/${cb.dataset.uuid}`, { method: 'DELETE' })));
        statusMessage.textContent = `Successfully deleted ${checked.length} user(s).`;
        loadUsers();
    } catch (err) {
        statusMessage.textContent = 'Error during bulk deletion: ' + err.message;
        loadUsers(); // reload to get actual state
    }
});

// Modal Logic
const resetCredsModal = document.getElementById('resetCredsModal');
const resetCredsName = document.getElementById('resetCredsName');
const resetPasswordText = document.getElementById('resetPasswordText');
const resetRecoveryText = document.getElementById('resetRecoveryText');
const closeResetCredsBtn = document.getElementById('closeResetCredsBtn');

let passwordCopied = false;

function setupCopy(elementId, textElementId, onCopyCallback) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.addEventListener('click', async () => {
        const text = document.getElementById(textElementId).textContent;
        try {
            await navigator.clipboard.writeText(text);
            el.classList.add('copied');
            setTimeout(() => el.classList.remove('copied'), 2000);
            if (onCopyCallback) onCopyCallback();
        } catch (err) {
            console.error('Copy failed', err);
        }
    });
}

function checkCanClose() {
    if (passwordCopied) {
        closeResetCredsBtn.disabled = false;
        closeResetCredsBtn.classList.add('can-close');
    }
}

setupCopy('copyResetPassword', 'resetPasswordText', () => {
    passwordCopied = true;
    checkCanClose();
});
setupCopy('copyResetRecovery', 'resetRecoveryText');

closeResetCredsBtn.addEventListener('click', () => {
    resetCredsModal.classList.add('hidden');
});

// Bulk Reset Password
document.getElementById('bulkResetBtn').addEventListener('click', async () => {
    const checked = document.querySelectorAll('.userRowCheck:checked');
    if (checked.length !== 1) return;

    const cb = checked[0];
    const uuid = cb.dataset.uuid;
    const name = cb.dataset.name;

    if (!confirm(`Reset anonymous password for ${name}? They will be logged out and need the new password.`)) return;

    try {
        const res = await api(`/api/admin/users/${uuid}/reset-password`, { method: 'POST' });

        // Show modal
        resetCredsName.textContent = name;
        resetPasswordText.textContent = res.new_password;
        resetRecoveryText.textContent = res.recovery_phrase;

        passwordCopied = false;
        closeResetCredsBtn.disabled = true;
        closeResetCredsBtn.classList.remove('can-close');

        resetCredsModal.classList.remove('hidden');
        statusMessage.textContent = `Password reset for ${name}.`;
    } catch (err) {
        statusMessage.textContent = 'Reset failed: ' + err.message;
    }
});


// --- INVITES ---
async function loadInvites() {
    try {
        const res = await api('/api/admin/invites');
        invitesStatus = res.invites;
        renderInvites();
    } catch (err) {
        statusMessage.textContent = 'Error loading invites: ' + err.message;
    }
}

function renderInvites() {
    const tbody = document.querySelector('#invitesTable tbody');
    tbody.replaceChildren();
    const filter = document.getElementById('inviteSearch').value.toLowerCase();

    document.getElementById('inviteSelectAll').checked = false;
    updateInviteBulkActions();

    for (const inv of invitesStatus) {
        // Search filter
        const textToSearch = `${inv.code} ${inv.label || ''}`.toLowerCase();
        if (filter && !textToSearch.includes(filter)) continue;

        const tr = document.createElement('tr');

        // Checkbox
        const tdCheck = document.createElement('td');
        tdCheck.className = 'col-checkbox';
        const isExpired = (Date.now() / 1000) > inv.expires_at;
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'inviteRowCheck';
        cb.dataset.code = inv.code;
        cb.addEventListener('change', updateInviteBulkActions);
        tdCheck.appendChild(cb);
        tr.appendChild(tdCheck);

        const tdCode = document.createElement('td');
        const codeSpan = document.createElement('span');
        codeSpan.textContent = inv.code;
        codeSpan.className = 'clickable-code';
        codeSpan.title = 'Click to copy invite link';
        codeSpan.addEventListener('click', (e) => {
            const inviteUrl = `${window.location.origin}/invite?code=${inv.code}`;
            navigator.clipboard.writeText(inviteUrl).then(() => {
                showCursorNotification(e, 'Invite Link Copied!');
            });
        });
        tdCode.appendChild(codeSpan);

        const tdLabel = document.createElement('td');
        tdLabel.textContent = inv.label || '-';

        const tdCreator = document.createElement('td');
        tdCreator.textContent = inv.created_by_uuid.split('-')[0];

        const tdStatus = document.createElement('td');
        if (inv.used_by_uuid) {
            tdStatus.textContent = 'Used';
            tdStatus.className = 'status-used';
        } else if (isExpired) {
            tdStatus.textContent = 'Expired';
            tdStatus.className = 'status-expired';
        } else {
            tdStatus.textContent = 'Valid';
            tdStatus.className = 'status-valid';
        }

        const tdExpires = document.createElement('td');
        tdExpires.textContent = formatDate(inv.expires_at);

        tr.appendChild(tdCode);
        tr.appendChild(tdLabel);
        tr.appendChild(tdCreator);
        tr.appendChild(tdStatus);
        tr.appendChild(tdExpires);
        tbody.appendChild(tr);
    }
}

function showCursorNotification(e, message) {
    const el = document.createElement('div');
    el.className = 'cursor-notification';
    el.textContent = message;
    document.body.appendChild(el);

    el.style.left = `${e.pageX}px`;
    el.style.top = `${e.pageY}px`;

    setTimeout(() => {
        el.classList.add('fade-out');
        setTimeout(() => el.remove(), 500);
    }, 1500);
}

document.getElementById('inviteSearch').addEventListener('input', renderInvites);

document.getElementById('inviteSelectAll').addEventListener('change', (e) => {
    const isChecked = e.target.checked;
    document.querySelectorAll('.inviteRowCheck').forEach(cb => {
        cb.checked = isChecked;
    });
    updateInviteBulkActions();
});

function updateInviteBulkActions() {
    const checked = document.querySelectorAll('.inviteRowCheck:checked');
    document.getElementById('bulkRevokeBtn').disabled = checked.length === 0;
}

// Generate Invite
document.getElementById('generateInviteBtn').addEventListener('click', async () => {
    const days = parseInt(document.getElementById('inviteExpireDays').value, 10) || 3;
    const label = document.getElementById('inviteLabel').value.trim() || undefined;

    try {
        const res = await api('/api/admin/invites', {
            method: 'POST',
            body: JSON.stringify({ expire_days: days, label: label })
        });

        const inviteUrl = `${window.location.origin}/invite?code=${res.code}`;
        prompt('Generated new shareable invite link! Ready to copy:', inviteUrl);
        statusMessage.textContent = 'Created new invite link for: ' + res.code;
        document.getElementById('inviteLabel').value = ''; // clear
        loadInvites();
    } catch (err) {
        statusMessage.textContent = 'Error generating invite: ' + err.message;
    }
});

// Bulk Revoke Invites
document.getElementById('bulkRevokeBtn').addEventListener('click', async () => {
    const checked = Array.from(document.querySelectorAll('.inviteRowCheck:checked'));
    if (checked.length === 0) return;

    if (!confirm(`Revoke and permanently delete ${checked.length} selected invites?`)) return;

    statusMessage.textContent = 'Revoking invites...';
    try {
        await Promise.all(checked.map(cb => api(`/api/admin/invites/${cb.dataset.code}`, { method: 'DELETE' })));
        statusMessage.textContent = `Successfully revoked ${checked.length} invite(s).`;
        loadInvites();
    } catch (err) {
        statusMessage.textContent = 'Error during bulk revocation: ' + err.message;
        loadInvites(); // reload to get actual state
    }
});

// --- AUDIT LOGS ---
async function loadAuditLogs() {
    try {
        const offset = logsPage * logsPerPage;
        const res = await api(`/api/admin/audit-logs?limit=${logsPerPage}&offset=${offset}`);
        logsStatus = res.logs;
        totalLogs = res.total;
        renderAuditLogs();
    } catch (err) {
        statusMessage.textContent = 'Error loading audit logs: ' + err.message;
    }
}

function renderAuditLogs() {
    const tbody = document.querySelector('#logsTable tbody');
    tbody.replaceChildren();

    for (const log of logsStatus) {
        const tr = document.createElement('tr');
        
        // Highlight failed attempts in bold
        const isFailed = log.action === 'failed_login' || log.action === 'failed_recovery';
        if (isFailed) {
            tr.style.fontWeight = 'bold';
        }

        const tdTime = document.createElement('td');
        tdTime.textContent = formatDate(log.timestamp);
        tdTime.className = 'subtle';

        const tdAction = document.createElement('td');
        const code = document.createElement('code');
        code.textContent = log.action;
        tdAction.appendChild(code);

        const tdUser = document.createElement('td');
        tdUser.textContent = log.username || log.user_uuid || '-';
        tdUser.className = 'col-username';

        const tdDetails = document.createElement('td');
        tdDetails.textContent = log.details || '-';
        tdDetails.className = 'subtle';

        const tdIp = document.createElement('td');
        tdIp.textContent = log.ip_address || '-';
        tdIp.className = 'subtle';

        tr.appendChild(tdTime);
        tr.appendChild(tdAction);
        tr.appendChild(tdUser);
        tr.appendChild(tdDetails);
        tr.appendChild(tdIp);
        tbody.appendChild(tr);
    }

    // Update Pagination UI
    const totalPages = Math.ceil(totalLogs / logsPerPage) || 1;
    document.getElementById('logsPageInfo').textContent = `Page ${logsPage + 1} of ${totalPages} (${totalLogs} total)`;
    document.getElementById('logsPrevBtn').disabled = logsPage === 0;
    document.getElementById('logsNextBtn').disabled = (logsPage + 1) >= totalPages;
}

document.getElementById('logsPerPage').addEventListener('change', (e) => {
    logsPerPage = parseInt(e.target.value, 10);
    logsPage = 0;
    loadAuditLogs();
});

document.getElementById('logsPrevBtn').addEventListener('click', () => {
    if (logsPage > 0) {
        logsPage--;
        loadAuditLogs();
    }
});

document.getElementById('logsNextBtn').addEventListener('click', () => {
    const totalPages = Math.ceil(totalLogs / logsPerPage);
    if ((logsPage + 1) < totalPages) {
        logsPage++;
        loadAuditLogs();
    }
});

// Init
loadUsers();
