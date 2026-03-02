const urlParams = new URLSearchParams(window.location.search);
const inviteCode = urlParams.get('code');

if (!inviteCode) {
    const p = document.createElement('p');
    p.className = 'error';
    p.textContent = 'No valid invite code provided in the URL.';
    document.getElementById('authOptions').replaceChildren(p);
} else {
    document.getElementById('discordSignupBtn').href = `/api/auth/discord/login?invite=${encodeURIComponent(inviteCode)}`;
}

function sanitizeUsernameInput(value) {
    if (typeof value !== 'string') return null;
    const normalized = value.normalize('NFKC').trim();
    if (normalized.length === 0 || normalized.length > 128) return null;
    if (!/^[a-zA-Z0-9_\-]+$/.test(normalized)) return null;
    if (/[\u0000-\u001F\u007F]/.test(normalized)) return null;
    return normalized;
}

const signupForm = document.getElementById('signupForm');
const signupUsername = document.getElementById('signupUsername');
const localSignupBtn = document.getElementById('localSignupBtn');
const signupError = document.getElementById('signupError');

const authOptions = document.getElementById('authOptions');
const credentialsDisplay = document.getElementById('credentialsDisplay');
const credUsername = document.getElementById('credUsername');
const credPassword = document.getElementById('credPassword');
const credRecovery = document.getElementById('credRecovery');
const savedCheckbox = document.getElementById('savedCheckbox');
const proceedBtn = document.getElementById('proceedBtn');

let generatedToken = null;

if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const rawUsername = signupUsername.value;
        const username = sanitizeUsernameInput(rawUsername);

        if (!username) {
            signupError.textContent = 'Please choose a valid username (letters, numbers, underscores, and hyphens only).';
            return;
        }

        localSignupBtn.disabled = true;
        signupError.textContent = '';

        try {
            const res = await fetch('/api/auth/local/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, invite_code: inviteCode })
            });
            const data = await res.json();

            if (!res.ok) {
                throw new Error(data.error || 'Signup failed');
            }

            // Success - Hide auth options, show credentials inline
            generatedToken = data.token;
            authOptions.classList.add('hidden');

            credUsername.textContent = data.username;
            credPassword.textContent = data.password;
            credRecovery.textContent = data.recovery_phrase;

            credentialsDisplay.classList.remove('hidden');

        } catch (err) {
            signupError.textContent = err.message;
            localSignupBtn.disabled = false;
        }
    });
}

function setupCopy(elementId, textElementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.addEventListener('click', async () => {
        const text = document.getElementById(textElementId).textContent;
        try {
            await navigator.clipboard.writeText(text);
            el.classList.add('copied');
            setTimeout(() => el.classList.remove('copied'), 2000);
        } catch (err) {
            console.error('Copy failed', err);
        }
    });
}

setupCopy('copyUsername', 'credUsername');
setupCopy('copyPassword', 'credPassword');
setupCopy('copyRecovery', 'credRecovery');

savedCheckbox.addEventListener('change', () => {
    proceedBtn.disabled = !savedCheckbox.checked;
    if (savedCheckbox.checked) {
        proceedBtn.style.opacity = '1';
        proceedBtn.style.cursor = 'pointer';
    } else {
        proceedBtn.style.opacity = '0.55';
        proceedBtn.style.cursor = 'not-allowed';
    }
});

proceedBtn.addEventListener('click', () => {
    if (generatedToken) {
        sessionStorage.setItem('authToken', generatedToken);
        window.location.href = '/';
    }
});
