/**
 * Attempts to trigger the browser's password manager to save/update credentials.
 * Requires a secure context (HTTPS) and browser support.
 */
async function triggerPasswordSave(username, password) {
    if (!window.PasswordCredential || !navigator.credentials) {
        console.debug('Credential Management API not supported');
        return;
    }

    try {
        const credential = new PasswordCredential({
            id: username,
            password: password
        });
        await navigator.credentials.store(credential);
        console.log('Credential storage request sent to browser');
    } catch (err) {
        console.error('Failed to store credential:', err);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const recoveryForm = document.getElementById('recoveryForm');
    const recoveryError = document.getElementById('recoveryError');
    const recoveryFlow = document.getElementById('recoveryFlow');
    const newPasswordDisplay = document.getElementById('newPasswordDisplay');
    const displayNewPassword = document.getElementById('displayNewPassword');
    const copyNewPassword = document.getElementById('copyNewPassword');
    const recoverBtn = document.getElementById('recoverBtn');
    const returnToLoginBtn = document.getElementById('returnToLoginBtn');

    let savedUsername = null;
    let savedPassword = null;

    if (recoveryForm) {
        recoveryForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            recoveryError.textContent = '';

            const username = document.getElementById('recoveryUsername').value.trim();
            const recoveryPhrase = document.getElementById('recoveryPhrase').value.trim();

            if (!username || !recoveryPhrase) {
                recoveryError.textContent = 'Please enter both your username and recovery phrase.';
                return;
            }

            recoverBtn.disabled = true;
            recoverBtn.textContent = 'Verifying...';

            try {
                const response = await fetch('/api/auth/local/recover', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, recovery_phrase: recoveryPhrase })
                });

                const data = await response.json();

                if (response.ok) {
                    savedUsername = username;
                    savedPassword = data.new_password;

                    recoveryFlow.classList.add('hidden');
                    newPasswordDisplay.classList.remove('hidden');
                    displayNewPassword.textContent = data.new_password;
                } else {
                    recoveryError.textContent = data.error || 'Recovery failed. Please check your credentials.';
                }
            } catch (err) {
                console.error('Recovery error:', err);
                recoveryError.textContent = 'A server error occurred. Please try again later.';
            } finally {
                recoverBtn.disabled = false;
                recoverBtn.textContent = 'Reset Password';
            }
        });
    }

    if (returnToLoginBtn) {
        returnToLoginBtn.addEventListener('click', async (e) => {
            if (savedUsername && savedPassword) {
                e.preventDefault();
                await triggerPasswordSave(savedUsername, savedPassword);
                window.location.href = '/';
            }
        });
    }

    if (copyNewPassword) {
        copyNewPassword.addEventListener('click', (e) => {
            const text = displayNewPassword.textContent;
            navigator.clipboard.writeText(text).then(() => {
                showCursorNotification(e, 'Password Copied!');
            });
        });
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
});
