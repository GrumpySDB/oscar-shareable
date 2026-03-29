/**
 * Theme management for light/dark mode.
 * Persists user preference in localStorage and respects system settings.
 */

const THEME_KEY = 'oscar-uploader-theme';

/**
 * Get the current theme from localStorage or system preference.
 * @returns {'light' | 'dark'}
 */
export function getPreferredTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    if (savedTheme) {
        return savedTheme;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

/**
 * Apply the theme to the document.
 * @param {'light' | 'dark'} theme 
 */
export function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    
    // Update the toggle button icon if it exists
    updateToggleIcons(theme);
}

/**
 * Toggle between light and dark themes.
 */
export function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(newTheme);
}

/**
 * Initialize the theme on page load.
 */
export function initTheme() {
    const theme = getPreferredTheme();
    applyTheme(theme);
    
    // Listen for system theme changes if user hasn't set an explicit preference
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem(THEME_KEY)) {
            applyTheme(e.matches ? 'dark' : 'light');
        }
    });

    // Add event listener to any theme toggle buttons on the page
    document.addEventListener('DOMContentLoaded', () => {
        setupToggleListeners();
    });
    
    // Also run setup immediately in case DOM is already loaded
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setupToggleListeners();
    }
}

function setupToggleListeners() {
    const toggles = document.querySelectorAll('.theme-toggle');
    toggles.forEach(toggle => {
        // Remove existing listener to avoid duplicates
        toggle.removeEventListener('click', toggleTheme);
        toggle.addEventListener('click', toggleTheme);
    });
    updateToggleIcons(document.documentElement.getAttribute('data-theme') || getPreferredTheme());
}

function updateToggleIcons(theme) {
    const toggles = document.querySelectorAll('.theme-toggle');
    toggles.forEach(toggle => {
        const sunIcon = toggle.querySelector('.sun-icon');
        const moonIcon = toggle.querySelector('.moon-icon');
        
        if (theme === 'dark') {
            if (sunIcon) sunIcon.classList.remove('hidden');
            if (moonIcon) moonIcon.classList.add('hidden');
            toggle.setAttribute('aria-label', 'Switch to light mode');
        } else {
            if (sunIcon) sunIcon.classList.add('hidden');
            if (moonIcon) moonIcon.classList.remove('hidden');
            toggle.setAttribute('aria-label', 'Switch to dark mode');
        }
    });
}

/**
 * Shows a floating notification at the cursor position.
 * @param {MouseEvent} e The click event.
 * @param {string} message The message to display.
 */
export function showCursorNotification(e, message) {
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

// Auto-initialize
initTheme();
