(function () {
  'use strict';

  // ─── Keepalive ───────────────────────────────────────────────────────────────
  // Pings /api/oscar-keepalive every 60 s, but ONLY when the tab is visible.
  // When hidden, pings stop → container evicts after OSCAR_IDLE_TIMEOUT_SECONDS.

  var KEEPALIVE_MS = 60 * 1000;

  function sendKeepalive() {
    if (document.visibilityState === 'visible') {
      fetch('/api/oscar-keepalive', { method: 'POST' }).catch(function () { });
    }
  }

  setInterval(sendKeepalive, KEEPALIVE_MS);

  // Immediate ping when user returns to the tab (re-focus after background).
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') {
      sendKeepalive();
    }
  });

  // Initial ping on load.
  sendKeepalive();

  // ─── Scenario Detection ───────────────────────────────────────────────────────
  // sessionStorage is tab-scoped and origin-scoped.
  // lastShareLaunchToken present → user is viewing someone else's shared profile.
  var isSharedView = false;
  try {
    isSharedView = !!(document.body.dataset.guestSession === 'true' || sessionStorage.getItem('lastShareLaunchToken'));
  } catch (_e) { }

  // ─── Styles ──────────────────────────────────────────────────────────────────
  var style = document.createElement('style');
  style.textContent = [
    '#oscar-toolbar {',
    '  position: fixed;',
    '  top: 12px;',
    '  right: 12px;',
    '  z-index: 9999;',
    '  display: flex;',
    '  align-items: center;',
    '  gap: 6px;',
    '  font-family: Inter, "Segoe UI", Roboto, sans-serif;',
    '  opacity: 0.88;',
    '  transition: opacity 0.2s ease;',
    '}',
    '#oscar-toolbar:hover { opacity: 1; }',

    '.oscar-tb-btn {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: 5px;',
    '  padding: 7px 13px;',
    '  border-radius: 10px;',
    '  border: 1px solid #c5d3ff;',
    '  background: linear-gradient(180deg, #f6f9ff 0%, #e7eeff 100%);',
    '  color: #1a3d9f;',
    '  font-weight: 600;',
    '  font-size: 13px;',
    '  font-family: inherit;',
    '  cursor: pointer;',
    '  box-shadow: 0 4px 10px rgba(36,87,245,0.14);',
    '  transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease, border-color 0.15s ease;',
    '  white-space: nowrap;',
    '  line-height: 1;',
    '  user-select: none;',
    '}',
    '.oscar-tb-btn:hover {',
    '  background: #e3eaff;',
    '  border-color: #adc2ff;',
    '  box-shadow: 0 6px 16px rgba(36,87,245,0.22);',
    '  transform: translateY(-1px);',
    '}',
    '.oscar-tb-btn svg { flex-shrink: 0; }',

    '.oscar-tb-btn.oscar-tb-logout {',
    '  border-color: #f0c5c5;',
    '  background: linear-gradient(180deg, #fff8f8 0%, #ffe8e8 100%);',
    '  color: #9b2c2c;',
    '  box-shadow: 0 4px 10px rgba(180,50,50,0.10);',
    '}',
    '.oscar-tb-btn.oscar-tb-logout:hover {',
    '  background: #fde8e8;',
    '  border-color: #f0a0a0;',
    '  box-shadow: 0 6px 16px rgba(180,50,50,0.18);',
    '}',

    '.oscar-shared-badge {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: 5px;',
    '  padding: 7px 11px;',
    '  border-radius: 10px;',
    '  border: 1px solid #fde68a;',
    '  background: linear-gradient(180deg, #fffbea 0%, #fef3c7 100%);',
    '  color: #92400e;',
    '  font-weight: 600;',
    '  font-size: 12px;',
    '  font-family: inherit;',
    '  box-shadow: 0 4px 10px rgba(180,120,0,0.10);',
    '  white-space: nowrap;',
    '  user-select: none;',
    '}',

    '#oscar-share-modal {',
    '  position: fixed;',
    '  top: 52px;',
    '  right: 12px;',
    '  z-index: 10000;',
    '  background: #fff;',
    '  border: 1px solid #c5d3ff;',
    '  border-radius: 12px;',
    '  padding: 14px 16px;',
    '  box-shadow: 0 12px 32px rgba(36,87,245,0.18);',
    '  width: 320px;',
    '  font-family: Inter, "Segoe UI", Roboto, sans-serif;',
    '  display: none;',
    '}',
    '#oscar-share-modal.oscar-modal-open { display: block; }',
    '#oscar-share-modal-hdr {',
    '  display: flex;',
    '  justify-content: space-between;',
    '  align-items: center;',
    '  margin-bottom: 8px;',
    '}',
    '#oscar-share-modal-hdr strong {',
    '  font-size: 13px;',
    '  color: #1a3d9f;',
    '}',
    '#oscar-share-close {',
    '  background: none;',
    '  border: none;',
    '  font-size: 17px;',
    '  cursor: pointer;',
    '  color: #5f6d89;',
    '  padding: 0;',
    '  line-height: 1;',
    '}',
    '#oscar-share-close:hover { color: #172033; }',
    '#oscar-share-subtitle {',
    '  font-size: 12px;',
    '  color: #5f6d89;',
    '  margin: 0 0 10px;',
    '}',
    '#oscar-share-url-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: 8px;',
    '  padding: 7px 10px;',
    '  border-radius: 8px;',
    '  border: 1px solid #d5def7;',
    '  background: #f7faff;',
    '}',
    '#oscar-share-url-text {',
    '  flex: 1;',
    '  font-size: 12px;',
    '  color: #172033;',
    '  word-break: break-all;',
    '  min-width: 0;',
    '}',
    '#oscar-share-copy-btn {',
    '  flex-shrink: 0;',
    '  padding: 4px 9px;',
    '  border-radius: 6px;',
    '  border: 1px solid #c5d3ff;',
    '  background: #e7eeff;',
    '  color: #1a3d9f;',
    '  font-size: 11px;',
    '  font-weight: 600;',
    '  cursor: pointer;',
    '  font-family: inherit;',
    '}',
    '#oscar-share-copy-btn:hover { background: #d5e3ff; }',
    '#oscar-share-copied {',
    '  font-size: 11px;',
    '  color: #13865b;',
    '  margin: 6px 0 0;',
    '  display: none;',
    '}',
  ].join('\n');
  document.head.appendChild(style);

  // ─── SVG icon helper ─────────────────────────────────────────────────────────
  function icon(paths, strokeColor) {
    var s = strokeColor || 'currentColor';
    return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" '
      + 'stroke="' + s + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
      + paths + '</svg>';
  }

  // ─── Build toolbar ────────────────────────────────────────────────────────────
  var toolbar = document.createElement('div');
  toolbar.id = 'oscar-toolbar';

  // Prevent VNC from capturing clicks/mousedowns on the toolbar
  toolbar.addEventListener('mousedown', function (e) { e.stopPropagation(); });
  toolbar.addEventListener('pointerdown', function (e) { e.stopPropagation(); });
  toolbar.addEventListener('click', function (e) { e.stopPropagation(); });

  // ── Uploader button ──────────────────────────────────────────────────────────
  var uploaderBtn = document.createElement('button');
  uploaderBtn.className = 'oscar-tb-btn';
  uploaderBtn.title = 'Return to the file uploader';
  uploaderBtn.innerHTML = icon(
    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
    + '<polyline points="17 8 12 3 7 8"/>'
    + '<line x1="12" y1="3" x2="12" y2="15"/>'
  ) + ' Uploader';
  uploaderBtn.addEventListener('click', function () {
    // Signal the backend to cleanly stop the container before we navigate away.
    // sendBeacon is guaranteed to fire even during page unload.
    navigator.sendBeacon('/api/oscar-disconnect');
    window.location.href = '/';
  });
  toolbar.appendChild(uploaderBtn);

  // ── Share Link button (own profile) OR Shared View badge (shared profile) ────
  if (isSharedView) {
    var badge = document.createElement('span');
    badge.className = 'oscar-shared-badge';
    badge.title = 'You are viewing a shared profile';
    badge.innerHTML = icon(
      '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>'
      + '<circle cx="12" cy="7" r="4"/>'
    ) + ' Shared View';
    toolbar.appendChild(badge);
  } else {
    var shareBtn = document.createElement('button');
    shareBtn.className = 'oscar-tb-btn';
    shareBtn.title = 'Create a sharing link for your OSCAR profile';
    shareBtn.innerHTML = icon(
      '<circle cx="18" cy="5" r="3"/>'
      + '<circle cx="6" cy="12" r="3"/>'
      + '<circle cx="18" cy="19" r="3"/>'
      + '<line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>'
      + '<line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>'
    ) + ' Share Link';
    shareBtn.addEventListener('click', handleShareLink);
    toolbar.appendChild(shareBtn);
  }

  // ── Logout button (rightmost) ─────────────────────────────────────────────────
  var logoutBtn = document.createElement('button');
  logoutBtn.className = 'oscar-tb-btn oscar-tb-logout';
  logoutBtn.title = 'Sign out';
  logoutBtn.innerHTML = icon(
    '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>'
    + '<polyline points="16 17 21 12 16 7"/>'
    + '<line x1="21" y1="12" x2="9" y2="12"/>',
    '#9b2c2c'
  ) + ' Logout';
  logoutBtn.addEventListener('click', handleLogout);
  toolbar.appendChild(logoutBtn);

  // ─── Share modal ─────────────────────────────────────────────────────────────
  var shareModal = document.createElement('div');
  shareModal.id = 'oscar-share-modal';
  shareModal.setAttribute('aria-modal', 'true');
  shareModal.setAttribute('role', 'dialog');
  shareModal.innerHTML = [
    '<div id="oscar-share-modal-hdr">',
    '  <strong>Profile Sharing Link</strong>',
    '  <button id="oscar-share-close" aria-label="Close">\u00d7</button>',
    '</div>',
    '<p id="oscar-share-subtitle">Grants read-only access to your OSCAR data for 24\u00a0hours.</p>',
    '<div id="oscar-share-url-row">',
    '  <span id="oscar-share-url-text">Generating\u2026</span>',
    '  <button id="oscar-share-copy-btn">Copy</button>',
    '</div>',
    '<p id="oscar-share-copied">\u2713 Copied to clipboard!</p>',
  ].join('');

  // ─── Append to DOM ────────────────────────────────────────────────────────────
  document.body.appendChild(toolbar);
  document.body.appendChild(shareModal);

  // ─── Event wiring (after DOM insertion) ──────────────────────────────────────
  document.getElementById('oscar-share-close').addEventListener('click', function () {
    shareModal.classList.remove('oscar-modal-open');
  });

  document.getElementById('oscar-share-copy-btn').addEventListener('click', function () {
    var text = (document.getElementById('oscar-share-url-text') || {}).textContent || '';
    if (!text || text === 'Generating\u2026' || text === 'Error \u2014 please try again.') return;
    navigator.clipboard.writeText(text).then(function () {
      var feedback = document.getElementById('oscar-share-copied');
      if (!feedback) return;
      feedback.style.display = 'block';
      setTimeout(function () { feedback.style.display = 'none'; }, 2500);
    }).catch(function () { });
  });

  // ─── Handlers ────────────────────────────────────────────────────────────────
  function handleShareLink() {
    shareModal.classList.add('oscar-modal-open');
    var urlText = document.getElementById('oscar-share-url-text');
    if (urlText) urlText.textContent = 'Generating\u2026';
    document.getElementById('oscar-share-copied').style.display = 'none';

    fetch('/api/share-links', { method: 'POST' })
      .then(function (res) {
        if (!res.ok) throw new Error('failed');
        return res.json();
      })
      .then(function (data) {
        var url = window.location.origin + '/share/' + data.token;
        if (urlText) urlText.textContent = url;
      })
      .catch(function () {
        if (urlText) urlText.textContent = 'Error \u2014 please try again.';
      });
  }

  function handleLogout() {
    // Disconnect signal first (best-effort; logout also cleans up server-side)
    navigator.sendBeacon('/api/oscar-disconnect');
    fetch('/api/logout', { method: 'POST' }).catch(function () { }).then(function () {
      window.location.href = '/';
    });
  }

  // Safety net: fire disconnect beacon for any navigation not caught by our buttons
  // (back/forward, direct URL change, tab close).
  window.addEventListener('beforeunload', function () {
    navigator.sendBeacon('/api/oscar-disconnect');
  });

}());
