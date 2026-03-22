/**
 * emailchecker.js — Email breach lookup via XposedOrNot public API.
 * https://xposedornot.com/api_doc
 *
 * Verified response formats (curl-tested):
 *   Found:     {"breaches":[["name1","name2",...]],"email":"...","status":"success"}
 *   Not found: {"Error":"Not found","email":null}   — HTTP 200 in both cases
 *   Metadata:  {"status":"success","exposedBreaches":[{breachID, breachedDate,
 *               exposedRecords, exposedData:[], domain, industry, passwordRisk,...}]}
 */

'use strict';

const _XON = 'https://api.xposedornot.com/v1';

function _esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ── Breach metadata cache ───────────────────────────────────── */
let _meta = null;

async function _loadMeta() {
  if (_meta !== null) return;
  _meta = {};
  try {
    const r = await fetch(`${_XON}/breaches`);
    if (!r.ok) return;
    const d = await r.json();
    (d.exposedBreaches ?? []).forEach(b => {
      if (!b.breachID) return;
      _meta[b.breachID]               = b;
      _meta[b.breachID.toLowerCase()] = b;
    });
  } catch { /* metadata is enrichment only */ }
}

/* ── Robust breach name extraction ──────────────────────────── */
function _extractNames(d) {
  const raw = d?.breaches;
  if (!Array.isArray(raw)) return [];
  // Standard format: [[name1, name2, ...]]
  if (raw.length > 0 && Array.isArray(raw[0])) {
    return raw[0].filter(x => typeof x === 'string' && x.length > 0);
  }
  // Flat fallback: [name1, name2, ...]
  return raw.filter(x => typeof x === 'string' && x.length > 0);
}

/* ── Helpers ─────────────────────────────────────────────────── */
function _isValidEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s.trim());
}

function _meta_for(name) {
  return (_meta ?? {})[name] ?? (_meta ?? {})[name.toLowerCase()] ?? {};
}

/* ── Inline status (loading / error only) ────────────────────── */
function _setStatus(state, data = {}) {
  const el = document.getElementById('ecResults');
  if (!el) return;

  if (state === 'idle') { el.innerHTML = ''; return; }

  if (state === 'loading') {
    el.innerHTML = `
      <div class="ec-state-box ec-loading">
        <div class="ec-spinner"></div>
        <span>Checking breach databases…</span>
      </div>`;
    return;
  }

  if (state === 'error') {
    el.innerHTML = `
      <div class="ec-state-box ec-error">
        <svg class="ec-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <div>
          <div class="ec-state-title">Check Failed</div>
          <div class="ec-state-sub">${_esc(data.message ?? 'Could not reach the breach database. Check your connection and try again.')}</div>
        </div>
      </div>`;
  }
}

/* ── Modal result popup ──────────────────────────────────────── */
function _showModal(type, data) {
  const overlay = document.getElementById('ecModal');
  const header  = document.getElementById('ecModalHeader');
  const icon    = document.getElementById('ecModalIcon');
  const title   = document.getElementById('ecModalTitle');
  const emailEl = document.getElementById('ecModalEmail');
  const countEl = document.getElementById('ecModalCount');
  const detail  = document.getElementById('ecModalDetail');
  const footer  = document.getElementById('ecModalFooter');
  if (!overlay) return;

  // Clear inline status
  _setStatus('idle');

  emailEl.textContent = data.email;

  if (type === 'breached') {
    const { email, breachNames } = data;
    const count = breachNames.length;

    header.className      = 'ec-modal-header ec-mh-breach';
    icon.innerHTML        = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
    </svg>`;
    title.textContent     = 'Your Email Appeared in a Breach';
    emailEl.className     = 'ec-modal-badge ec-badge-breach';
    countEl.textContent   = count;
    countEl.className     = 'ec-modal-badge ec-badge-breach-count';

    // Build breach name pills
    const pillsHtml = breachNames
      .map(n => `<span class="ec-modal-pill">${_esc(n)}</span>`)
      .join('');
    detail.innerHTML = `
      <p class="ec-modal-detail-label">Your email appeared in these data breaches:</p>
      <div class="ec-modal-pills">${pillsHtml}</div>`;

    const reportUrl = `https://xposedornot.com/data-breaches-risks?email=${encodeURIComponent(email)}`;
    footer.innerHTML = `
      <a href="https://xposedornot.com" target="_blank" rel="noopener noreferrer" class="ec-btn-alerts">
        🔔 Get Breach Alerts
      </a>
      <a href="${reportUrl}" target="_blank" rel="noopener noreferrer" class="ec-btn-report">
        ✈ Detailed Report
      </a>`;

  } else {
    // Safe
    header.className      = 'ec-modal-header ec-mh-safe';
    icon.innerHTML        = `<span>😊</span>`;
    title.textContent     = 'Yay! No Breaches Found';
    emailEl.className     = 'ec-modal-badge ec-badge-safe';
    countEl.textContent   = 'No breaches found!';
    countEl.className     = 'ec-modal-badge ec-badge-safe-text';

    detail.innerHTML = `
      <p class="ec-modal-safe-msg">
        🎉 Great news! Your email wasn't found in any known data breaches.
        Stay protected by setting up free alerts.
      </p>`;

    footer.innerHTML = `
      <a href="https://xposedornot.com" target="_blank" rel="noopener noreferrer" class="ec-btn-alerts-safe">
        🔔 Get Breach Alerts
      </a>`;
  }

  overlay.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function _closeModal() {
  const overlay = document.getElementById('ecModal');
  if (overlay) overlay.classList.add('hidden');
  document.body.style.overflow = '';
}

/* ── Core check logic ────────────────────────────────────────── */
let _checking = false;

async function _runCheck() {
  if (_checking) return;

  const emailInput = document.getElementById('ecEmailInput');
  const checkBtn   = document.getElementById('ecCheckBtn');
  // Always lowercase — some APIs are case-sensitive and it's correct normalisation
  const email = (emailInput?.value ?? '').trim().toLowerCase();

  if (!email) { emailInput?.focus(); return; }

  if (window.location.protocol === 'file:') {
    _setStatus('error', {
      message: 'Run via local server first: "python web/server.py", then open http://localhost:8080. Direct file:// is blocked by browser CORS policy.',
    });
    return;
  }

  if (!_isValidEmail(email)) {
    _setStatus('error', { message: 'Please enter a valid email address (e.g. name@example.com).' });
    return;
  }

  _checking = true;
  if (checkBtn) checkBtn.disabled = true;
  _setStatus('loading');

  try {
    // Load metadata + check email in parallel
    const [, r] = await Promise.all([
      _loadMeta(),
      fetch(`${_XON}/check-email/${encodeURIComponent(email)}`, { cache: 'no-store' }),
    ]);

    if (!r.ok) {
      throw new Error(`API returned HTTP ${r.status}. Try again in a moment.`);
    }

    const d = await r.json();

    // Not found: {"Error":"Not found","email":null}
    // Found:     {"breaches":[["name1",...]],"email":"...","status":"success"}
    if (d.Error || !d.breaches) {
      _showModal('safe', { email });
      return;
    }

    const breachNames = _extractNames(d);

    if (breachNames.length === 0) {
      _showModal('safe', { email });
    } else {
      _showModal('breached', { email, breachNames });
    }

  } catch (e) {
    const msg = (e instanceof TypeError && e.message.toLowerCase().includes('fetch'))
      ? 'Network error — could not reach XposedOrNot. Check your internet connection.'
      : e.message;
    _setStatus('error', { message: msg });
  } finally {
    _checking = false;
    if (checkBtn) checkBtn.disabled = false;
  }
}

/* ── Wire up ─────────────────────────────────────────────────── */
(function init() {
  const emailInput = document.getElementById('ecEmailInput');
  const checkBtn   = document.getElementById('ecCheckBtn');
  const closeBtn   = document.getElementById('ecModalClose');
  const overlay    = document.getElementById('ecModal');

  if (!emailInput || !checkBtn) return;

  checkBtn.addEventListener('click', _runCheck);
  emailInput.addEventListener('keydown', e => { if (e.key === 'Enter') _runCheck(); });
  emailInput.addEventListener('input',   () => _setStatus('idle'));

  // Close modal on button or backdrop click
  closeBtn?.addEventListener('click', _closeModal);
  overlay?.addEventListener('click', e => { if (e.target === overlay) _closeModal(); });

  // Close modal on Escape key
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay && !overlay.classList.contains('hidden')) {
      _closeModal();
    }
  });
})();
