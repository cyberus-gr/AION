/**
 * emailchecker.js — Email breach lookup via XposedOrNot public API.
 *
 * API docs: https://xposedornot.com/api_doc
 * No API key required. Free public endpoint.
 */

'use strict';

const _XON = 'https://api.xposedornot.com/v1';

/* ── Local escHtml (self-contained, no dependency on app.js) ─── */
function _esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ── Breach metadata cache ───────────────────────────────────── */
let _meta = null; // { breachName: {...} }

async function _loadMeta() {
  if (_meta !== null) return;
  _meta = {};
  try {
    const r = await fetch(`${_XON}/breaches`);
    if (!r.ok) return;
    const d = await r.json();
    (d.breaches ?? []).forEach(b => { _meta[b.breach] = b; });
  } catch { /* leave _meta as empty object — graceful degradation */ }
}

/* ── Data type severity mapping ──────────────────────────────── */
const _SEVERITY = {
  // critical — direct account/financial compromise
  'Passwords':              'critical',
  'Password hints':         'critical',
  'Credit cards':           'critical',
  'Bank account numbers':   'critical',
  'Social security numbers':'critical',
  'Private messages':       'critical',
  // high — personal identity data
  'Phone numbers':          'high',
  'Physical addresses':     'high',
  'Dates of birth':         'high',
  'Government issued IDs':  'high',
  'Health records':         'high',
  'Sexual orientations':    'high',
  // medium — profile / behavioural data
  'Names':                  'medium',
  'Usernames':              'medium',
  'Genders':                'medium',
  'Employers':              'medium',
  'Job titles':             'medium',
  'Geographic locations':   'medium',
  'IP addresses':           'medium',
  'Device information':     'medium',
  // low — low-sensitivity identifiers
  'Email addresses':        'low',
  'Spoken languages':       'low',
  'Time zones':             'low',
  'Website activity':       'low',
};

function _chipClass(type) {
  return _SEVERITY[type] ?? 'medium';
}

/* ── Formatting helpers ──────────────────────────────────────── */
function _fmtCount(n) {
  if (!n || n < 1) return null;
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B records`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M records`;
  if (n >= 1e3) return `${Math.round(n / 1e3).toLocaleString()}K records`;
  return `${n.toLocaleString()} records`;
}

function _fmtDate(dateStr) {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr.slice(0, 4) || null;
  return d.toLocaleDateString('en-GB', { month: 'short', year: 'numeric' });
}

function _isValidEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s.trim());
}

/* ── Render a single breach card ─────────────────────────────── */
function _renderCard(name) {
  const info      = (_meta ?? {})[name] ?? {};
  const date      = _fmtDate(info.xposed_date);
  const count     = _fmtCount(info.xposed_records);
  const domain    = info.domain    || null;
  const industry  = info.industry  || null;

  const meta = [domain, industry, date, count].filter(Boolean).join(' · ');

  const types = info.xposed_data
    ? info.xposed_data.split(';').map(s => s.trim()).filter(Boolean)
    : [];

  const chips = types.map(t =>
    `<span class="ec-chip ec-chip-${_chipClass(t)}">${_esc(t)}</span>`
  ).join('');

  return `
    <div class="ec-breach-card">
      <div class="ec-breach-header">
        <div class="ec-breach-dot"></div>
        <div>
          <span class="ec-breach-name">${_esc(name)}</span>
          ${meta ? `<span class="ec-breach-meta">${_esc(meta)}</span>` : ''}
        </div>
      </div>
      ${chips ? `<div class="ec-chips">${chips}</div>` : ''}
    </div>`;
}

/* ── Result state renderer ───────────────────────────────────── */
function _setState(state, data = {}) {
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

  if (state === 'safe') {
    el.innerHTML = `
      <div class="ec-state-box ec-safe">
        <svg class="ec-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <polyline points="9 12 11 14 15 10"/>
        </svg>
        <div>
          <div class="ec-state-title">No Breaches Found</div>
          <div class="ec-state-sub">
            <strong>${_esc(data.email)}</strong> was not found in any breach database tracked by XposedOrNot.
            Keep using strong, unique passwords as a precaution.
          </div>
        </div>
      </div>`;
    return;
  }

  if (state === 'breached') {
    const { email, breachNames, metrics } = data;
    const count   = breachNames.length;
    const pwCount = metrics?.passwords?.[0]?.passwordcount ?? 0;

    const cards = breachNames.map(n => _renderCard(n)).join('');

    const pwWarning = pwCount > 0
      ? ` ${pwCount} breach${pwCount !== 1 ? 'es' : ''} exposed passwords — change them immediately.`
      : '';

    el.innerHTML = `
      <div class="ec-state-box ec-breached">
        <svg class="ec-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <div>
          <div class="ec-state-title">Found in ${count} Breach${count !== 1 ? 'es' : ''}</div>
          <div class="ec-state-sub">
            <strong>${_esc(email)}</strong> appeared in ${count} known data breach${count !== 1 ? 'es' : ''}.${_esc(pwWarning)}
          </div>
        </div>
      </div>
      <div class="ec-breach-list">${cards}</div>
      <div class="ec-action-tip">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        Change your passwords for any affected services. Use the <strong>Generator</strong> tab to create strong new ones.
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
          <div class="ec-state-sub">${_esc(data.message ?? 'Could not reach the breach database. Check your internet connection and try again.')}</div>
        </div>
      </div>`;
  }
}

/* ── Core check logic ────────────────────────────────────────── */
let _checking = false;

async function _runCheck() {
  if (_checking) return;

  const emailInput = document.getElementById('ecEmailInput');
  const checkBtn   = document.getElementById('ecCheckBtn');
  const email      = (emailInput?.value ?? '').trim();

  if (!email) { emailInput?.focus(); return; }

  if (!_isValidEmail(email)) {
    _setState('error', { message: 'Please enter a valid email address (e.g. name@example.com).' });
    return;
  }

  _checking = true;
  if (checkBtn) checkBtn.disabled = true;
  _setState('loading');

  try {
    // Pre-fetch breach metadata in parallel with the email check
    const [, r] = await Promise.all([
      _loadMeta(),
      fetch(`${_XON}/check-email/${encodeURIComponent(email)}`, { cache: 'no-store' }),
    ]);

    if (r.status === 404) {
      _setState('safe', { email });
      return;
    }

    if (!r.ok) {
      throw new Error(`API returned HTTP ${r.status}. Try again later.`);
    }

    const d = await r.json();

    // XposedOrNot returns {"Error":"Not found"} for clean emails (besides 404)
    if (d.Error || !d.exposures) {
      _setState('safe', { email });
      return;
    }

    const breachNames = d.exposures?.breaches?.[0] ?? [];
    const metrics     = d.exposures?.BreachMetrics ?? {};

    if (breachNames.length === 0) {
      _setState('safe', { email });
    } else {
      _setState('breached', { email, breachNames, metrics });
    }

  } catch (e) {
    _setState('error', { message: e.message });
  } finally {
    _checking = false;
    if (checkBtn) checkBtn.disabled = false;
  }
}

/* ── Wire up events ──────────────────────────────────────────── */
(function init() {
  const emailInput = document.getElementById('ecEmailInput');
  const checkBtn   = document.getElementById('ecCheckBtn');
  if (!emailInput || !checkBtn) return;

  checkBtn.addEventListener('click', _runCheck);
  emailInput.addEventListener('keydown', e => { if (e.key === 'Enter') _runCheck(); });

  // Clear results when user modifies the email
  emailInput.addEventListener('input', () => _setState('idle'));
})();
