/**
 * emailchecker.js — Email breach lookup via XposedOrNot public API.
 * https://xposedornot.com/api_doc
 */

'use strict';

const _XON = 'https://api.xposedornot.com/v1';

function _esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ── Breach metadata cache (optional enrichment) ─────────────── */
let _meta = null;

async function _loadMeta() {
  if (_meta !== null) return;
  _meta = {};
  try {
    const r = await fetch(`${_XON}/breaches`);
    if (!r.ok) return;
    const d = await r.json();
    (d.breaches ?? []).forEach(b => {
      if (!b.breach) return;
      _meta[b.breach]            = b;   // exact key
      _meta[b.breach.toLowerCase()] = b; // lowercase fallback
    });
  } catch { /* metadata is bonus info — silently skip on failure */ }
}

/* ── Robust breach names extractor ───────────────────────────── */
// XposedOrNot may return [[name,name,...]] OR [name,name,...] OR null
function _extractNames(exposures) {
  const raw = exposures?.breaches;
  if (!raw) return [];
  if (Array.isArray(raw)) {
    // Nested: [[name1, name2, ...]]
    if (raw.length > 0 && Array.isArray(raw[0])) {
      return raw[0].filter(x => typeof x === 'string' && x.length > 0);
    }
    // Flat: [name1, name2, ...]
    return raw.filter(x => typeof x === 'string' && x.length > 0);
  }
  return [];
}

/* ── Year map from yearwise_details (inside main API response) ── */
// Gives us breach year without needing a second API call
function _buildYearMap(metrics) {
  const map = {};
  const details = metrics?.yearwise_details ?? [];

  if (Array.isArray(details)) {
    // Format: [{year:"2013", breaches:["Adobe"]}, ...]
    details.forEach(entry => {
      const yr    = String(entry.year ?? entry.Year ?? '').slice(0, 4);
      const names = entry.breaches ?? entry.breach_names ?? entry.Breaches ?? [];
      (Array.isArray(names) ? names : [names]).forEach(n => {
        if (n && yr && !map[n]) map[n] = yr;
      });
    });
  } else if (details && typeof details === 'object') {
    // Format: {"2013": ["Adobe"], "2019": ["Collection1"]}
    Object.entries(details).forEach(([yr, names]) => {
      (Array.isArray(names) ? names : [names]).forEach(n => {
        if (n && !map[n]) map[n] = String(yr).slice(0, 4);
      });
    });
  }
  return map;
}

/* ── Data type severity ──────────────────────────────────────── */
const _SEVERITY = {
  'Passwords':'critical','Password hints':'critical','Credit cards':'critical',
  'Bank account numbers':'critical','Social security numbers':'critical',
  'Private messages':'critical',
  'Phone numbers':'high','Physical addresses':'high','Dates of birth':'high',
  'Government issued IDs':'high','Health records':'high','Sexual orientations':'high',
  'Names':'medium','Usernames':'medium','Genders':'medium','Employers':'medium',
  'Job titles':'medium','Geographic locations':'medium','IP addresses':'medium',
  'Device information':'medium',
  'Email addresses':'low','Spoken languages':'low','Time zones':'low',
  'Website activity':'low',
};

function _chipClass(t) { return _SEVERITY[t] ?? 'medium'; }

/* ── Helpers ─────────────────────────────────────────────────── */
function _fmtCount(n) {
  if (!n || n < 1) return null;
  if (n >= 1e9) return `${(n/1e9).toFixed(1)}B records`;
  if (n >= 1e6) return `${(n/1e6).toFixed(1)}M records`;
  if (n >= 1e3) return `${Math.round(n/1e3).toLocaleString()}K records`;
  return `${n.toLocaleString()} records`;
}

function _isValidEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s.trim());
}

/* ── Breach card renderer ────────────────────────────────────── */
function _renderCard(name, yearMap) {
  // Try exact match, then lowercase match
  const info     = (_meta ?? {})[name] ?? (_meta ?? {})[name.toLowerCase()] ?? {};
  const year     = info.xposed_date?.slice(0, 4) ?? yearMap?.[name] ?? null;
  const count    = _fmtCount(info.xposed_records);
  const domain   = info.domain   || null;
  const industry = info.industry || null;

  const metaParts = [domain, industry, year, count].filter(Boolean);
  const metaStr   = metaParts.join(' · ');

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
          ${metaStr ? `<span class="ec-breach-meta">${_esc(metaStr)}</span>` : ''}
        </div>
      </div>
      ${chips ? `<div class="ec-chips">${chips}</div>` : ''}
    </div>`;
}

/* ── State renderer ──────────────────────────────────────────── */
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
            <strong>${_esc(data.email)}</strong> was not found in any known breach database.
            Keep using strong, unique passwords as a precaution.
          </div>
        </div>
      </div>`;
    return;
  }

  if (state === 'breached') {
    const { email, breachNames, yearMap, metrics } = data;
    const count   = breachNames.length;
    const pwCount = metrics?.passwords?.[0]?.passwordcount ?? 0;
    const pwWarn  = pwCount > 0
      ? ` ${pwCount} breach${pwCount !== 1 ? 'es' : ''} exposed passwords — change them immediately.`
      : '';

    const cards = breachNames.map(n => _renderCard(n, yearMap)).join('');

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
            <strong>${_esc(email)}</strong> appeared in ${count} known data
            breach${count !== 1 ? 'es' : ''}.${_esc(pwWarn)}
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
        Change passwords for affected services. Use the <strong>Generator</strong> tab to create strong replacements.
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

/* ── Core check logic ────────────────────────────────────────── */
let _checking = false;

async function _runCheck() {
  if (_checking) return;

  const emailInput = document.getElementById('ecEmailInput');
  const checkBtn   = document.getElementById('ecCheckBtn');
  const email      = (emailInput?.value ?? '').trim();

  if (!email) { emailInput?.focus(); return; }

  // Warn if opened via file:// — CORS will block external fetch
  if (window.location.protocol === 'file:') {
    _setState('error', {
      message: 'Open via the local server to use this feature: run "python web/server.py" then visit http://localhost:8080 in your browser. Direct file:// access is blocked by browser CORS policy.',
    });
    return;
  }

  if (!_isValidEmail(email)) {
    _setState('error', { message: 'Please enter a valid email address (e.g. name@example.com).' });
    return;
  }

  _checking = true;
  if (checkBtn) checkBtn.disabled = true;
  _setState('loading');

  try {
    // Fetch metadata + email check in parallel
    const [, r] = await Promise.all([
      _loadMeta(),
      fetch(`${_XON}/check-email/${encodeURIComponent(email)}`, { cache: 'no-store' }),
    ]);

    // 404 = clean email
    if (r.status === 404) {
      _setState('safe', { email });
      return;
    }

    if (!r.ok) {
      throw new Error(`API returned HTTP ${r.status}. Try again in a moment.`);
    }

    const d = await r.json();

    // API may also return {"Error":"Not found"} on 200
    if (d.Error || !d.exposures) {
      _setState('safe', { email });
      return;
    }

    const breachNames = _extractNames(d.exposures);
    const metrics     = d.exposures?.BreachMetrics ?? {};
    const yearMap     = _buildYearMap(metrics);

    if (breachNames.length === 0) {
      _setState('safe', { email });
    } else {
      _setState('breached', { email, breachNames, yearMap, metrics });
    }

  } catch (e) {
    const msg = (e instanceof TypeError && e.message.toLowerCase().includes('fetch'))
      ? 'Network error — could not reach the XposedOrNot API. Check your internet connection.'
      : e.message;
    _setState('error', { message: msg });
  } finally {
    _checking = false;
    if (checkBtn) checkBtn.disabled = false;
  }
}

/* ── Wire up ─────────────────────────────────────────────────── */
(function init() {
  const emailInput = document.getElementById('ecEmailInput');
  const checkBtn   = document.getElementById('ecCheckBtn');
  if (!emailInput || !checkBtn) return;

  checkBtn.addEventListener('click', _runCheck);
  emailInput.addEventListener('keydown', e => { if (e.key === 'Enter') _runCheck(); });
  emailInput.addEventListener('input',   () => _setState('idle'));
})();
