/**
 * app.js — UI orchestration: tab switching, generator, vault, lab, history modal.
 */

'use strict';

/* ── Shared utils ────────────────────────────────────────────── */
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024**2) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1024**2).toFixed(1)} MB`;
}

const SCORE_COLORS = {
  weak:'#ff3b3b', fair:'#ff8c00', good:'#f5c518', strong:'#34d399', vstrong:'#00d97e',
};

/* ── Toast ───────────────────────────────────────────────────── */
let _toastTimer;
function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 2200);
}

/* ── Custom number steppers ──────────────────────────────────── */
document.querySelectorAll('.stepper-btns').forEach(stepperEl => {
  const inp   = document.getElementById(stepperEl.dataset.target);
  if (!inp) return;

  const upBtn = stepperEl.querySelector('.stepper-up');
  const dnBtn = stepperEl.querySelector('.stepper-dn');

  function getMin() { return inp.min !== '' ? parseFloat(inp.min) : -Infinity; }
  function getMax() { return inp.max !== '' ? parseFloat(inp.max) :  Infinity; }

  function updateBoundaryState() {
    const val = parseFloat(inp.value) || 0;
    dnBtn.disabled = val <= getMin();
    upBtn.disabled = val >= getMax();
  }

  function syncCheckboxes(val) {
    if (inp.id === 'minNumbers' && val > 0) chkDigits.checked  = true;
    if (inp.id === 'minSpecial' && val > 0) chkSymbols.checked = true;
  }

  function step(dir) {
    const min  = getMin();
    const max  = getMax();
    const inc  = parseFloat(inp.step) || 1;
    const next = Math.round(((parseFloat(inp.value) || 0) + dir * inc) * 1e9) / 1e9;
    if (next < min || next > max) return;
    inp.value = next;
    syncCheckboxes(next);
    updateBoundaryState();
    inp.dispatchEvent(new Event('input',  { bubbles: true }));
    inp.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // Single click step
  upBtn.addEventListener('click', () => step(+1));
  dnBtn.addEventListener('click', () => step(-1));

  // Hold-to-repeat (press and hold)
  let _interval, _timeout;
  function startRepeat(dir) {
    _timeout = setTimeout(() => {
      _interval = setInterval(() => step(dir), 80);
    }, 400);
  }
  function stopRepeat() {
    clearTimeout(_timeout);
    clearInterval(_interval);
  }

  upBtn.addEventListener('mousedown', () => startRepeat(+1));
  dnBtn.addEventListener('mousedown', () => startRepeat(-1));
  document.addEventListener('mouseup', stopRepeat);

  // Keep boundary state in sync when user types directly
  inp.addEventListener('input', () => {
    syncCheckboxes(parseFloat(inp.value) || 0);
    updateBoundaryState();
  });

  // Initialise disabled state
  updateBoundaryState();
});

/* ── Main tab navigation ─────────────────────────────────────── */
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

/* ════════════════════════════════════════════════════════════════
   GENERATOR
════════════════════════════════════════════════════════════════ */

/* ── Generator history (in-session memory, cleared on page reload) ── */
let _history = [];

function addToHistory(type, value, score, label, cssClass) {
  const entry = {
    id: Date.now(),
    type, value, score, label, cssClass,
    time: new Date().toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' }),
  };
  _history.unshift(entry);
  if (_history.length > 50) _history.pop();
}

function renderHistory() {
  const list = document.getElementById('historyList');
  if (_history.length === 0) {
    list.innerHTML = '<p class="history-empty">No passwords generated this session.</p>';
    return;
  }

  list.innerHTML = _history.map(e => `
    <div class="history-entry" data-id="${e.id}">
      <span class="history-type-badge hbadge-${e.type}">${e.type}</span>
      <span class="history-value">${escHtml(e.value)}</span>
      <span class="history-score" style="color:${SCORE_COLORS[e.cssClass]??'#4f8ef7'}">${e.score}</span>
      <button class="history-copy-btn" data-val="${escHtml(e.value)}" title="Copy">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2"/>
          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
        </svg>
      </button>
      <span class="history-time">${e.time}</span>
    </div>
  `).join('');

  list.querySelectorAll('.history-copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.val);
        showToast('Copied from history');
      } catch { showToast('Copy failed'); }
    });
  });
}

/* ── History modal ───────────────────────────────────────────── */
const historyModal = document.getElementById('historyModal');

function openHistory() {
  renderHistory();
  historyModal.classList.remove('hidden');
}

function closeHistory() {
  historyModal.classList.add('hidden');
}

document.getElementById('closeHistoryBtn').addEventListener('click', closeHistory);
document.getElementById('clearHistoryBtn').addEventListener('click', () => {
  _history = [];
  renderHistory();
});
historyModal.addEventListener('click', e => {
  if (e.target === historyModal) closeHistory();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeHistory();
});

['historyBtnPw','historyBtnPp','historyBtnUn'].forEach(id => {
  document.getElementById(id).addEventListener('click', openHistory);
});

/* ── Generator sub-tab switching ─────────────────────────────── */
let _genMode = 'password';

document.querySelectorAll('.gen-subtab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.gen-subtab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    _genMode = btn.dataset.mode;

    document.getElementById('optPassword').classList.toggle('hidden', _genMode !== 'password');
    document.getElementById('optPassphrase').classList.toggle('hidden', _genMode !== 'passphrase');
    document.getElementById('optUsername').classList.toggle('hidden', _genMode !== 'username');

    const strengthWrap = document.getElementById('genStrengthWrap');
    strengthWrap.style.display = _genMode === 'username' ? 'none' : '';

    doGenerate();
  });
});

/* ── Core generator elements ─────────────────────────────────── */
const pwDisplay       = document.getElementById('pwDisplay');
const regenerateBtn   = document.getElementById('regenerateBtn');
const copyBtn         = document.getElementById('copyBtn');
const strengthFill    = document.getElementById('genStrengthFill');
const strengthLabel   = document.getElementById('genStrengthLabel');

// Password options
const pwLengthInput   = document.getElementById('pwLengthInput');
const pwLengthHint    = document.getElementById('pwLengthHint');
const chkUpper        = document.getElementById('chkUpper');
const chkLower        = document.getElementById('chkLower');
const chkDigits       = document.getElementById('chkDigits');
const chkSymbols      = document.getElementById('chkSymbols');
const minNumbers      = document.getElementById('minNumbers');
const minSpecial      = document.getElementById('minSpecial');
const chkNoAmbig      = document.getElementById('chkNoAmbig');

// Passphrase options
const ppWordCount     = document.getElementById('ppWordCount');
const ppWordHint      = document.getElementById('ppWordHint');
const ppSeparator     = document.getElementById('ppSeparator');
const ppCapitalize    = document.getElementById('ppCapitalize');
const ppIncludeNum    = document.getElementById('ppIncludeNum');

let _currentValue = '';

function setOutput(value, cssClass) {
  _currentValue = value;
  pwDisplay.textContent = value;
  pwDisplay.className = `gen-output-value ${cssClass}`;
}

function setStrengthBar(score, cssClass, label) {
  strengthFill.style.width      = `${score}%`;
  strengthFill.style.background = SCORE_COLORS[cssClass] ?? '#4f8ef7';
  strengthLabel.textContent     = label ?? '';
  strengthLabel.style.color     = SCORE_COLORS[cssClass] ?? '';
}

function doGenerate() {
  try {
    if (_genMode === 'password') _genPassword();
    else if (_genMode === 'passphrase') _genPassphrase();
    else _genUsername();
  } catch (e) {
    showToast(e.message);
  }
}

/* ── Password generation ─────────────────────────────────────── */
function _genPassword() {
  const len     = Math.max(5, Math.min(128, parseInt(pwLengthInput.value, 10) || 16));
  const minN    = Math.max(0, parseInt(minNumbers.value, 10) || 0);
  const minS    = Math.max(0, parseInt(minSpecial.value, 10) || 0);

  pwLengthHint.textContent = len < 14
    ? `Value must be between 5 and 128. Use 14 characters or more to generate a strong password.`
    : `Value must be between 5 and 128.`;

  const pw = generatePassword({
    length:      len,
    useUpper:    chkUpper.checked,
    useLower:    chkLower.checked,
    useDigits:   chkDigits.checked,
    useSymbols:  chkSymbols.checked,
    noAmbiguous: chkNoAmbig.checked,
    minNumbers:  minN,
    minSpecial:  minS,
  });

  const r = analyzePassword(pw);
  setOutput(pw, r.cssClass);
  setStrengthBar(r.score, r.cssClass, r.label);
  addToHistory('password', pw, r.score, r.label, r.cssClass);
}

/* ── Passphrase generation ───────────────────────────────────── */
function _genPassphrase() {
  const wc  = Math.max(3, Math.min(20, parseInt(ppWordCount.value, 10) || 6));
  const sep = ppSeparator.value; // any string including empty

  ppWordHint.textContent = wc < 6
    ? 'Value must be between 3 and 20. Use 6 words or more to generate a strong passphrase.'
    : 'Value must be between 3 and 20.';

  const { phrase } = generatePassphrase({
    wordCount:   wc,
    separator:   sep,
    capitalize:  ppCapitalize.checked,
    includeNum:  ppIncludeNum.checked,
  });

  const r = analyzePassword(phrase);
  setOutput(phrase, 'passphrase');
  setStrengthBar(r.score, r.cssClass, r.label);
  addToHistory('passphrase', phrase, r.score, r.label, r.cssClass);
}

/* ── Username generation ─────────────────────────────────────── */
function _genUsername() {
  const styleEl = document.querySelector('input[name="usernameStyle"]:checked');
  const style   = styleEl?.value ?? 'word';
  const name    = generateUsername(style);
  setOutput(name, 'username');
  addToHistory('username', name, 0, 'username', 'username');
}

/* ── Live regeneration on option change ──────────────────────── */
[pwLengthInput, minNumbers, minSpecial, chkUpper, chkLower, chkDigits,
 chkSymbols, chkNoAmbig].forEach(el => el?.addEventListener('change', doGenerate));

pwLengthInput.addEventListener('input', () => {
  const v = parseInt(pwLengthInput.value, 10);
  if (v >= 5 && v <= 128) doGenerate();
});

[ppWordCount, ppSeparator, ppCapitalize, ppIncludeNum].forEach(el => {
  el?.addEventListener('input', () => doGenerate());
  el?.addEventListener('change', () => doGenerate());
});

document.querySelectorAll('input[name="usernameStyle"]').forEach(el => {
  el.addEventListener('change', doGenerate);
});

regenerateBtn.addEventListener('click', doGenerate);

copyBtn.addEventListener('click', async () => {
  if (!_currentValue || _currentValue === '—') return;
  try {
    await navigator.clipboard.writeText(_currentValue);
    copyBtn.classList.add('copied');
    showToast('Copied to clipboard');
    setTimeout(() => copyBtn.classList.remove('copied'), 1500);
  } catch { showToast('Copy failed — select text manually'); }
});

// Initial generate
doGenerate();

/* ════════════════════════════════════════════════════════════════
   FILE VAULT
════════════════════════════════════════════════════════════════ */

let _encFile = null, _vaultFile = null;

/* ── Encrypt ─────────────────────────────────────────────────── */
const dropZone  = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const encPw     = document.getElementById('encPw');
const encryptBtn= document.getElementById('encryptBtn');
const encStatus = document.getElementById('encStatus');
const showEncPw = document.getElementById('showEncPw');
const encPwStrength = document.getElementById('encPwStrength');

function setEncFile(file) {
  _encFile = file;
  dropZone.classList.add('has-file');
  dropZone.querySelectorAll('p')[0].textContent = `📄 ${file.name}  (${formatBytes(file.size)})`;
  _checkEncReady();
}

function _checkEncReady() {
  encryptBtn.disabled = !(_encFile && encPw.value.length >= 1);
}

encPw.addEventListener('input', () => {
  _checkEncReady();
  const r = analyzePassword(encPw.value);
  if (!encPw.value) { encPwStrength.textContent = ''; return; }
  encPwStrength.textContent = r.label.toUpperCase();
  encPwStrength.style.color = SCORE_COLORS[r.cssClass] ?? '#4f8ef7';
});

showEncPw.addEventListener('click', () => {
  encPw.type = encPw.type === 'password' ? 'text' : 'password';
});

fileInput.addEventListener('change', e => { if (e.target.files[0]) setEncFile(e.target.files[0]); });

_setupDrop(dropZone, file => setEncFile(file));

encryptBtn.addEventListener('click', async () => {
  if (!_encFile || !encPw.value) return;
  encryptBtn.disabled = true;
  _setStatus(encStatus, 'Encrypting…', '');
  try {
    const blob = await encryptFile(_encFile, encPw.value);
    const out  = `${_encFile.name}.vault`;
    downloadBlob(blob, out);
    _setStatus(encStatus, `✓ Encrypted → ${out}`, 'ok');
    _addLog('encrypt', _encFile.name, formatBytes(_encFile.size));
    showToast('File encrypted & downloaded');
  } catch (e) {
    _setStatus(encStatus, `✗ ${e.message}`, 'err');
  } finally { encryptBtn.disabled = false; }
});

/* ── Decrypt ─────────────────────────────────────────────────── */
const dropZoneDec = document.getElementById('dropZoneDec');
const vaultInput  = document.getElementById('vaultInput');
const decPw       = document.getElementById('decPw');
const decryptBtn  = document.getElementById('decryptBtn');
const decStatus   = document.getElementById('decStatus');
const showDecPw   = document.getElementById('showDecPw');

function _setVaultFile(file) {
  _vaultFile = file;
  dropZoneDec.classList.add('has-file');
  dropZoneDec.querySelectorAll('p')[0].textContent = `🔒 ${file.name}`;
  _checkDecReady();
}

function _checkDecReady() {
  decryptBtn.disabled = !(_vaultFile && decPw.value.length >= 1);
}

decPw.addEventListener('input', _checkDecReady);
showDecPw.addEventListener('click', () => {
  decPw.type = decPw.type === 'password' ? 'text' : 'password';
});

vaultInput.addEventListener('change', e => { if (e.target.files[0]) _setVaultFile(e.target.files[0]); });
_setupDrop(dropZoneDec, file => _setVaultFile(file));

decryptBtn.addEventListener('click', async () => {
  if (!_vaultFile || !decPw.value) return;
  decryptBtn.disabled = true;
  _setStatus(decStatus, 'Decrypting…', '');
  try {
    const result = await decryptVault(_vaultFile, decPw.value);
    downloadBlob(result.blob, result.filename);
    _setStatus(decStatus, `✓ Decrypted → ${result.filename}`, 'ok');
    _addLog('decrypt', result.filename, '');
    showToast('File decrypted & downloaded');
  } catch (e) {
    _setStatus(decStatus, `✗ ${e.message}`, 'err');
    showToast('Decryption failed');
  } finally { decryptBtn.disabled = false; }
});

/* ── Vault helpers ───────────────────────────────────────────── */
function _setupDrop(zone, onFile) {
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]);
  });
  zone.addEventListener('click', () => {
    const inp = zone.querySelector('input[type=file]');
    if (inp) inp.click();
  });
}

function _setStatus(el, msg, type) {
  el.textContent = msg;
  el.className = `vault-status${type ? ' '+type : ''}`;
}

function _addLog(action, filename, detail) {
  const logList = document.getElementById('logList');
  logList.querySelector('.log-empty')?.remove();
  const now = new Date().toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
  const icons = { encrypt:'🔐', decrypt:'🔓' };
  const el = document.createElement('div');
  el.className = 'log-entry';
  el.innerHTML = `
    <span class="log-icon">${icons[action]}</span>
    <div class="log-info">
      <div class="log-name">${escHtml(filename)}</div>
      ${detail ? `<div class="log-detail">${escHtml(detail)}</div>` : ''}
    </div>
    <span class="log-time">${now}</span>
  `;
  logList.prepend(el);
}

/* ════════════════════════════════════════════════════════════════
   LAB ANALYSIS
════════════════════════════════════════════════════════════════ */

const labInput    = document.getElementById('labInput');
const labQuickFill= document.getElementById('labQuickFill');
const showLabPw   = document.getElementById('showLabPw');
const ringFill    = document.getElementById('ringFill');
const scoreNum    = document.getElementById('scoreNum');
const scoreLabel  = document.getElementById('scoreLabel');
const scoreEntropy= document.getElementById('scoreEntropy');
const pwLength    = document.getElementById('pwLength');
const patternList = document.getElementById('patternList');
const suggsList   = document.getElementById('suggestionsList');
const attackGraph = document.getElementById('attackGraph');

const classEls = {
  lower:  document.getElementById('clLower'),
  upper:  document.getElementById('clUpper'),
  digit:  document.getElementById('clDigit'),
  symbol: document.getElementById('clSymbol'),
};

showLabPw.addEventListener('click', () => {
  labInput.type = labInput.type === 'password' ? 'text' : 'password';
});

const RING_CIRC = 251.2;

function updateLabUI(r) {
  const color = SCORE_COLORS[r.cssClass] ?? '#4f8ef7';

  // Score ring
  ringFill.style.strokeDashoffset = RING_CIRC * (1 - r.score / 100);
  ringFill.style.stroke = color;
  scoreNum.textContent  = r.score;
  scoreNum.style.color  = color;
  scoreLabel.textContent = r.label;
  scoreLabel.style.color = color;
  scoreEntropy.textContent = `${r.entropy} bits`;
  pwLength.textContent   = `${r.length} chars`;

  // Quick bar
  labQuickFill.style.width      = `${r.score}%`;
  labQuickFill.style.background = color;

  // Character classes
  for (const [key, has] of [['lower',r.hasLower],['upper',r.hasUpper],['digit',r.hasDigit],['symbol',r.hasSymbol]]) {
    const el = classEls[key];
    el.classList.toggle('has-it', has);
    el.querySelector('.class-check').textContent = has ? '✓' : '✗';
  }

  // Patterns
  if (!r.penalties.length) {
    patternList.innerHTML = '<div class="pattern-item ok"><span class="pattern-icon">✓</span><span class="pattern-text">No common patterns detected.</span></div>';
  } else {
    patternList.innerHTML = r.penalties.map(p =>
      `<div class="pattern-item"><span class="pattern-icon">⚠</span><span class="pattern-text">${escHtml(p.desc)}</span></div>`
    ).join('');
  }

  // Attack risk analysis
  renderAttackGraph(r.entropy);

  // Suggestions
  if (!r.suggestions.length) {
    suggsList.innerHTML = '<div class="pattern-item ok"><span class="pattern-icon">✓</span><span class="pattern-text"><strong>Looks great!</strong> No recommendations.</span></div>';
  } else {
    suggsList.innerHTML = r.suggestions.map((s, i) =>
      `<div class="suggestion-item"><span class="suggestion-num">${i+1}</span><span>${escHtml(s.msg ?? s.message ?? '')}</span></div>`
    ).join('');
  }
}

/* ── Attack Risk Analysis graph ──────────────────────────────── */
const ATTACK_SCENARIOS = [
  { name: 'Online — rate limited',     detail: '10 attempts / minute',         gps: 10/60 },
  { name: 'Online — no limit',         detail: '1,000 attempts / second',       gps: 1_000 },
  { name: 'Offline — slow hash',       detail: '1M / sec  (bcrypt, Argon2)',    gps: 1_000_000 },
  { name: 'Offline — fast hash',       detail: '100B / sec  (MD5, SHA-1)',      gps: 100_000_000_000 },
];

const MAX_SAFE_LOG = Math.log10(3.154e9); // log10(100 years in seconds)

function _crackSeconds(entropyBits, gps) {
  return Math.pow(2, entropyBits) / (2 * gps);
}

function _secondsToBar(seconds) {
  if (seconds <= 0) return 0;
  const log = Math.min(Math.log10(Math.max(1, seconds)), MAX_SAFE_LOG);
  return Math.round((log / MAX_SAFE_LOG) * 100);
}

function _riskLevel(seconds) {
  if (seconds < 60)           return { cls:'critical', label:'CRITICAL', color:'#ff2d55' };
  if (seconds < 3600)         return { cls:'high',     label:'HIGH',     color:'#ff3b3b' };
  if (seconds < 86400)        return { cls:'elevated', label:'ELEVATED', color:'#ff8c00' };
  if (seconds < 86400*30)     return { cls:'medium',   label:'MEDIUM',   color:'#f5c518' };
  if (seconds < 86400*365*10) return { cls:'low',      label:'LOW',      color:'#34d399' };
  return                             { cls:'safe',     label:'SAFE',     color:'#00d97e' };
}

function _formatCrackTime(s) {
  if (s < 1)           return '< 1 second';
  if (s < 60)          return `${Math.round(s)} sec`;
  if (s < 3600)        return `${Math.round(s/60)} min`;
  if (s < 86400)       return `${Math.round(s/3600)} hours`;
  if (s < 86400*30)    return `${Math.round(s/86400)} days`;
  if (s < 86400*365)   return `${Math.round(s/(86400*30))} months`;
  if (s < 86400*365*1e3)  return `${Math.round(s/(86400*365))} years`;
  if (s < 86400*365*1e6)  return `${Math.round(s/(86400*365*1e3))}k years`;
  return 'Centuries+';
}

function renderAttackGraph(entropyBits) {
  if (!entropyBits) {
    attackGraph.innerHTML = '<p class="lab-empty">Enter a password to see attack risk by scenario.</p>';
    return;
  }

  let html = '';
  ATTACK_SCENARIOS.forEach((sc, i) => {
    const seconds = _crackSeconds(entropyBits, sc.gps);
    const barW    = _secondsToBar(seconds);
    const risk    = _riskLevel(seconds);
    const time    = _formatCrackTime(seconds);

    if (i > 0) html += '<hr class="attack-divider" />';
    html += `
      <div class="attack-row">
        <div class="attack-scenario">
          <span class="attack-name">${escHtml(sc.name)}</span>
          <span class="attack-detail">${escHtml(sc.detail)}</span>
        </div>
        <div class="attack-bar-wrap">
          <div class="attack-bar-fill" style="width:${barW}%;background:${risk.color}"></div>
        </div>
        <span class="attack-time">${time}</span>
        <span class="attack-risk risk-${risk.cls}">${risk.label}</span>
      </div>
    `;
  });

  attackGraph.innerHTML = html;
}

function resetLabUI() {
  ringFill.style.strokeDashoffset = RING_CIRC;
  ringFill.style.stroke = '#4f8ef7';
  scoreNum.textContent  = '—';
  scoreNum.style.color  = '';
  scoreLabel.textContent = '—';
  scoreLabel.style.color = '';
  scoreEntropy.textContent = '—';
  pwLength.textContent   = '—';
  labQuickFill.style.width = '0%';

  for (const key of Object.keys(classEls)) {
    classEls[key].classList.remove('has-it');
    classEls[key].querySelector('.class-check').textContent = '✗';
  }

  patternList.innerHTML  = '<p class="lab-empty">Enter a password to scan.</p>';
  suggsList.innerHTML    = '<p class="lab-empty">Enter a password to receive recommendations.</p>';
  attackGraph.innerHTML  = '<p class="lab-empty">Enter a password to see attack risk by scenario.</p>';
}

let _labDebounce;
labInput.addEventListener('input', () => {
  clearTimeout(_labDebounce);
  const pw = labInput.value;
  if (!pw) { resetLabUI(); return; }
  _labDebounce = setTimeout(() => {
    const r = analyzePassword(pw);
    if (r) updateLabUI(r);
  }, 80);
});
