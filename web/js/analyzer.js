/**
 * analyzer.js — Password strength analysis (JavaScript port of analyzer/ package)
 *
 * Implements the same scoring pipeline as the Python backend:
 *   charset entropy → structural penalty → pattern penalties → dictionary check
 *   → 0-100 score → suggestions
 */

'use strict';

/* ── Common passwords blocklist ──────────────────────────────── */
const COMMON_PASSWORDS = new Set([
  // Top breach passwords
  'password','password1','password123','password!','passw0rd','p@ssword','p@ssw0rd',
  '123456','1234567','12345678','123456789','1234567890','12345','123123','111111',
  '000000','654321','666666','696969','1q2w3e','1q2w3e4r','1q2w3e4r5t',
  'qwerty','qwerty123','qwertyuiop','qweasdzxc','asdfgh','asdfghjkl','zxcvbn',
  'abc123','abcdef','abcd1234','letmein','login','welcome','hello','hello123',
  'monkey','dragon','master','shadow','sunshine','princess','football','baseball',
  'michael','batman','superman','spiderman','starwars','solo','iloveyou',
  'admin','admin123','admin1234','administrator','root','root123','toor',
  'guest','user','test','test123','temp','temp123','demo','demo123',
  'changeme','change_me','mustchange','default','blank',
  'trustno1','letmein1','qazwsx','qazwsxedc','1qaz2wsx','zaq1xsw2',
  'pass','pass123','passpass','mypassword','mypass','newpassword',
  'google','amazon','facebook','twitter','instagram','linkedin','netflix',
  'summer','summer1','summer2023','summer2024','winter','winter2023','winter2024',
  'spring','spring2023','spring2024','autumn','autumn2023',
  'january','february','march','april','june','july','august',
  'september','october','november','december',
  '0987654321','1111111111','2222222222','1234554321','9876543210',
  'pass@123','pass@1234','password@1','password@123','p@$$word','p@$$w0rd',
  'abc@123','admin@123','test@123','user@123','login@123',
  'football1','baseball1','soccer','hockey','tennis','basketball',
  'sunshine1','princess1','dragon1','monkey1','shadow1','master1',
  'whatever','nothing','nobody','someone','anyone','everyone',
  'computer','internet','server','network','database','security',
  'secret','mysecret','topsecret','classified','private',
  'love','loveyou','iloveyou1','123love','love123',
  'happy','happy1','happy123','lucky','lucky1','lucky123',
  'access','access1','access123','guest123','visitor','visitor123',
]);

/* ── Leet normaliser ─────────────────────────────────────────── */
const LEET_MAP = { '@':'a','4':'a','3':'e','1':'i','!':'i','0':'o',
                   '5':'s','$':'s','7':'t','+':'t','9':'g','6':'b','8':'b' };

function normalizeLeet(pw) {
  return pw.toLowerCase().split('').map(c => LEET_MAP[c] ?? c).join('');
}

/* ── Entropy ─────────────────────────────────────────────────── */
function charsetEntropy(pw) {
  if (!pw) return 0;
  let size = 0;
  if (/[a-z]/.test(pw)) size += 26;
  if (/[A-Z]/.test(pw)) size += 26;
  if (/[0-9]/.test(pw)) size += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) size += 32;
  return pw.length * Math.log2(Math.max(size, 1));
}

/* ── Structural factor (mirrors Python's zlib heuristic) ─────── */
// Detects repetitive / low-diversity passwords that charset entropy overstates.
// Returns a factor in [0.4, 1.0] — lower = more repetitive.
function structuralFactor(pw) {
  if (pw.length < 4) return 1.0;
  const unique      = new Set(pw).size;
  const uniqueRatio = unique / pw.length;          // 1/len for all-same, 1.0 for all-different
  let maxRun = 1, run = 1;
  for (let i = 1; i < pw.length; i++) {
    run = pw[i] === pw[i - 1] ? run + 1 : 1;
    if (run > maxRun) maxRun = run;
  }
  const runPenalty = 1.0 - (maxRun - 1) / pw.length; // 0 for all-same, 1.0 for no runs
  const factor     = Math.min(uniqueRatio * 2, 1.0) * runPenalty;
  return Math.max(0.4, factor);                    // floor at 0.4 matches Python
}

/* ── Pattern detectors ───────────────────────────────────────── */
const KB_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];
const KB_ADJ = {};
for (const row of KB_ROWS) {
  for (let i = 0; i < row.length; i++) {
    const ch = row[i], neighbours = new Set();
    if (i > 0) neighbours.add(row[i-1]);
    if (i < row.length-1) neighbours.add(row[i+1]);
    KB_ADJ[ch] = neighbours;
    KB_ADJ[ch.toUpperCase()] = new Set([...neighbours].map(x => x.toUpperCase()));
  }
}

function longestKeyboardWalk(pw) {
  if (pw.length < 2) return { len: 0, fragment: '' };
  let bestLen = 1, bestStart = 0, runLen = 1, runStart = 0;
  for (let i = 1; i < pw.length; i++) {
    const a = pw[i-1].toLowerCase(), b = pw[i].toLowerCase();
    if (KB_ADJ[a]?.has(b)) {
      runLen++;
    } else {
      if (runLen > bestLen) { bestLen = runLen; bestStart = runStart; }
      runStart = i; runLen = 1;
    }
  }
  if (runLen > bestLen) { bestLen = runLen; bestStart = runStart; }
  return { len: bestLen, fragment: pw.slice(bestStart, bestStart + bestLen) };
}

function longestSequentialRun(pw) {
  if (pw.length < 2) return { len: 0, fragment: '' };
  let bestLen = 1, bestStart = 0;
  for (const dir of [1, -1]) {
    let runLen = 1, runStart = 0;
    for (let i = 1; i < pw.length; i++) {
      if (pw[i].toLowerCase().charCodeAt(0) - pw[i-1].toLowerCase().charCodeAt(0) === dir) {
        runLen++;
      } else {
        if (runLen > bestLen) { bestLen = runLen; bestStart = runStart; }
        runStart = i; runLen = 1;
      }
    }
    if (runLen > bestLen) { bestLen = runLen; bestStart = runStart; }
  }
  return { len: bestLen, fragment: pw.slice(bestStart, bestStart + bestLen) };
}

function detectPatterns(pw) {
  const penalties = [];

  // Keyboard walk
  const walk = longestKeyboardWalk(pw);
  if (walk.len >= 6) {
    penalties.push({ name: 'keyboard_walk', factor: 0.2,
      desc: `Long keyboard walk "${walk.fragment}"`, match: walk.fragment });
  } else if (walk.len >= 4) {
    penalties.push({ name: 'keyboard_walk', factor: 0.5,
      desc: `Keyboard walk "${walk.fragment}"`, match: walk.fragment });
  }

  // Sequential
  const seq = longestSequentialRun(pw);
  if (seq.len >= 5) {
    penalties.push({ name: 'sequential', factor: 0.3,
      desc: `Long sequential run "${seq.fragment}"`, match: seq.fragment });
  } else if (seq.len >= 4) {
    penalties.push({ name: 'sequential', factor: 0.6,
      desc: `Sequential characters "${seq.fragment}"`, match: seq.fragment });
  }

  // Repeating chars
  const repeatMatch = pw.match(/(.)\1{2,}/);
  if (repeatMatch) {
    penalties.push({ name: 'repeating', factor: 0.6,
      desc: `Repeated character "${repeatMatch[1]}"`, match: repeatMatch[1] });
  }

  // Date pattern
  const dateMatch = pw.match(/(19|20)\d{2}|\d{1,2}[\/\-]\d{1,2}|(?<!\d)\d{4}(?!\d)/);
  if (dateMatch) {
    penalties.push({ name: 'date', factor: 0.7,
      desc: `Date/year pattern "${dateMatch[0]}"`, match: dateMatch[0] });
  }

  return penalties;
}

/* ── Dictionary check ────────────────────────────────────────── */
function isCommonPassword(pw) {
  return COMMON_PASSWORDS.has(pw) ||
         COMMON_PASSWORDS.has(pw.toLowerCase()) ||
         COMMON_PASSWORDS.has(normalizeLeet(pw));
}

/* ── Score assembly ──────────────────────────────────────────── */
const BREAKPOINTS = [[0,0],[28,25],[36,40],[60,75],[100,100]];

function entropyToScore(bits) {
  if (bits <= 0) return 0;
  if (bits >= BREAKPOINTS.at(-1)[0]) return BREAKPOINTS.at(-1)[1];
  for (let i = 1; i < BREAKPOINTS.length; i++) {
    const [e0,s0] = BREAKPOINTS[i-1], [e1,s1] = BREAKPOINTS[i];
    if (bits >= e0 && bits <= e1) {
      return Math.round(s0 + ((bits-e0)/(e1-e0)) * (s1-s0));
    }
  }
  return 0;
}

function scoreToLabel(score) {
  if (score < 25) return 'Very Weak';
  if (score < 40) return 'Weak';
  if (score < 60) return 'Fair';
  if (score < 80) return 'Strong';
  return 'Very Strong';
}

function scoreToCssClass(score) {
  if (score < 25) return 'weak';
  if (score < 40) return 'fair';
  if (score < 60) return 'good';
  if (score < 80) return 'strong';
  return 'vstrong';
}

/* ── Crack time estimate ─────────────────────────────────────── */
function crackTimeEstimate(effectiveBits) {
  // Assume 10 billion guesses/sec (high-end GPU cluster on fast hash)
  // For bcrypt/Argon2 the real number is far lower, but this is conservative
  const gps = 1e10;
  const seconds = (Math.pow(2, effectiveBits) / gps) / 2;
  if (!isFinite(seconds) || seconds > 1e18) return 'Centuries+';
  if (seconds < 1) return 'Instantly';
  if (seconds < 60) return `${seconds.toFixed(0)} seconds`;
  if (seconds < 3600) return `${(seconds/60).toFixed(0)} minutes`;
  if (seconds < 86400) return `${(seconds/3600).toFixed(0)} hours`;
  if (seconds < 31536000) return `${(seconds/86400).toFixed(0)} days`;
  if (seconds < 3153600000) return `${(seconds/31536000).toFixed(0)} years`;
  return 'Centuries+';
}

/* ── Suggestions ─────────────────────────────────────────────── */
function buildSuggestions(pw, penalties, isCommon) {
  if (isCommon) return [{
    msg: 'This password (or a close variant) appears in known breach databases. Choose a completely different base — capitalising or adding "1!" to a known password does not make it secure.',
  }];

  const suggestions = [];
  const hasLower  = /[a-z]/.test(pw);
  const hasUpper  = /[A-Z]/.test(pw);
  const hasDigit  = /[0-9]/.test(pw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pw);

  if (pw.length < 8)
    suggestions.push({ pri: 1, msg: 'Extend to at least 12 characters. Length is the single most effective security lever.' });
  else if (pw.length < 12)
    suggestions.push({ pri: 2, msg: 'Extend to 16+ characters for a strong password.' });

  if (!hasUpper && !hasLower)
    suggestions.push({ pri: 3, msg: 'Mix upper and lower-case letters to expand the search space.' });
  else if (!hasUpper)
    suggestions.push({ pri: 4, msg: 'Add at least one uppercase letter (A–Z).' });
  else if (!hasLower)
    suggestions.push({ pri: 4, msg: 'Add at least one lowercase letter (a–z).' });

  if (!hasDigit)
    suggestions.push({ pri: 5, msg: 'Include at least one digit (0–9). Avoid placing it only at the start or end.' });

  if (!hasSymbol)
    suggestions.push({ pri: 6, msg: 'Add a symbol such as ! @ # $ % ^ & * to multiply the effective search space.' });

  for (const p of penalties) {
    if (p.name === 'keyboard_walk')
      suggestions.push({ pri: 7, msg: `Replace the keyboard walk "${p.match}" with unrelated characters.` });
    if (p.name === 'sequential')
      suggestions.push({ pri: 7, msg: `Avoid sequential runs like "${p.match}" — attackers include these in targeted masks.` });
    if (p.name === 'repeating')
      suggestions.push({ pri: 8, msg: `Remove repeated characters "${p.match}${p.match}${p.match}" — they add almost no entropy.` });
    if (p.name === 'date')
      suggestions.push({ pri: 8, msg: `Remove the date/year pattern "${p.match}". Attackers include date ranges in wordlists.` });
  }

  return suggestions.sort((a, b) => a.pri - b.pri);
}

/* ── Master analysis function ────────────────────────────────── */
function analyzePassword(pw) {
  if (!pw) return null;

  const hasLower  = /[a-z]/.test(pw);
  const hasUpper  = /[A-Z]/.test(pw);
  const hasDigit  = /[0-9]/.test(pw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pw);

  const raw = charsetEntropy(pw);
  const penalties = detectPatterns(pw);
  const common = isCommonPassword(pw);

  if (common) {
    penalties.push({ name: 'common_password', factor: 0.05,
      desc: 'Password found in common-password list or breach databases', match: pw });
  }

  // Structural penalty (repetitive/low-diversity passwords) then pattern penalties
  const base     = raw * structuralFactor(pw);
  const factor   = penalties.reduce((f, p) => f * p.factor, 1.0);
  const effective = base * factor;

  let score = entropyToScore(effective);
  if (pw.length < 8) score = Math.min(score, 30); // policy floor

  return {
    score,
    label: scoreToLabel(score),
    cssClass: scoreToCssClass(score),
    entropy: Math.round(effective * 10) / 10,
    rawEntropy: Math.round(raw * 10) / 10,
    crackTime: crackTimeEstimate(effective),
    penalties,
    suggestions: buildSuggestions(pw, penalties, common),
    isCommon: common,
    hasLower, hasUpper, hasDigit, hasSymbol,
    length: pw.length,
  };
}
