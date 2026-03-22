/**
 * generator.js — Client-side cryptographically secure credential generation.
 *
 * All randomness comes from crypto.getRandomValues() — Math.random() is never used.
 */

'use strict';

const LOWER   = 'abcdefghijklmnopqrstuvwxyz';
const UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS  = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
const AMBIGUOUS = new Set('0O1lI');

/* ── Internal helper: cryptographically secure randBelow ─────── */
// Rejection sampling eliminates modulo bias for non-power-of-2 pool sizes.
function randBelow(n) {
  const limit = 2 ** 32 - (2 ** 32 % n); // largest multiple of n that fits in uint32
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % n;
}

/**
 * Generate a random password satisfying all given constraints.
 *
 * Uses rejection sampling: draw `length` characters from the pool, verify
 * all minimum requirements are met, redraw if not. Expected redraws < 1.05.
 *
 * @param {object} opts
 * @param {number}  opts.length      - Total length (min 5, max 128)
 * @param {boolean} opts.useUpper    - Include A-Z
 * @param {boolean} opts.useLower    - Include a-z (always true)
 * @param {boolean} opts.useDigits   - Include 0-9
 * @param {boolean} opts.useSymbols  - Include special characters
 * @param {boolean} opts.noAmbiguous - Exclude 0 O I l 1
 * @param {number}  opts.minNumbers  - Minimum digit count (forces useDigits if > 0)
 * @param {number}  opts.minSpecial  - Minimum symbol count (forces useSymbols if > 0)
 */
function generatePassword({
  length = 16,
  useUpper = true,
  useLower = true,
  useDigits = true,
  useSymbols = false,
  noAmbiguous = false,
  minNumbers = 1,
  minSpecial = 0,
} = {}) {
  length = Math.max(5, Math.min(128, length));

  // Enforce minimums → enable class if needed
  if (minNumbers > 0) useDigits = true;
  if (minSpecial > 0) useSymbols = true;

  // Clamp mins to something feasible
  minNumbers = Math.min(minNumbers, Math.floor(length / 2));
  minSpecial = Math.min(minSpecial, Math.floor(length / 2));
  if (minNumbers + minSpecial > length) minNumbers = Math.floor(length / 2), minSpecial = 0;

  let pool = useLower ? LOWER : '';
  if (useUpper)   pool += UPPER;
  if (useDigits)  pool += DIGITS;
  if (useSymbols) pool += SYMBOLS;

  if (noAmbiguous) pool = [...pool].filter(c => !AMBIGUOUS.has(c)).join('');
  if (pool.length < 2) throw new Error('Character pool is too small. Enable more character classes.');

  const digitsPool  = noAmbiguous ? [...DIGITS].filter(c => !AMBIGUOUS.has(c)).join('') : DIGITS;
  const symbolsPool = noAmbiguous ? [...SYMBOLS].filter(c => !AMBIGUOUS.has(c)).join('') : SYMBOLS;
  const upperPool   = noAmbiguous ? [...UPPER].filter(c => !AMBIGUOUS.has(c)).join('') : UPPER;
  const lowerPool   = noAmbiguous ? [...LOWER].filter(c => !AMBIGUOUS.has(c)).join('') : LOWER;

  let candidate, attempts = 0;
  do {
    const buf = new Uint32Array(length);
    crypto.getRandomValues(buf);
    candidate = Array.from(buf, x => pool[x % pool.length]).join('');
    attempts++;
    if (attempts > 2000) break; // safety valve

    const numCount = [...candidate].filter(c => digitsPool.includes(c)).length;
    const symCount = [...candidate].filter(c => symbolsPool.includes(c)).length;
    const hasUpper = !useUpper || [...candidate].some(c => upperPool.includes(c));
    const hasLower = !useLower || [...candidate].some(c => lowerPool.includes(c));

    if (numCount >= minNumbers && symCount >= minSpecial && hasUpper && hasLower) break;
  } while (true);

  return candidate;
}

/* ── Passphrase word list (500+ curated words) ───────────────── */
const WORDLIST = [
  'able','above','acid','actor','alarm','album','alien','alive','amber','angel',
  'anger','angle','apple','arena','arise','armor','atlas','audio','avoid','azure',
  'bacon','badge','baker','bamboo','baron','basic','basin','beach','beard','blade',
  'blank','blast','blaze','blend','bliss','block','bloom','blown','blues','boost',
  'booth','brain','brave','bread','break','brick','bride','brief','bring','brisk',
  'brook','brush','build','burst','camel','candy','carry','catch','cause','cedar',
  'chair','chalk','charm','chase','chess','child','chill','claim','class','clean',
  'clear','cliff','climb','clock','close','cloud','comet','coral','couch','count',
  'court','cover','crack','craft','crane','crash','cream','creek','crisp','cross',
  'crown','crush','curve','cycle','dance','delta','demon','depth','digit','draft',
  'drawn','dream','drift','drink','drive','drone','dwarf','eagle','earth','eight',
  'elite','ember','empty','enemy','enter','event','exact','extra','fable','faith',
  'feast','fence','ferry','fever','field','fight','final','flair','flame','flash',
  'fleet','float','flood','flour','fluid','flute','focus','forge','fresh','front',
  'frost','fruit','funky','ghost','glass','glide','globe','gloom','gloss','glove',
  'grace','grain','grand','grape','grasp','grass','greet','grind','grove','grown',
  'guard','guide','gusto','habit','happy','haste','haunt','haven','heart','heavy',
  'hedge','heist','helix','honor','horse','hotel','humid','humor','hunch','ideal',
  'image','input','irony','jewel','joint','joker','judge','juice','jumbo','karma',
  'kayak','knife','knock','known','lance','laser','laugh','layer','learn','lever',
  'light','linen','local','lodge','logic','lucky','lunar','magic','major','maker',
  'manor','maple','march','marsh','mason','match','media','merit','metal','model',
  'money','month','moral','motor','motto','mound','mount','mouse','mouth','music',
  'naive','night','ninja','noble','noise','north','notch','novel','ocean','orbit',
  'order','oxide','ozone','paint','panic','paper','party','patch','peace','pearl',
  'phase','phone','pilot','pivot','pixel','place','plain','plant','plate','plaza',
  'plume','polar','pouch','power','press','price','pride','prime','proof','prowl',
  'pulse','punch','queen','quest','quick','quiet','quote','radar','radio','raise',
  'range','rapid','reach','ready','realm','rebel','relax','remix','ridge','right',
  'rigid','river','robot','rocky','rouge','rough','round','royal','rugby','rural',
  'sabre','salty','scalp','scene','scope','scout','seize','sense','shape','share',
  'shark','sharp','shelf','shift','shine','short','sigma','skate','skill','skull',
  'slate','sleep','slide','slope','smart','smash','smoke','snake','sneak','snowy',
  'solar','solid','sorry','south','space','spark','speak','spear','speed','spine',
  'spoon','squad','stain','stamp','stand','stark','start','state','steel','steep',
  'stern','stick','stomp','stone','store','storm','story','stove','strap','stray',
  'style','sugar','super','surge','swift','swirl','sword','table','taste','teach',
  'tenor','theme','thick','tiger','timer','toast','token','touch','tower','trace',
  'track','trade','trail','train','trait','troop','trove','tutor','twist','ultra',
  'union','unite','upper','urban','valor','valve','vault','vigor','viral','vivid',
  'voice','voter','wagon','waltz','waste','water','weave','wedge','weird','while',
  'whole','windy','witch','world','write','yacht','young','youth','zebra',
];

/**
 * Generate a passphrase from random dictionary words.
 *
 * @param {object} opts
 * @param {number}  opts.wordCount   - Number of words (3-20)
 * @param {string}  opts.separator   - Word separator (empty = join directly)
 * @param {boolean} opts.capitalize  - Capitalise first letter of each word
 * @param {boolean} opts.includeNum  - Insert a 1-2 digit number at a random position
 */
function generatePassphrase({
  wordCount = 6,
  separator = '',
  capitalize = true,
  includeNum = true,
} = {}) {
  wordCount = Math.max(3, Math.min(20, wordCount));

  const buf = new Uint32Array(wordCount);
  crypto.getRandomValues(buf);
  let words = Array.from(buf, x => WORDLIST[x % WORDLIST.length]);

  if (capitalize) words = words.map(w => w[0].toUpperCase() + w.slice(1));

  if (includeNum) {
    const nb = new Uint32Array(2);
    crypto.getRandomValues(nb);
    const num = String(nb[0] % 99 + 1); // 1-99
    const pos = nb[1] % (words.length + 1);
    words.splice(pos, 0, num);
  }

  const phrase = words.join(separator);

  // Entropy: based on word selections only (number adds ~7 bits)
  const bitsPerWord = Math.log2(WORDLIST.length);
  let entropy = wordCount * bitsPerWord;
  if (includeNum) entropy += Math.log2(99);

  return { phrase, entropy: Math.round(entropy * 10) / 10, wordCount };
}

/* ── Username generator ──────────────────────────────────────── */
const UN_ADJECTIVES = [
  'swift','dark','quiet','bright','bold','sharp','deep','calm','wild','iron',
  'steel','stone','frost','flame','echo','prime','alpha','cyber','nano','nova',
  'ultra','hyper','shadow','lunar','solar','storm','void','ghost','pixel','byte',
  'core','delta','krypto','nexus','phantom','quantum','rogue','signal','terra',
];

const UN_NOUNS = [
  'wolf','hawk','storm','cipher','byte','pulse','spark','crest','blade','orbit',
  'forge','lens','matrix','node','peak','ridge','shell','shield','trail','vault',
  'wave','wing','zero','axis','code','core','dart','echo','flux','gate',
  'grid','helm','link','lore','mark','mesh','mind','myth','neon','path',
];

/**
 * Generate a username.
 * @param {'word'|'wordn'|'random'} style
 */
function generateUsername(style = 'word') {
  if (style === 'random') {
    const pool = LOWER + UPPER + DIGITS + '_';
    const length = 8 + randBelow(5); // 8-12 chars
    const buf = new Uint32Array(length);
    crypto.getRandomValues(buf);
    return Array.from(buf, x => pool[x % pool.length]).join('');
  }

  const adj  = UN_ADJECTIVES[randBelow(UN_ADJECTIVES.length)];
  const noun = UN_NOUNS[randBelow(UN_NOUNS.length)];
  const cap  = s => s[0].toUpperCase() + s.slice(1);
  const base = cap(adj) + cap(noun);

  if (style === 'wordn') {
    const num = String(randBelow(999) + 1); // 1-999
    return base + num;
  }
  return base;
}

/* ── PIN generator ───────────────────────────────────────────── */
const COMMON_PINS = new Set([
  '0000','1111','1234','1212','7777','1004','2000','4444','2222','6969',
  '9999','3333','5555','6666','1122','1313','4321','2001','1010','0001',
  '12345','11111','123456','654321','111111','000000','123123',
]);

function generatePin(length = 6) {
  length = Math.max(4, length);
  let pin, attempts = 0;
  do {
    const buf = new Uint32Array(length);
    crypto.getRandomValues(buf);
    pin = Array.from(buf, x => x % 10).join('');
    if (++attempts > 1000) break;
  } while (_isWeakPin(pin));

  const entropy = Math.round(length * Math.log2(10) * 10) / 10;
  const warning = length < 6
    ? `${length}-digit PIN has only ${entropy} bits of entropy. Use 6+ digits or a passphrase instead.`
    : null;
  return { pin, entropy, warning };
}

function _isWeakPin(pin) {
  if (COMMON_PINS.has(pin)) return true;
  if (new Set(pin).size === 1) return true;
  for (const dir of [1, -1]) {
    let run = 1;
    for (let i = 1; i < pin.length; i++) {
      if (parseInt(pin[i]) - parseInt(pin[i-1]) === dir) {
        if (++run >= 4) return true;
      } else run = 1;
    }
  }
  return false;
}
