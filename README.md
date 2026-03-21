# Password Analyzer / Smart Generator

A command-line tool that scores password strength, explains weaknesses, and generates cryptographically secure credentials — with zero required dependencies beyond Python's standard library.

```
╭─────────────────── Password Analysis ───────────────────╮
│ ████████████████████████░░░░░░░░░░░░░░  Strong (64/100) │
╰─────────────────────────────────────────────────────────╯

  Entropy   52.4 bits effective  (raw: 65.5 bits)
  Classes   Lowercase ✓   Uppercase ✓   Digits ✓   Symbols ✓

  Recommendations:
    1. Extend to 16+ characters for a strong password (+39.3 bits).
```

---

## Features

| Feature | Details |
|---|---|
| Strength scoring | 0–100 score anchored at real cryptographic entropy thresholds |
| Pattern detection | Keyboard walks, sequential runs, date patterns, repeating chars |
| Leet-speak detection | `p@ssw0rd` is caught the same as `password` |
| Common-password blocklist | 130+ breached passwords checked on every analysis |
| Optional HIBP check | SHA-1 k-anonymity — your password never leaves the machine |
| Auto-suggestions | Ranked by entropy gain per character, not generic tips |
| Random password generator | `secrets.SystemRandom()`, rejection-sampled for policy compliance |
| Passphrase generator | Diceware-style word phrases (≥45 bits at 5 words) |
| PIN generator | Blocks all-same, sequential, and top-20 common PINs |
| JSON output | `--json` for scripting and pipeline use |
| No required deps | Falls back to ANSI plain renderer if `rich` is not installed |

---

## Installation

```bash
git clone https://github.com/your-username/Password-Analyzer-Smart-Generator
cd Password-Analyzer-Smart-Generator

# Optional: install rich for polished output
pip install rich

# Run immediately — no install step needed
python main.py --help
```

---

## Usage

### Analyze a Password

```bash
# Pass inline
python main.py analyze "MyP@ssword123"

# Prompted securely (not echoed, not in shell history)
python main.py analyze

# Piped from another command
echo "MyP@ssword123" | python main.py analyze

# Also query HaveIBeenPwned (k-anonymity — safe)
python main.py analyze --check-hibp "MyP@ssword123"

# Machine-readable JSON for scripting
python main.py analyze --json "MyP@ssword123"
```

### Generate a Password

```bash
# Random password (default: 16 chars, all character classes)
python main.py generate

# Longer, no ambiguous chars (0 O l 1 I)
python main.py generate --length 24 --no-ambiguous

# Show full strength analysis of the generated password
python main.py generate --length 20 --analyze

# No symbols (for systems with restricted charsets)
python main.py generate --no-symbols
```

### Generate a Passphrase

```bash
# 5-word passphrase (default)
python main.py generate --mode passphrase

# 6 words, augmented with digit + symbol for policy compliance
python main.py generate --mode passphrase --words 6 --augment

# Custom separator, capitalised words
python main.py generate --mode passphrase --separator " " --capitalize
```

### Generate a PIN

```bash
python main.py generate --mode pin           # 6-digit PIN (default)
python main.py generate --mode pin --length 8
```

---

## Scoring Algorithm

The score is computed in a **pipeline of independent signal modules**. Each stage can be understood and tested independently.

### Stage 1 — Charset Entropy (theoretical ceiling)

```
H = L × log₂(N)
```

Where `L` = password length and `N` = active charset size (26 + 26 + 10 + 32 for all four classes).

This is deliberately *optimistic* — it assumes every character was drawn uniformly at random from the full charset. Pattern penalties reduce it toward the true value.

### Stage 2 — Structural Entropy (zlib heuristic)

A second entropy estimate compresses the password with `zlib`. If the compressed form is significantly shorter than the original, the password has exploitable internal structure that the charset model cannot see (e.g., `abababababab`). The compression ratio drives a structural penalty factor.

```python
ratio = len(zlib.compress(password)) / len(password)
structure_factor = max(0.4, min(1.0, ratio))
effective_entropy_ceiling = charset_entropy × structure_factor
```

### Stage 3 — Pattern Penalties (multiplicative)

Each detector returns a `factor ∈ [0, 1]`. Factors compose multiplicatively so independent weaknesses stack correctly — two 0.5-factor penalties yield 0.25, not 0.0.

| Detector | Condition | Factor |
|---|---|---|
| Keyboard walk | 4+ adjacent keys (`qwer`) | 0.5 |
| Keyboard walk | 6+ adjacent keys (`qwerty`) | 0.2 |
| Sequential chars | 4+ sequential (`abcd`, `1234`) | 0.6 |
| Sequential chars | 5+ sequential | 0.3 |
| Repeating chars | 3+ identical in a row (`aaa`) | 0.6 |
| Date/year pattern | `2023`, `5/12`, isolated 4-digit | 0.7 |
| Common password | In blocklist or leet-normalised variant | 0.05 |

### Stage 4 — Score Assembly & Policy Floor

```
effective_entropy = base_entropy × ∏(penalty.factor)
score = piecewise_linear(effective_entropy, breakpoints)
```

| Effective Entropy | Score | Rationale |
|---|---|---|
| 0 bits | 0 | — |
| 28 bits | 25 (Weak) | GPU cracks bcrypt cost-10 in < 1 second |
| 60 bits | 75 (Strong) | Offline cracking infeasible on current KDFs |
| 100 bits | 100 (Very Strong) | — |

A policy floor caps any password under 8 characters at score 30 regardless of entropy. This is a policy decision, not a mathematical one — no reasonable system should accept sub-8-character passwords.

---

## Generation Design

All three generators use `secrets.SystemRandom()` (wraps `os.urandom()`). The `random` module is never imported in the generator package.

**Random passwords** use rejection sampling: draw `length` characters, verify all required classes are present, redraw if not. Expected redraws: < 1.02 for any reasonable configuration.

**Passphrases** draw uniformly from a ~500-word bundled wordlist using `secrets.randbelow(len(wordlist))`. 5 words yields ≈45 bits; the `--augment` flag appends a digit and symbol for systems requiring character-class diversity.

**PINs** block all-same digits, ascending/descending runs of 4+, and the 20 most common PINs from breach data.

---

## Project Structure

```
├── main.py                  # CLI entry point (argparse)
├── analyzer/
│   ├── scorer.py            # Master scoring pipeline → AnalysisResult
│   ├── entropy.py           # charset_entropy + conditional_entropy (zlib)
│   ├── patterns.py          # Pattern detectors + leet normalizer
│   ├── dictionary.py        # Common-password blocklist + optional HIBP
│   └── suggestions.py       # Signal → ranked fix suggestions
├── generator/
│   ├── random_gen.py        # Cryptographically secure character passwords
│   ├── passphrase.py        # Diceware-style word passphrases
│   └── pin.py               # PIN generator with weak-PIN rejection
├── display/
│   ├── plain.py             # ANSI colour renderer (stdlib only)
│   └── rich_display.py      # Rich-powered renderer (optional)
├── data/
│   ├── common_passwords.txt # Blocked common passwords
│   └── wordlist.txt         # Word pool for passphrases
└── tests/                   # 64 tests, all independent, no mocks
```

---

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
# 64 passed
```

Tests cover:
- Known bad passwords score correctly (e.g., `password` → Very Weak)
- Leet variants are caught (`p@ssw0rd` → caught)
- All generators satisfy their own policies in statistical runs
- PIN generator never produces sequential/all-same/top-20 PINs
- Entropy functions agree with analytic values

---

## Security Notes

- **Passwords are never stored.** The `analyze` command accepts via argument, pipe, or `getpass` prompt only.
- **HIBP uses k-anonymity.** Only the first 5 hex characters of the SHA-1 hash are sent. The full hash and original password never leave the machine.
- **Generators use `os.urandom()` exclusively.** The `random` module (based on Mersenne Twister, not cryptographically secure) is never used in generation code.
- **The common-password check is a floor, not a ceiling.** A password not in the blocklist is not automatically safe — that's what the entropy scoring is for.
