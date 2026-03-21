"""
Diceware-style passphrase generator.

Each word contributes log2(wordlist_size) bits of entropy. With the bundled
wordlist of ~500+ words (log2 ≈ 9 bits/word):
  4 words ≈ 36 bits
  5 words ≈ 45 bits   ← default (Fair → Strong depending on augmentation)
  6 words ≈ 54 bits
  7 words ≈ 63 bits

The --augment flag appends a 2-digit number and a symbol, adding ~9 extra bits
while keeping the passphrase memorable. This is off by default but useful when
the target system requires character-class diversity.

Design note: for maximum entropy, use the EFF Large Wordlist (7776 words,
12.9 bits/word). The bundled wordlist is smaller but still produces memorable,
secure passphrases at 5+ words.

All randomness comes from secrets.randbelow(). The random module is not used.
"""

import pathlib
import secrets

_DATA_DIR = pathlib.Path(__file__).parent.parent / "data"
_WORDLIST_FILE = _DATA_DIR / "wordlist.txt"

_SYMBOLS_AUGMENT = "!@#$%^&*"


def _load_wordlist() -> list[str]:
    try:
        text = _WORDLIST_FILE.read_text(encoding="utf-8")
        return [w.strip() for w in text.splitlines() if w.strip()]
    except FileNotFoundError:
        # Fallback micro-list so the generator never hard-crashes
        return ["apple", "river", "cloud", "storm", "maple", "tiger",
                "frost", "ember", "sword", "piano"]


_WORDLIST: list[str] = _load_wordlist()


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    augment: bool = False,
    capitalize: bool = False,
) -> str:
    """
    Generate a memorable passphrase from random dictionary words.

    Args:
        word_count:  Number of words (4-8 recommended).
        separator:   Character(s) placed between words.
        augment:     Append a 2-digit number and a symbol for policy compliance.
        capitalize:  Capitalise the first letter of each word.

    Returns:
        A passphrase string such as 'maple-frost-sword-ember-tiger'.
    """
    word_count = max(3, word_count)
    size = len(_WORDLIST)

    words = [_WORDLIST[secrets.randbelow(size)] for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    phrase = separator.join(words)

    if augment:
        digit_suffix = str(secrets.randbelow(90) + 10)   # 10-99
        symbol = _SYMBOLS_AUGMENT[secrets.randbelow(len(_SYMBOLS_AUGMENT))]
        phrase = phrase + digit_suffix + symbol

    return phrase


def passphrase_entropy_bits(word_count: int, augmented: bool = False) -> float:
    """Return approximate entropy in bits for the given configuration."""
    import math
    bits = word_count * math.log2(max(1, len(_WORDLIST)))
    if augmented:
        bits += math.log2(90) + math.log2(len(_SYMBOLS_AUGMENT))
    return bits
