"""
Entropy calculation for password strength analysis.

Two measures are computed:
  - charset_entropy: theoretical upper bound (length × log2(active charset size))
  - conditional_entropy: accounts for internal structure via zlib compression heuristic

Design note: charset_entropy is optimistic — it assumes the user drew each character
uniformly at random from the entire charset. Pattern penalties in scorer.py pull the
effective entropy down toward the true value.
"""

import math
import string
import zlib

# Charset pools and their sizes
_LOWER = set(string.ascii_lowercase)    # 26
_UPPER = set(string.ascii_uppercase)    # 26
_DIGITS = set(string.digits)            # 10
_SYMBOLS = set(string.punctuation)     # 32


def _active_charset_size(password: str) -> int:
    """Return the size of the combined charset of character classes present in the password."""
    size = 0
    if any(c in _LOWER for c in password):
        size += 26
    if any(c in _UPPER for c in password):
        size += 26
    if any(c in _DIGITS for c in password):
        size += 10
    if any(c in _SYMBOLS for c in password):
        size += 32
    return max(size, 1)  # guard against empty password


def charset_entropy(password: str) -> float:
    """
    Theoretical maximum entropy in bits.

    Formula: H = L × log2(N)
    where L = password length, N = active charset size.

    This is the ceiling; actual entropy is lower if the password has structure.
    """
    if not password:
        return 0.0
    n = _active_charset_size(password)
    return len(password) * math.log2(n)


def conditional_entropy(password: str) -> float:
    """
    Structure-aware entropy estimate using zlib compression as a heuristic.

    If zlib can compress the password significantly, it contains exploitable
    repetition or patterns that a naive attacker could exploit. The ratio
    compressed_len / original_len drives a structural penalty factor.

    Returns an entropy value that is <= charset_entropy(password).
    """
    if not password or len(password) < 4:
        return charset_entropy(password)

    raw = password.encode("utf-8")
    compressed = zlib.compress(raw, level=9)

    # zlib adds ~10 bytes of header overhead; normalise it out
    effective_compressed = max(1, len(compressed) - 10)
    ratio = effective_compressed / len(raw)

    # ratio near 1.0 means no compression → no structure detected
    # ratio near 0.0 means high compression → highly structured
    # We clamp the penalty factor between 0.4 and 1.0
    structure_factor = max(0.4, min(1.0, ratio))

    return charset_entropy(password) * structure_factor


def entropy_label(bits: float) -> str:
    """Human-readable label for an entropy value."""
    if bits < 28:
        return "Very Low"
    if bits < 36:
        return "Low"
    if bits < 60:
        return "Moderate"
    if bits < 100:
        return "High"
    return "Very High"
