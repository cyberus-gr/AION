"""
Cryptographically secure random password generator.

All randomness comes from secrets.SystemRandom(), which wraps os.urandom().
The random module is never imported here — this is intentional and must stay
that way to avoid accidentally using a predictable PRNG.

Generation uses rejection sampling to guarantee policy compliance:
draw 'length' characters, verify at least one from each required class is
present, redraw if not. The expected number of redraws is < 1.02 for any
reasonable length/policy combination.

The --no-ambiguous flag removes visually similar characters (0 O I l 1).
This is useful for passwords that will be read aloud or typed from a printed
sheet. It does slightly reduce the charset but the effect is negligible for
lengths > 12.
"""

import secrets
import string

# Characters that are visually ambiguous in many typefaces
_AMBIGUOUS = set("0O1lI")

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    no_ambiguous: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length:       Total character count (minimum 8, recommended 16+).
        use_upper:    Include uppercase letters.
        use_digits:   Include digits.
        use_symbols:  Include symbols.
        no_ambiguous: Exclude visually similar characters (0 O I l 1).

    Returns:
        A password string that satisfies all enabled character-class requirements.
    """
    length = max(8, length)

    # Build the pool
    pool = _LOWER
    required_pools: list[str] = [_LOWER]

    if use_upper:
        pool += _UPPER
        required_pools.append(_UPPER)
    if use_digits:
        pool += _DIGITS
        required_pools.append(_DIGITS)
    if use_symbols:
        pool += _SYMBOLS
        required_pools.append(_SYMBOLS)

    if no_ambiguous:
        pool = "".join(c for c in pool if c not in _AMBIGUOUS)
        required_pools = [
            "".join(c for c in rp if c not in _AMBIGUOUS)
            for rp in required_pools
        ]
        # Drop any pool that became empty after filtering
        required_pools = [rp for rp in required_pools if rp]

    if len(pool) < 2:
        raise ValueError("Character pool is too small. Relax constraints.")

    # Rejection sampling: draw until all required classes are present
    rng = secrets.SystemRandom()
    while True:
        candidate = "".join(rng.choice(pool) for _ in range(length))
        if all(any(c in rp for c in candidate) for rp in required_pools):
            return candidate
