"""
Cryptographically secure PIN generator.

PINs have low entropy by nature — a 6-digit PIN has only ~20 bits, which is
insufficient for any offline attack scenario. The generator still blocks the
most obvious weak PINs to prevent trivially-guessable codes in rate-limited
systems (ATMs, phones, etc.).

Blocked patterns:
  - All-same digits: 0000, 1111, ...
  - Long sequential ascending/descending runs (4+ digits)
  - The 20 most statistically common PINs from published breach analysis

All randomness comes from secrets.randbelow(). The random module is not used.
"""

import secrets

# Most common PINs from published statistical analyses of breach datasets
_COMMON_PINS: frozenset[str] = frozenset([
    "0000", "1111", "1234", "1212", "7777",
    "1004", "2000", "4444", "2222", "6969",
    "9999", "3333", "5555", "6666", "1122",
    "1313", "4321", "2001", "1010", "0001",
    "00000", "11111", "12345", "11111", "55555",
    "123456", "654321", "111111", "000000", "123123",
])

_ENTROPY_WARNING_THRESHOLD = 6  # digits


def _is_weak_pin(pin: str) -> bool:
    """Return True if the PIN should be rejected and redrawn."""
    if pin in _COMMON_PINS:
        return True

    # All-same digits
    if len(set(pin)) == 1:
        return True

    # Sequential ascending or descending run of 4+
    for direction in (1, -1):
        run = 1
        for i in range(1, len(pin)):
            if int(pin[i]) - int(pin[i - 1]) == direction:
                run += 1
                if run >= 4:
                    return True
            else:
                run = 1

    return False


def generate_pin(length: int = 6) -> tuple[str, str | None]:
    """
    Generate a cryptographically secure PIN.

    Returns:
        (pin, warning) where warning is a non-None string if the PIN length
        is below the safe threshold.
    """
    length = max(4, length)

    # Rejection sampling: redraw if weak
    while True:
        pin = "".join(str(secrets.randbelow(10)) for _ in range(length))
        if not _is_weak_pin(pin):
            break

    warning: str | None = None
    if length < _ENTROPY_WARNING_THRESHOLD:
        import math
        bits = length * math.log2(10)
        warning = (
            f"A {length}-digit PIN has only {bits:.1f} bits of entropy. "
            "This is sufficient only for rate-limited systems (e.g., phones, ATMs). "
            "Use a minimum of 6 digits, or prefer a passphrase."
        )

    return pin, warning
