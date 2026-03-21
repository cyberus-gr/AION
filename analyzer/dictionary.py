"""
Dictionary / breach-database detection.

Loads the common-passwords blocklist once at import time into a frozenset
for O(1) membership tests. Three variants of each password are checked:
  1. The raw password
  2. A case-folded (lowercased) version
  3. A leet-normalised + lowercased version

Optional HIBP (HaveIBeenPwned) check uses SHA-1 k-anonymity: only the first
5 hex characters of the hash are sent to the API. The full password never
leaves the machine.

Design note: the dictionary hit is treated as a near-total penalty in scorer.py
(factor 0.05) because knowledge of the base word breaks the password regardless
of capitalisation or trivial substitutions.
"""

import hashlib
import pathlib
import urllib.error
import urllib.request
from .patterns import normalize_leet

_DATA_DIR = pathlib.Path(__file__).parent.parent / "data"
_COMMON_PASSWORDS_FILE = _DATA_DIR / "common_passwords.txt"

# Load once into a frozenset at import time.
def _load_blocklist() -> frozenset[str]:
    try:
        text = _COMMON_PASSWORDS_FILE.read_text(encoding="utf-8")
        return frozenset(line.strip().lower() for line in text.splitlines() if line.strip())
    except FileNotFoundError:
        return frozenset()


_BLOCKLIST: frozenset[str] = _load_blocklist()


def is_common_password(password: str) -> bool:
    """Return True if the password (or a trivial variant) is in the blocklist."""
    candidates = {
        password,
        password.lower(),
        normalize_leet(password),
    }
    return bool(candidates & _BLOCKLIST)


def hibp_count(password: str) -> int | None:
    """
    Query the HaveIBeenPwned Pwned Passwords API using k-anonymity.

    Returns the number of times the password has appeared in known breaches,
    or None if the API could not be reached.

    Only the first 5 characters of the SHA-1 hash are transmitted.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordAnalyzer/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError):
        return None

    for line in body.splitlines():
        hash_suffix, _, count_str = line.partition(":")
        if hash_suffix.upper() == suffix:
            return int(count_str)
    return 0
