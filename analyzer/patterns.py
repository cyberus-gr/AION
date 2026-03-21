"""
Pattern detectors for password weakness analysis.

Each detector returns a Penalty dataclass:
  - name: identifier string
  - factor: float in [0.0, 1.0] — multiplicative penalty on effective entropy
             (1.0 = no reduction, 0.0 = worthless password)
  - description: human-readable explanation

Penalties compose multiplicatively: two 0.5-factor penalties yield 0.25,
correctly representing that two independent weaknesses compound each other.

Also exports the leet-speak normalizer used by dictionary.py before lookup.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class Penalty:
    name: str
    factor: float           # [0.0, 1.0]
    description: str
    match: str = ""         # the specific matched fragment, for suggestions


# ---------------------------------------------------------------------------
# Keyboard walk detector
# ---------------------------------------------------------------------------

_KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# Build a char -> set-of-horizontal-neighbours map
_KEYBOARD_ADJACENT: dict[str, set[str]] = {}
for _row in _KEYBOARD_ROWS:
    for _i, _ch in enumerate(_row):
        _neighbours: set[str] = set()
        if _i > 0:
            _neighbours.add(_row[_i - 1])
        if _i < len(_row) - 1:
            _neighbours.add(_row[_i + 1])
        _KEYBOARD_ADJACENT[_ch] = _neighbours
        _KEYBOARD_ADJACENT[_ch.upper()] = {n.upper() for n in _neighbours}


def _longest_keyboard_walk(password: str) -> tuple[int, str]:
    """Return (length, fragment) of the longest consecutive keyboard-adjacent run."""
    if len(password) < 2:
        return 0, ""

    best_len, best_start = 1, 0
    run_start, run_len = 0, 1

    for i in range(1, len(password)):
        a, b = password[i - 1].lower(), password[i].lower()
        if b in _KEYBOARD_ADJACENT.get(a, set()):
            run_len += 1
        else:
            if run_len > best_len:
                best_len, best_start = run_len, run_start
            run_start = i
            run_len = 1

    if run_len > best_len:
        best_len, best_start = run_len, run_start

    return best_len, password[best_start: best_start + best_len]


def detect_keyboard_walk(password: str) -> list[Penalty]:
    length, fragment = _longest_keyboard_walk(password)
    if length >= 6:
        return [Penalty("keyboard_walk", 0.2, f"Long keyboard walk '{fragment}'", fragment)]
    if length >= 4:
        return [Penalty("keyboard_walk", 0.5, f"Keyboard walk '{fragment}'", fragment)]
    return []


# ---------------------------------------------------------------------------
# Character repeat detector
# ---------------------------------------------------------------------------

def detect_repeating_chars(password: str) -> list[Penalty]:
    matches = re.findall(r"(.)\1{2,}", password)
    if not matches:
        return []
    fragment = max(matches, key=len) if len(matches) > 1 else matches[0]
    return [Penalty("repeating_chars", 0.6, f"Repeated character '{fragment[0]}'", fragment[0])]


# ---------------------------------------------------------------------------
# Sequential character detector  (abc, 123, zyx, 987)
# ---------------------------------------------------------------------------

def _longest_sequential_run(password: str) -> tuple[int, str]:
    """Return (length, fragment) of the longest ascending or descending sequential run."""
    if len(password) < 2:
        return 0, ""

    best_len, best_start = 1, 0

    for direction in (1, -1):   # ascending, descending
        run_start, run_len = 0, 1
        for i in range(1, len(password)):
            if ord(password[i].lower()) - ord(password[i - 1].lower()) == direction:
                run_len += 1
            else:
                if run_len > best_len:
                    best_len, best_start = run_len, run_start
                run_start = i
                run_len = 1
        if run_len > best_len:
            best_len, best_start = run_len, run_start

    return best_len, password[best_start: best_start + best_len]


def detect_sequential_chars(password: str) -> list[Penalty]:
    length, fragment = _longest_sequential_run(password)
    if length >= 5:
        return [Penalty("sequential_chars", 0.3, f"Long sequential run '{fragment}'", fragment)]
    if length >= 4:
        return [Penalty("sequential_chars", 0.6, f"Sequential characters '{fragment}'", fragment)]
    return []


# ---------------------------------------------------------------------------
# Date / year pattern detector
# ---------------------------------------------------------------------------

_DATE_PATTERNS = [
    re.compile(r"(19|20)\d{2}"),           # 1970–2099
    re.compile(r"\d{1,2}[\/\-\.]\d{1,2}"), # 12/5, 5-12
    re.compile(r"(?<!\d)\d{4}(?!\d)"),     # isolated 4-digit number
]


def detect_date_pattern(password: str) -> list[Penalty]:
    for pat in _DATE_PATTERNS:
        m = pat.search(password)
        if m:
            return [Penalty("date_pattern", 0.7,
                            f"Date/year pattern '{m.group()}' detected", m.group())]
    return []


# ---------------------------------------------------------------------------
# Leet-speak normalizer  (used by dictionary.py before lookup)
# ---------------------------------------------------------------------------

_LEET_MAP: dict[str, str] = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
    "+": "t",
    "9": "g",
    "6": "b",
    "8": "b",
}


def normalize_leet(password: str) -> str:
    """Replace common leet-speak substitutions with their plain-text equivalents."""
    return "".join(_LEET_MAP.get(c, c) for c in password.lower())


# ---------------------------------------------------------------------------
# Convenience: run all pattern detectors
# ---------------------------------------------------------------------------

def all_penalties(password: str) -> list[Penalty]:
    """Return every penalty that fires for the given password."""
    results: list[Penalty] = []
    results.extend(detect_keyboard_walk(password))
    results.extend(detect_repeating_chars(password))
    results.extend(detect_sequential_chars(password))
    results.extend(detect_date_pattern(password))
    return results
