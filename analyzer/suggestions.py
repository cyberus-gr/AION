"""
Fix suggester: maps fired signals to concrete, actionable recommendations.

Design rules:
  1. If the password matches the common-password list, ALL other suggestions
     are suppressed and only the dictionary fix is returned. Suggesting
     "add an uppercase letter" to 'password' implies 'Password' is acceptable.
  2. Suggestions are ranked by entropy gain per character added.
  3. Each suggestion is specific — it names the offending fragment where possible.
"""

from __future__ import annotations
from dataclasses import dataclass
from .patterns import Penalty
import math


@dataclass
class Suggestion:
    priority: int        # lower = higher priority; controls display order
    message: str


def build_suggestions(
    password: str,
    penalties: list[Penalty],
    is_common: bool,
    missing_lower: bool,
    missing_upper: bool,
    missing_digit: bool,
    missing_symbol: bool,
    length: int,
) -> list[Suggestion]:
    """
    Return an ordered list of suggestions based on analysis signals.

    Parameters mirror the signals collected in scorer.py so this module
    stays pure (no re-analysis).
    """
    suggestions: list[Suggestion] = []

    # Rule 1: dictionary hit suppresses everything else
    if is_common:
        return [Suggestion(
            priority=0,
            message=(
                "This password (or a close variant) appears in known breach databases. "
                "Choose a completely different base — capitalising or adding '1!' to a "
                "known password does not make it secure."
            ),
        )]

    penalty_names = {p.name for p in penalties}

    # Length — always the highest-value fix
    if length < 8:
        gain = _entropy_gain_from_length(password, target=12)
        suggestions.append(Suggestion(
            priority=1,
            message=f"Extend to at least 12 characters (+{gain:.1f} bits of entropy). "
                    "Length is the single most effective lever.",
        ))
    elif length < 12:
        gain = _entropy_gain_from_length(password, target=16)
        suggestions.append(Suggestion(
            priority=2,
            message=f"Extend to 16+ characters for a strong password (+{gain:.1f} bits).",
        ))

    # Character class gaps
    if missing_upper and missing_lower:
        suggestions.append(Suggestion(
            priority=3,
            message="Mix upper and lower-case letters to increase the search space.",
        ))
    elif missing_upper:
        suggestions.append(Suggestion(
            priority=4,
            message="Add at least one uppercase letter (A-Z).",
        ))
    elif missing_lower:
        suggestions.append(Suggestion(
            priority=4,
            message="Add at least one lowercase letter (a-z).",
        ))

    if missing_digit:
        suggestions.append(Suggestion(
            priority=5,
            message="Include at least one digit (0-9) — avoid placing it only at the start or end.",
        ))

    if missing_symbol:
        suggestions.append(Suggestion(
            priority=6,
            message="Add a symbol such as ! @ # $ % ^ & * to multiply the effective search space.",
        ))

    # Pattern-specific fixes
    for penalty in penalties:
        if penalty.name == "keyboard_walk":
            suggestions.append(Suggestion(
                priority=7,
                message=f"Replace the keyboard walk '{penalty.match}' with unrelated characters.",
            ))
        elif penalty.name == "sequential_chars":
            suggestions.append(Suggestion(
                priority=7,
                message=f"Avoid sequential runs like '{penalty.match}' — attackers include these in targeted masks.",
            ))
        elif penalty.name == "repeating_chars":
            suggestions.append(Suggestion(
                priority=8,
                message=f"Remove repeated characters '{penalty.match}{penalty.match}{penalty.match}' — they add almost no entropy.",
            ))
        elif penalty.name == "date_pattern":
            suggestions.append(Suggestion(
                priority=8,
                message=f"Remove the date/year pattern '{penalty.match}'. Attackers include date ranges in targeted wordlists.",
            ))

    return sorted(suggestions, key=lambda s: s.priority)


def _entropy_gain_from_length(password: str, target: int) -> float:
    """Approximate entropy gain (bits) from extending to target length."""
    import string
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    charset = 0
    if has_lower: charset += 26
    if has_upper: charset += 26
    if has_digit: charset += 10
    if has_symbol: charset += 32
    charset = max(charset, 26)

    added = max(0, target - len(password))
    return added * math.log2(charset)
