"""
Master scoring pipeline: orchestrates entropy, patterns, and dictionary checks
into a single 0-100 score with a human-readable label.

Score → Label mapping is anchored at cryptographically meaningful entropy values:

  Effective Entropy | Score | Label
  ──────────────────┼───────┼──────────────
  0 bits            |   0   | Very Weak
  28 bits (2^28 ≈   |  25   | Weak          ← GPU cracks bcrypt cost-10 in < 1s
    268M guesses)   |       |
  36 bits           |  40   | Fair
  60 bits (2^60 ≈   |  75   | Strong        ← offline cracking infeasible on KDFs
    10^18 guesses)  |       |
  100 bits          | 100   | Very Strong

A hard policy floor: passwords under 8 characters are capped at score 30
regardless of entropy — this is a policy decision, not a mathematical one.

Design note: effective_entropy = charset_entropy × ∏(penalty.factor)
Penalties compose multiplicatively so independent weaknesses stack correctly.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field

from .entropy import charset_entropy, conditional_entropy, entropy_label
from .patterns import Penalty, all_penalties
from .dictionary import is_common_password
from .suggestions import Suggestion, build_suggestions


@dataclass
class AnalysisResult:
    password: str
    score: int                          # 0-100
    label: str                          # Very Weak / Weak / Fair / Strong / Very Strong
    entropy_bits: float                 # effective entropy after penalties
    raw_entropy_bits: float             # theoretical maximum
    penalties: list[Penalty]
    suggestions: list[Suggestion]
    is_common: bool
    hibp_count: int | None = None       # set later if --check-hibp used

    # Character class presence flags (for display)
    has_lower: bool = False
    has_upper: bool = False
    has_digit: bool = False
    has_symbol: bool = False


# Piecewise-linear breakpoints: (entropy_bits, score)
_BREAKPOINTS = [
    (0, 0),
    (28, 25),
    (36, 40),
    (60, 75),
    (100, 100),
]


def _entropy_to_score(bits: float) -> int:
    if bits <= 0:
        return 0
    if bits >= _BREAKPOINTS[-1][0]:
        return _BREAKPOINTS[-1][1]

    for i in range(1, len(_BREAKPOINTS)):
        e0, s0 = _BREAKPOINTS[i - 1]
        e1, s1 = _BREAKPOINTS[i]
        if e0 <= bits <= e1:
            t = (bits - e0) / (e1 - e0)
            return round(s0 + t * (s1 - s0))

    return 0


def _score_to_label(score: int) -> str:
    if score < 25:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"


def analyze(password: str) -> AnalysisResult:
    """
    Run the full analysis pipeline and return an AnalysisResult.

    Pipeline:
      1. Entropy calculation (charset + conditional/structural)
      2. Pattern penalty detection
      3. Dictionary / common-password check
      4. Score assembly (entropy × multiplicative penalties)
      5. Policy floor (min-length cap)
      6. Suggestion generation
    """
    if not password:
        return AnalysisResult(
            password="",
            score=0,
            label="Very Weak",
            entropy_bits=0.0,
            raw_entropy_bits=0.0,
            penalties=[],
            suggestions=[],
            is_common=True,
        )

    # --- 1. Character class flags ---
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    # --- 2. Entropy ---
    raw = charset_entropy(password)
    structural = conditional_entropy(password)

    # Use the lower of the two as the starting entropy ceiling
    base_entropy = min(raw, structural)

    # --- 3. Pattern penalties ---
    penalties = all_penalties(password)

    # --- 4. Dictionary check ---
    common = is_common_password(password)
    if common:
        penalties.append(Penalty(
            name="common_password",
            factor=0.05,
            description="Password found in common-password list or breach databases",
            match=password,
        ))

    # --- 5. Effective entropy (multiplicative penalty composition) ---
    factor = 1.0
    for p in penalties:
        factor *= p.factor
    effective_entropy = base_entropy * factor

    # --- 6. Score & policy floor ---
    score = _entropy_to_score(effective_entropy)

    if len(password) < 8:
        score = min(score, 30)          # policy floor: too short

    label = _score_to_label(score)

    # --- 7. Suggestions ---
    suggestions = build_suggestions(
        password=password,
        penalties=penalties,
        is_common=common,
        missing_lower=not has_lower,
        missing_upper=not has_upper,
        missing_digit=not has_digit,
        missing_symbol=not has_symbol,
        length=len(password),
    )

    return AnalysisResult(
        password=password,
        score=score,
        label=label,
        entropy_bits=round(effective_entropy, 1),
        raw_entropy_bits=round(raw, 1),
        penalties=penalties,
        suggestions=suggestions,
        is_common=common,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
    )
