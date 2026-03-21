"""
Plain-text renderer with ANSI colour codes.

No third-party dependencies. Falls back to unstyled output if the terminal
does not support ANSI codes (detected via sys.stdout.isatty()).
"""

import sys
import math

_ANSI = sys.stdout.isatty()

# ANSI escape codes
_RESET  = "\033[0m"  if _ANSI else ""
_BOLD   = "\033[1m"  if _ANSI else ""
_RED    = "\033[91m" if _ANSI else ""
_YELLOW = "\033[93m" if _ANSI else ""
_GREEN  = "\033[92m" if _ANSI else ""
_CYAN   = "\033[96m" if _ANSI else ""
_DIM    = "\033[2m"  if _ANSI else ""


def _color_for_score(score: int) -> str:
    if score < 25:
        return _RED
    if score < 60:
        return _YELLOW
    return _GREEN


def _score_bar(score: int, width: int = 40) -> str:
    filled = int(score / 100 * width)
    color = _color_for_score(score)
    bar = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{_RESET}"


def _check(flag: bool) -> str:
    return f"{_GREEN}✓{_RESET}" if flag else f"{_RED}✗{_RESET}"


def render_analysis(result) -> None:
    """Print a full analysis report to stdout."""
    print()
    print(f"{_BOLD}── Password Analysis ─────────────────────────────────{_RESET}")
    print()

    # Score bar
    color = _color_for_score(result.score)
    print(f"  Strength  {_score_bar(result.score)}  {color}{_BOLD}{result.label}{_RESET}  ({result.score}/100)")
    print()

    # Entropy
    print(f"  Entropy   {_CYAN}{result.entropy_bits:.1f} bits{_RESET} effective "
          f"(raw ceiling: {_DIM}{result.raw_entropy_bits:.1f} bits{_RESET})")
    print()

    # Character class checklist
    print(f"  Lowercase  {_check(result.has_lower)}   "
          f"Uppercase  {_check(result.has_upper)}   "
          f"Digits  {_check(result.has_digit)}   "
          f"Symbols  {_check(result.has_symbol)}")
    print()

    # HIBP count
    if result.hibp_count is not None:
        if result.hibp_count > 0:
            print(f"  {_RED}⚠  Seen {result.hibp_count:,} times in breach databases (HaveIBeenPwned){_RESET}")
        else:
            print(f"  {_GREEN}✓  Not found in HaveIBeenPwned breach database{_RESET}")
        print()

    # Penalties
    if result.penalties:
        print(f"  {_YELLOW}Issues detected:{_RESET}")
        for p in result.penalties:
            print(f"    {_YELLOW}•{_RESET} {p.description}")
        print()

    # Suggestions
    if result.suggestions:
        print(f"  {_BOLD}Recommendations:{_RESET}")
        for i, s in enumerate(result.suggestions, 1):
            print(f"    {i}. {s.message}")
        print()

    print(f"{_DIM}──────────────────────────────────────────────────────{_RESET}")
    print()


def render_password(password: str, score: int, label: str, length: int) -> None:
    """Print a generated random password."""
    color = _color_for_score(score)
    print()
    print(f"{_BOLD}── Generated Password ────────────────────────────────{_RESET}")
    print()
    print(f"  {_CYAN}{_BOLD}{password}{_RESET}")
    print()
    print(f"  Length: {length}   Strength: {color}{label}{_RESET}   Score: {score}/100")
    print()
    print(f"{_DIM}──────────────────────────────────────────────────────{_RESET}")
    print()


def render_passphrase(phrase: str, word_count: int, entropy_bits: float, augmented: bool) -> None:
    """Print a generated passphrase."""
    print()
    print(f"{_BOLD}── Generated Passphrase ──────────────────────────────{_RESET}")
    print()
    print(f"  {_CYAN}{_BOLD}{phrase}{_RESET}")
    print()
    aug_note = "  (augmented with digit + symbol)" if augmented else ""
    print(f"  {word_count} words  ≈ {entropy_bits:.1f} bits of entropy{aug_note}")
    print()
    print(f"{_DIM}──────────────────────────────────────────────────────{_RESET}")
    print()


def render_pin(pin: str, warning: str | None) -> None:
    """Print a generated PIN."""
    print()
    print(f"{_BOLD}── Generated PIN ─────────────────────────────────────{_RESET}")
    print()
    print(f"  {_CYAN}{_BOLD}{pin}{_RESET}")
    print()
    if warning:
        print(f"  {_YELLOW}⚠  {warning}{_RESET}")
        print()
    print(f"{_DIM}──────────────────────────────────────────────────────{_RESET}")
    print()
