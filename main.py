#!/usr/bin/env python3
"""
Password Analyzer / Smart Generator
=====================================
Analyzes password strength and generates secure passwords.

Usage:
  python main.py analyze "MyPassword123!"
  python main.py analyze --check-hibp "P@ssw0rd"
  python main.py analyze --json "secret"       # machine-readable output
  python main.py generate --mode random --length 16
  python main.py generate --mode random --no-symbols --no-ambiguous
  python main.py generate --mode passphrase --words 6 --augment
  python main.py generate --mode pin --length 8
  echo "mypassword" | python main.py analyze   # pipe support

If no password argument is given to 'analyze', the tool prompts securely
via getpass (password not echoed, not stored in shell history).
"""

import argparse
import getpass
import json
import sys

from analyzer import analyze
from generator import generate_password, generate_passphrase, generate_pin
from generator.passphrase import passphrase_entropy_bits


# ---------------------------------------------------------------------------
# Subcommand: analyze
# ---------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> None:
    # Determine password source: positional arg > stdin pipe > interactive prompt
    if args.password:
        password = args.password
    elif not sys.stdin.isatty():
        password = sys.stdin.read().strip()
    else:
        password = getpass.getpass("Enter password to analyze: ")

    if not password:
        print("Error: no password provided.", file=sys.stderr)
        sys.exit(1)

    result = analyze(password)

    # Optional HIBP check
    if args.check_hibp:
        from analyzer.dictionary import hibp_count
        result.hibp_count = hibp_count(password)

    # JSON output mode (for scripting / pipelines)
    if args.json:
        output = {
            "score": result.score,
            "label": result.label,
            "entropy_bits": result.entropy_bits,
            "raw_entropy_bits": result.raw_entropy_bits,
            "is_common": result.is_common,
            "hibp_count": result.hibp_count,
            "has_lower": result.has_lower,
            "has_upper": result.has_upper,
            "has_digit": result.has_digit,
            "has_symbol": result.has_symbol,
            "penalties": [
                {"name": p.name, "factor": p.factor, "description": p.description}
                for p in result.penalties
            ],
            "suggestions": [s.message for s in result.suggestions],
        }
        print(json.dumps(output, indent=2))
        return

    from display import render_analysis
    render_analysis(result)


# ---------------------------------------------------------------------------
# Subcommand: generate
# ---------------------------------------------------------------------------

def cmd_generate(args: argparse.Namespace) -> None:
    from display import render_password, render_passphrase, render_pin

    mode = args.mode

    if mode == "random":
        password = generate_password(
            length=args.length,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            no_ambiguous=args.no_ambiguous,
        )
        result = analyze(password)
        render_password(password, result.score, result.label, len(password))

        # Optionally print the analysis too
        if args.analyze:
            render_analysis = _import_render_analysis()
            render_analysis(result)

    elif mode == "passphrase":
        phrase = generate_passphrase(
            word_count=args.words,
            separator=args.separator,
            augment=args.augment,
            capitalize=args.capitalize,
        )
        bits = passphrase_entropy_bits(args.words, augmented=args.augment)
        render_passphrase(phrase, args.words, bits, args.augment)

    elif mode == "pin":
        pin, warning = generate_pin(length=args.length)
        render_pin(pin, warning)

    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)


def _import_render_analysis():
    from display import render_analysis
    return render_analysis


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-analyzer",
        description="Analyze password strength and generate secure passwords.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # --- analyze ---
    p_analyze = sub.add_parser(
        "analyze",
        help="Analyze a password's strength",
        description="Score a password from 0-100 and explain its weaknesses.",
    )
    p_analyze.add_argument(
        "password",
        nargs="?",
        help="Password to analyze. If omitted, read from stdin or prompted securely.",
    )
    p_analyze.add_argument(
        "--check-hibp",
        action="store_true",
        help="Query HaveIBeenPwned to check if the password appears in breach databases. "
             "Only the first 5 hex chars of the SHA-1 hash are sent.",
    )
    p_analyze.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (useful for scripting).",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # --- generate ---
    p_gen = sub.add_parser(
        "generate",
        help="Generate a secure password, passphrase, or PIN",
        description="Generate cryptographically secure credentials.",
    )
    p_gen.add_argument(
        "--mode",
        choices=["random", "passphrase", "pin"],
        default="random",
        help="Generation mode: random (default), passphrase, or pin.",
    )
    p_gen.add_argument(
        "--length",
        type=int,
        default=16,
        help="Length for random passwords or PINs (default: 16 / 6 for PIN).",
    )
    p_gen.add_argument(
        "--words",
        type=int,
        default=5,
        help="Number of words in passphrase mode (default: 5).",
    )
    p_gen.add_argument(
        "--separator",
        default="-",
        help="Word separator for passphrases (default: -).",
    )
    p_gen.add_argument(
        "--augment",
        action="store_true",
        help="Append a digit and symbol to the passphrase for policy compliance.",
    )
    p_gen.add_argument(
        "--capitalize",
        action="store_true",
        help="Capitalise the first letter of each passphrase word.",
    )
    p_gen.add_argument(
        "--no-upper",
        action="store_true",
        help="Exclude uppercase letters (random mode).",
    )
    p_gen.add_argument(
        "--no-digits",
        action="store_true",
        help="Exclude digits (random mode).",
    )
    p_gen.add_argument(
        "--no-symbols",
        action="store_true",
        help="Exclude symbols (random mode).",
    )
    p_gen.add_argument(
        "--no-ambiguous",
        action="store_true",
        help="Exclude visually similar characters: 0 O I l 1 (random mode).",
    )
    p_gen.add_argument(
        "--analyze",
        action="store_true",
        help="Also print a full strength analysis of the generated password.",
    )
    p_gen.set_defaults(func=cmd_generate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
