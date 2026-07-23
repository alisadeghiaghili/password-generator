#!/usr/bin/env python3
"""
Password Generator CLI - A secure, configurable password generation tool.

Usage:
    python cli.py                          # Interactive mode
    python cli.py --length 20 --count 5    # Generate 5 passwords
    python cli.py --passphrase --words 4   # XKCD-style passphrase
    python cli.py --pin --length 6         # Generate 6-digit PIN
    python cli.py --analyze "my_password"  # Analyze password strength
"""

import argparse
import json
import sys

from password_generator import (
    generate,
    generate_passphrase,
    generate_pin,
    analyze,
    copy_to_clipboard,
    GeneratorConfig,
    PassphraseConfig,
    PinConfig,
)


def interactive_mode():
    """Run interactive password generation."""
    print("=" * 45)
    print("       SECURE PASSWORD GENERATOR")
    print("=" * 45)
    print()

    while True:
        print("What would you like to generate?")
        print("  1. Random password")
        print("  2. Passphrase (XKCD-style)")
        print("  3. PIN / numeric code")
        print("  4. Analyze a password")
        print("  5. Exit")
        print()

        choice = input("Choice (1-5): ").strip()

        if choice == "1":
            _interactive_random_password()
        elif choice == "2":
            _interactive_passphrase()
        elif choice == "3":
            _interactive_pin()
        elif choice == "4":
            _interactive_analyze()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.\n")


def _interactive_random_password():
    """Interactive random password generation."""
    length = _input_int("Password length (4-256, default 16): ", default=16, min_val=4, max_val=256)
    uppercase = _input_yes_no("Include uppercase (A-Z)?", True)
    lowercase = _input_yes_no("Include lowercase (a-z)?", True)
    digits = _input_yes_no("Include digits (0-9)?", True)
    symbols = _input_yes_no("Include symbols (!@#...)?", True)
    exclude_ambiguous = _input_yes_no("Exclude ambiguous chars (l, I, 1, O, 0)?", False)
    count = _input_int("How many passwords? (1-100, default 1): ", default=1, min_val=1, max_val=100)

    try:
        config = GeneratorConfig(
            length=length,
            uppercase=uppercase,
            lowercase=lowercase,
            digits=digits,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
    except ValueError as e:
        print(f"\nError: {e}\n")
        return

    print(f"\n{'=' * 45}")
    print(f"  Generated {count} password(s) ({length} chars)")
    print(f"{'=' * 45}\n")

    passwords = [generate(config) for _ in range(count)]
    for i, pwd in enumerate(passwords, 1):
        print(f"  {i:>2}. {pwd}")

    report = analyze(passwords[0])
    _print_strength_report(report)

    _offer_clipboard(passwords)


def _interactive_passphrase():
    """Interactive passphrase generation."""
    words = _input_int("Number of words (2-10, default 4): ", default=4, min_val=2, max_val=10)

    print("Separator options:")
    print("  1. Hyphen (-)")
    print("  2. Space")
    print("  3. Period (.)")
    print("  4. Underscore (_)")
    sep_choice = input("Choice (1-4, default 1): ").strip()
    separators = {"1": "-", "2": " ", "3": ".", "4": "_"}
    separator = separators.get(sep_choice, "-")

    capitalize = _input_yes_no("Capitalize words?", False)
    count = _input_int("How many passphrases? (1-100, default 1): ", default=1, min_val=1, max_val=100)

    try:
        config = PassphraseConfig(words=words, separator=separator, capitalize=capitalize)
    except ValueError as e:
        print(f"\nError: {e}\n")
        return

    print(f"\n{'=' * 45}")
    print(f"  Generated {count} passphrase(s) ({words} words)")
    print(f"{'=' * 45}\n")

    passphrases = [generate_passphrase(config) for _ in range(count)]
    for i, phrase in enumerate(passphrases, 1):
        print(f"  {i:>2}. {phrase}")

    report = analyze(passphrases[0])
    _print_strength_report(report)

    _offer_clipboard(passphrases)


def _interactive_pin():
    """Interactive PIN generation."""
    length = _input_int("PIN length (1-12, default 4): ", default=4, min_val=1, max_val=12)
    avoid_repeats = _input_yes_no("Avoid repeated digits (no 1111)?", False)
    avoid_sequential = _input_yes_no("Avoid sequential digits (no 1234)?", False)
    count = _input_int("How many PINs? (1-100, default 1): ", default=1, min_val=1, max_val=100)

    try:
        config = PinConfig(length=length, avoid_repeats=avoid_repeats, avoid_sequential=avoid_sequential)
    except ValueError as e:
        print(f"\nError: {e}\n")
        return

    print(f"\n{'=' * 45}")
    print(f"  Generated {count} PIN(s) ({length} digits)")
    print(f"{'=' * 45}\n")

    pins = [generate_pin(config) for _ in range(count)]
    for i, pin in enumerate(pins, 1):
        print(f"  {i:>2}. {pin}")

    _offer_clipboard(pins)


def _interactive_analyze():
    """Interactive password analysis."""
    password = input("\nEnter password to analyze: ").strip()
    if not password:
        print("No password entered.\n")
        return

    report = analyze(password)
    _print_strength_report(report, show_password=True)


def _print_strength_report(report, show_password=False):
    """Print a strength report."""
    score_labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
    print(f"\n  Strength: {report.score}/4 ({score_labels.get(report.score, 'Unknown')})")
    print(f"  Entropy: ~{report.entropy:.0f} bits")
    print(f"  Estimated guesses: {report.guesses:.0e}")

    print("\n  Crack time estimates:")
    for scenario, time_str in report.crack_times.items():
        label = scenario.replace("_", " ").replace("per", "/")
        print(f"    {label}: {time_str}")

    if report.feedback:
        print("\n  Feedback:")
        for fb in report.feedback:
            print(f"    - {fb}")
    print()


def _offer_clipboard(passwords):
    """Offer to copy passwords to clipboard."""
    if len(passwords) == 1:
        if _input_yes_no("Copy to clipboard?", True):
            if copy_to_clipboard(passwords[0], auto_clear_seconds=30):
                print("  Copied! (will auto-clear in 30 seconds)")
            else:
                print("  Clipboard not available.")
    else:
        if _input_yes_no("Copy all (newline-separated) to clipboard?", False):
            if copy_to_clipboard("\n".join(passwords), auto_clear_seconds=30):
                print("  Copied! (will auto-clear in 30 seconds)")
            else:
                print("  Clipboard not available.")
    print()


def _input_int(prompt, default, min_val=1, max_val=1000):
    """Get integer input with validation."""
    while True:
        raw = input(prompt).strip()
        if raw == "":
            return default
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            print(f"Please enter a number between {min_val} and {max_val}.")
        except ValueError:
            print("Please enter a valid number.")


def _input_yes_no(prompt, default=True):
    """Get yes/no input."""
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"{prompt} {suffix}: ").strip().lower()
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please enter y or n.")


def cli_mode(args):
    """Run CLI mode with arguments."""
    if args.analyze:
        report = analyze(args.analyze)
        if args.json:
            print(json.dumps({
                "score": report.score,
                "entropy": report.entropy,
                "guesses": report.guesses,
                "crack_times": report.crack_times,
                "feedback": report.feedback,
                "patterns": report.patterns,
            }, indent=2))
        else:
            _print_strength_report(report, show_password=True)
        return

    if args.passphrase:
        config = PassphraseConfig(
            words=args.words,
            separator=args.separator,
            capitalize=args.capitalize,
        )
        passwords = [generate_passphrase(config) for _ in range(args.count)]
        label = f"passphrase(s) ({args.words} words)"
    elif args.pin:
        config = PinConfig(
            length=args.pin_length,
            avoid_repeats=args.avoid_repeats,
            avoid_sequential=args.avoid_sequential,
        )
        passwords = [generate_pin(config) for _ in range(args.count)]
        label = f"PIN(s) ({args.pin_length} digits)"
    else:
        config = GeneratorConfig(
            length=args.length,
            uppercase=args.uppercase,
            lowercase=args.lowercase,
            digits=args.digits,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
        passwords = [generate(config) for _ in range(args.count)]
        label = f"password(s) ({args.length} chars)"

    if args.json:
        output = {
            "type": "passphrase" if args.passphrase else ("pin" if args.pin else "password"),
            "count": args.count,
            "passwords": passwords,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Generated {args.count} {label}:\n")
        for i, pwd in enumerate(passwords, 1):
            print(f"  {i:>2}. {pwd}")
        print()

    if args.clipboard:
        joined = passwords[0] if args.count == 1 else "\n".join(passwords)
        if copy_to_clipboard(joined, auto_clear_seconds=args.clipboard_clear):
            print(f"Copied to clipboard! (auto-clear in {args.clipboard_clear}s)")
        else:
            print("Clipboard not available.")


def main():
    parser = argparse.ArgumentParser(
        description="Secure Password Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              Interactive mode
  %(prog)s --length 20 --count 5        Generate 5 passwords
  %(prog)s --passphrase --words 4       XKCD-style passphrase
  %(prog)s --pin --length 6 --avoid-repeats
  %(prog)s --analyze "my_password"      Analyze password strength
  %(prog)s --length 20 --json           Output as JSON
        """,
    )

    parser.add_argument("--length", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("--count", type=int, default=1, help="Number of passwords (default: 1)")
    parser.add_argument("--uppercase", action="store_true", default=True, help="Include uppercase (default: True)")
    parser.add_argument("--no-uppercase", dest="uppercase", action="store_false", help="Exclude uppercase")
    parser.add_argument("--lowercase", action="store_true", default=True, help="Include lowercase (default: True)")
    parser.add_argument("--no-lowercase", dest="lowercase", action="store_false", help="Exclude lowercase")
    parser.add_argument("--digits", action="store_true", default=True, help="Include digits (default: True)")
    parser.add_argument("--no-digits", dest="digits", action="store_false", help="Exclude digits")
    parser.add_argument("--no-symbols", dest="no_symbols", action="store_true", help="Exclude symbols")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous chars (l, I, 1, O, 0)")

    parser.add_argument("--passphrase", action="store_true", help="Generate passphrase instead of password")
    parser.add_argument("--words", type=int, default=4, help="Number of words for passphrase (default: 4)")
    parser.add_argument("--separator", default="-", help="Word separator for passphrase (default: -)")
    parser.add_argument("--capitalize", action="store_true", help="Capitalize passphrase words")

    parser.add_argument("--pin", action="store_true", help="Generate PIN instead of password")
    parser.add_argument("--pin-length", type=int, default=4, help="PIN length (default: 4)")
    parser.add_argument("--avoid-repeats", action="store_true", help="Avoid repeated digits in PIN")
    parser.add_argument("--avoid-sequential", action="store_true", help="Avoid sequential digits in PIN")

    parser.add_argument("--analyze", type=str, metavar="PASSWORD", help="Analyze a password's strength")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--clipboard", action="store_true", help="Copy to clipboard")
    parser.add_argument("--clipboard-clear", type=int, default=30, help="Clipboard auto-clear seconds (default: 30)")

    args = parser.parse_args()

    # If no CLI args, run interactive mode
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        cli_mode(args)


if __name__ == "__main__":
    main()
