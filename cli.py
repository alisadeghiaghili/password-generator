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

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich import box
    from rich.style import Style
    from rich.color import Color

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


SCORE_STYLES = {
    0: ("bold red", "VERY WEAK", "red"),
    1: ("bold red", "WEAK", "red"),
    2: ("bold yellow", "FAIR", "yellow"),
    3: ("bold green", "STRONG", "green"),
    4: ("bold bright_green", "VERY STRONG", "bright_green"),
}


# ---------------------------------------------------------------------------
# Rich-based output helpers
# ---------------------------------------------------------------------------

def _console():
    return Console()


def _colored_score(score):
    """Return styled score text for rich."""
    style, label, color = SCORE_STYLES.get(score, ("bold white", "UNKNOWN", "white"))
    return Text(f"{score}/4 — {label}", style=style)


def _strength_bar_rich(score):
    """Return a visual strength bar."""
    filled = score + 1
    empty = 4 - score
    _, _, color = SCORE_STYLES.get(score, ("bold white", "UNKNOWN", "white"))
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim")
    return bar


def _print_strength_rich(report, show_password=False):
    """Print a beautiful strength report using rich."""
    console = _console()
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()

    table.add_row("Strength", _colored_score(report.score))
    table.add_row("Bar", _strength_bar_rich(report.score))
    table.add_row("Entropy", f"~{report.entropy:.0f} bits")
    table.add_row("Guesses", f"{report.guesses:.0e}")

    crack_table = Table(title="Crack Time Estimates", box=box.ROUNDED, show_header=True)
    crack_table.add_column("Scenario", style="cyan", no_wrap=True)
    crack_table.add_column("Time", style="bold")
    for scenario, time_str in report.crack_times.items():
        label = scenario.replace("_", " ").replace("per", "/")
        crack_table.add_row(label, time_str)

    if report.feedback:
        fb = Text()
        for i, msg in enumerate(report.feedback):
            if i > 0:
                fb.append("\n")
            fb.append(f"  ▸ {msg}", style="yellow")

    console.print(Panel(table, title="[bold]Password Analysis[/bold]", border_style="blue"))
    console.print(crack_table)
    if report.feedback:
        console.print(Panel(fb, title="[bold]Feedback[/bold]", border_style="yellow"))


def _print_passwords_rich(passwords, label):
    """Print generated passwords in a rich panel."""
    console = _console()
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("#", style="dim", width=4)
    table.add_column("Password", style="bold cyan")
    for i, pwd in enumerate(passwords, 1):
        table.add_row(str(i), pwd)

    count = len(passwords)
    console.print(Panel(
        table,
        title=f"[bold green]Generated {count} {label}[/bold green]",
        border_style="green",
    ))


def _print_passwords_plain(passwords, label):
    """Fallback plain output."""
    count = len(passwords)
    print(f"\nGenerated {count} {label}:\n")
    for i, pwd in enumerate(passwords, 1):
        print(f"  {i:>2}. {pwd}")
    print()


def _print_strength_plain(report, show_password=False):
    """Fallback plain strength output."""
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


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def interactive_mode():
    """Run interactive password generation."""
    if RICH_AVAILABLE:
        _interactive_rich()
    else:
        _interactive_plain()


def _interactive_rich():
    """Interactive mode with rich output."""
    console = _console()
    console.print(Panel(
        "[bold]Secure Password Generator[/bold]\n"
        "[dim]Cryptographically secure • Configurable • Beautiful[/dim]",
        border_style="bright_blue",
        padding=(1, 2),
    ))

    while True:
        console.print()
        table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
        table.add_column("[bold]Choice[/bold]", style="cyan", width=6)
        table.add_column("Action")
        table.add_row("1", "Random password")
        table.add_row("2", "Passphrase (XKCD-style)")
        table.add_row("3", "PIN / numeric code")
        table.add_row("4", "Analyze a password")
        table.add_row("5", "Exit")
        console.print(table)

        choice = Prompt.ask("\n[bold cyan]Choice[/bold cyan]", choices=["1", "2", "3", "4", "5"])

        if choice == "1":
            _interactive_random_password_rich()
        elif choice == "2":
            _interactive_passphrase_rich()
        elif choice == "3":
            _interactive_pin_rich()
        elif choice == "4":
            _interactive_analyze_rich()
        elif choice == "5":
            console.print("[bold green]Goodbye![/bold green]")
            break


def _interactive_random_password_rich():
    """Interactive random password generation (rich)."""
    console = _console()
    length = int(Prompt.ask("Password length", default="16"))
    uppercase = Confirm.ask("Include uppercase (A-Z)?", default=True)
    lowercase = Confirm.ask("Include lowercase (a-z)?", default=True)
    digits = Confirm.ask("Include digits (0-9)?", default=True)
    symbols = Confirm.ask("Include symbols (!@#...)?", default=True)
    exclude_ambiguous = Confirm.ask("Exclude ambiguous chars (l, I, 1, O, 0)?", default=False)
    count = int(Prompt.ask("How many passwords?", default="1"))

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
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Generating...", total=None)
        passwords = [generate(config) for _ in range(count)]
        progress.update(task, completed=True)

    _print_passwords_rich(passwords, f"password(s) ({length} chars)")

    report = analyze(passwords[0])
    _print_strength_rich(report)

    _offer_clipboard_rich(passwords)


def _interactive_passphrase_rich():
    """Interactive passphrase generation (rich)."""
    console = _console()
    words = int(Prompt.ask("Number of words", default="4"))
    console.print("  [dim]1. Hyphen (-)   2. Space   3. Period (.)   4. Underscore (_)[/dim]")
    sep_choice = Prompt.ask("Separator", choices=["1", "2", "3", "4"], default="1")
    separators = {"1": "-", "2": " ", "3": ".", "4": "_"}
    separator = separators[sep_choice]
    capitalize = Confirm.ask("Capitalize words?", default=False)
    count = int(Prompt.ask("How many passphrases?", default="1"))

    try:
        config = PassphraseConfig(words=words, separator=separator, capitalize=capitalize)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Generating...", total=None)
        passphrases = [generate_passphrase(config) for _ in range(count)]
        progress.update(task, completed=True)

    _print_passwords_rich(passphrases, f"passphrase(s) ({words} words)")

    report = analyze(passphrases[0])
    _print_strength_rich(report)

    _offer_clipboard_rich(passphrases)


def _interactive_pin_rich():
    """Interactive PIN generation (rich)."""
    console = _console()
    length = int(Prompt.ask("PIN length", default="4"))
    avoid_repeats = Confirm.ask("Avoid repeated digits (no 1111)?", default=False)
    avoid_sequential = Confirm.ask("Avoid sequential digits (no 1234)?", default=False)
    count = int(Prompt.ask("How many PINs?", default="1"))

    try:
        config = PinConfig(length=length, avoid_repeats=avoid_repeats, avoid_sequential=avoid_sequential)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Generating...", total=None)
        pins = [generate_pin(config) for _ in range(count)]
        progress.update(task, completed=True)

    _print_passwords_rich(pins, f"PIN(s) ({length} digits)")

    _offer_clipboard_rich(pins)


def _interactive_analyze_rich():
    """Interactive password analysis (rich)."""
    console = _console()
    password = Prompt.ask("\n[bold]Enter password to analyze[/bold]")
    if not password:
        console.print("[red]No password entered.[/red]")
        return
    report = analyze(password)
    _print_strength_rich(report, show_password=True)


def _offer_clipboard_rich(passwords):
    """Offer to copy passwords to clipboard (rich)."""
    console = _console()
    if len(passwords) == 1:
        if Confirm.ask("\n[bold]Copy to clipboard?[/bold]", default=True):
            if copy_to_clipboard(passwords[0], auto_clear_seconds=30):
                console.print("  [green]Copied![/green] (will auto-clear in 30 seconds)")
            else:
                console.print("  [yellow]Clipboard not available.[/yellow]")
    else:
        if Confirm.ask("\n[bold]Copy all (newline-separated) to clipboard?[/bold]", default=False):
            if copy_to_clipboard("\n".join(passwords), auto_clear_seconds=30):
                console.print("  [green]Copied![/green] (will auto-clear in 30 seconds)")
            else:
                console.print("  [yellow]Clipboard not available.[/yellow]")
    console.print()


# ---------------------------------------------------------------------------
# Plain (fallback) interactive mode
# ---------------------------------------------------------------------------

def _interactive_plain():
    """Interactive mode without rich."""
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
            _interactive_random_password_plain()
        elif choice == "2":
            _interactive_passphrase_plain()
        elif choice == "3":
            _interactive_pin_plain()
        elif choice == "4":
            _interactive_analyze_plain()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.\n")


def _interactive_random_password_plain():
    length = _input_int("Password length (4-256, default 16): ", default=16, min_val=4, max_val=256)
    uppercase = _input_yes_no("Include uppercase (A-Z)?", True)
    lowercase = _input_yes_no("Include lowercase (a-z)?", True)
    digits = _input_yes_no("Include digits (0-9)?", True)
    symbols = _input_yes_no("Include symbols (!@#...)?", True)
    exclude_ambiguous = _input_yes_no("Exclude ambiguous chars (l, I, 1, O, 0)?", False)
    count = _input_int("How many passwords? (1-100, default 1): ", default=1, min_val=1, max_val=100)

    try:
        config = GeneratorConfig(
            length=length, uppercase=uppercase, lowercase=lowercase,
            digits=digits, symbols=symbols, exclude_ambiguous=exclude_ambiguous,
        )
    except ValueError as e:
        print(f"\nError: {e}\n")
        return

    passwords = [generate(config) for _ in range(count)]
    _print_passwords_plain(passwords, f"password(s) ({length} chars)")
    _print_strength_plain(analyze(passwords[0]))
    _offer_clipboard_plain(passwords)


def _interactive_passphrase_plain():
    words = _input_int("Number of words (2-10, default 4): ", default=4, min_val=2, max_val=10)
    print("Separator options:  1. Hyphen (-)  2. Space  3. Period (.)  4. Underscore (_)")
    sep_choice = input("Choice (1-4, default 1): ").strip()
    separator = {"1": "-", "2": " ", "3": ".", "4": "_"}.get(sep_choice, "-")
    capitalize = _input_yes_no("Capitalize words?", False)
    count = _input_int("How many passphrases? (1-100, default 1): ", default=1, min_val=1, max_val=100)

    try:
        config = PassphraseConfig(words=words, separator=separator, capitalize=capitalize)
    except ValueError as e:
        print(f"\nError: {e}\n")
        return

    passphrases = [generate_passphrase(config) for _ in range(count)]
    _print_passwords_plain(passphrases, f"passphrase(s) ({words} words)")
    _print_strength_plain(analyze(passphrases[0]))
    _offer_clipboard_plain(passphrases)


def _interactive_pin_plain():
    length = _input_int("PIN length (1-12, default 4): ", default=4, min_val=1, max_val=12)
    avoid_repeats = _input_yes_no("Avoid repeated digits (no 1111)?", False)
    avoid_sequential = _input_yes_no("Avoid sequential digits (no 1234)?", False)
    count = _input_int("How many PINs? (1-100, default 1): ", default=1, min_val=1, max_val=100)

    try:
        config = PinConfig(length=length, avoid_repeats=avoid_repeats, avoid_sequential=avoid_sequential)
    except ValueError as e:
        print(f"\nError: {e}\n")
        return

    pins = [generate_pin(config) for _ in range(count)]
    _print_passwords_plain(pins, f"PIN(s) ({length} digits)")
    _offer_clipboard_plain(pins)


def _interactive_analyze_plain():
    password = input("\nEnter password to analyze: ").strip()
    if not password:
        print("No password entered.\n")
        return
    _print_strength_plain(analyze(password), show_password=True)


def _offer_clipboard_plain(passwords):
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


# ---------------------------------------------------------------------------
# CLI mode (argparse)
# ---------------------------------------------------------------------------

def cli_mode(args):
    """Run CLI mode with arguments."""
    console = _console() if RICH_AVAILABLE else None

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
        elif RICH_AVAILABLE:
            _print_strength_rich(report, show_password=True)
        else:
            _print_strength_plain(report, show_password=True)
        return

    if args.passphrase:
        config = PassphraseConfig(
            words=args.words, separator=args.separator, capitalize=args.capitalize,
        )
        passwords = [generate_passphrase(config) for _ in range(args.count)]
        label = f"passphrase(s) ({args.words} words)"
    elif args.pin:
        config = PinConfig(
            length=args.pin_length, avoid_repeats=args.avoid_repeats,
            avoid_sequential=args.avoid_sequential,
        )
        passwords = [generate_pin(config) for _ in range(args.count)]
        label = f"PIN(s) ({args.pin_length} digits)"
    else:
        config = GeneratorConfig(
            length=args.length, uppercase=args.uppercase, lowercase=args.lowercase,
            digits=args.digits, symbols=not args.no_symbols,
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
    elif RICH_AVAILABLE:
        _print_passwords_rich(passwords, label)
    else:
        _print_passwords_plain(passwords, label)

    if args.clipboard:
        joined = passwords[0] if args.count == 1 else "\n".join(passwords)
        if copy_to_clipboard(joined, auto_clear_seconds=args.clipboard_clear):
            msg = f"Copied to clipboard! (auto-clear in {args.clipboard_clear}s)"
            if console:
                console.print(f"[green]{msg}[/green]")
            else:
                print(msg)
        else:
            msg = "Clipboard not available."
            if console:
                console.print(f"[yellow]{msg}[/yellow]")
            else:
                print(msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="[Rich] Secure Password Generator",
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

    if len(sys.argv) == 1:
        interactive_mode()
    else:
        cli_mode(args)


if __name__ == "__main__":
    main()
