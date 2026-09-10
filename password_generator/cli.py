"""Command-line interface for password_generator.

Secure CLI: passwords for analysis are read from a prompt or stdin —
never from argv (avoids shell history and process-list leaks).
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from typing import Any, Sequence

from password_generator import (
    GeneratorConfig,
    PassphraseConfig,
    PinConfig,
    analyze,
    clear_clipboard,
    copy_to_clipboard,
    generate,
    generate_passphrase,
    generate_pin,
)

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.progress import SpinnerColumn, TextColumn, Progress
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

SCORE_STYLES: dict[int, tuple[str, str, str]] = {
    0: ("bold red", "VERY WEAK", "red"),
    1: ("bold red", "WEAK", "red"),
    2: ("bold yellow", "FAIR", "yellow"),
    3: ("bold green", "STRONG", "green"),
    4: ("bold bright_green", "VERY STRONG", "bright_green"),
}


def _console() -> Any:
    return Console()


def _read_password_securely() -> str:
    """Read a password from stdin (pipe) or a hidden prompt.

    Returns:
        The password string. Empty string if nothing was provided.

    Examples:
        Never pass secrets via argv; this helper is the supported path.
    """
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        # Support a single trailing newline from echo/pipe.
        return data.rstrip("\n") if data else ""
    return getpass.getpass("Password to analyze: ")


def _safe_int(raw: str, default: int, min_val: int, max_val: int) -> int:
    """Parse an int within bounds, returning default for empty input.

    Args:
        raw: User input string.
        default: Value used when raw is empty.
        min_val: Inclusive minimum.
        max_val: Inclusive maximum.

    Returns:
        Parsed integer within [min_val, max_val].

    Raises:
        ValueError: If raw is non-empty but invalid or out of range.
    """
    if raw.strip() == "":
        return default
    value = int(raw)
    if not min_val <= value <= max_val:
        raise ValueError(f"Value must be between {min_val} and {max_val}")
    return value


def _colored_score(score: int) -> Any:
    style, label, _color = SCORE_STYLES.get(score, ("bold white", "UNKNOWN", "white"))
    return Text(f"{score}/4 — {label}", style=style)


def _strength_bar_rich(score: int) -> Any:
    filled = score + 1
    empty = 4 - score
    _style, _label, color = SCORE_STYLES.get(score, ("bold white", "UNKNOWN", "white"))
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim")
    return bar


def _print_strength_rich(report: Any, show_password: bool = False) -> None:
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

    fb = Text()
    if report.feedback:
        for i, msg in enumerate(report.feedback):
            if i > 0:
                fb.append("\n")
            fb.append(f"  ▸ {msg}", style="yellow")

    console.print(Panel(table, title="[bold]Password Analysis[/bold]", border_style="blue"))
    console.print(crack_table)
    if report.feedback:
        console.print(Panel(fb, title="[bold]Feedback[/bold]", border_style="yellow"))


def _print_passwords_rich(passwords: list[str], label: str) -> None:
    console = _console()
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("#", style="dim", width=4)
    table.add_column("Password", style="bold cyan")
    for i, pwd in enumerate(passwords, 1):
        table.add_row(str(i), pwd)
    console.print(
        Panel(
            table,
            title=f"[bold green]Generated {len(passwords)} {label}[/bold green]",
            border_style="green",
        )
    )


def _print_passwords_plain(passwords: list[str], label: str) -> None:
    print(f"\nGenerated {len(passwords)} {label}:\n")
    for i, pwd in enumerate(passwords, 1):
        print(f"  {i:>2}. {pwd}")
    print()


def _print_strength_plain(report: Any, show_password: bool = False) -> None:
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


def _copy_and_clear(text: str, clear_seconds: int, console: Any = None) -> None:
    """Copy to clipboard and block until auto-clear completes.

    Args:
        text: Secret to copy.
        clear_seconds: Seconds to wait before clearing. Zero disables clear.
        console: Optional rich console for messages.
    """
    if not copy_to_clipboard(text, auto_clear_seconds=0):
        msg = "Clipboard not available."
        if console:
            console.print(f"[yellow]{msg}[/yellow]")
        else:
            print(f"  {msg}")
        return

    if clear_seconds <= 0:
        msg = "Copied to clipboard."
        if console:
            console.print(f"[green]{msg}[/green]")
        else:
            print(f"  {msg}")
        return

    msg = f"Copied! Clipboard clears in {clear_seconds}s (waiting)..."
    if console:
        console.print(f"[green]{msg}[/green]")
    else:
        print(f"  {msg}")
    try:
        time.sleep(clear_seconds)
    except KeyboardInterrupt:
        pass
    clear_clipboard()
    done = "Clipboard cleared."
    if console:
        console.print(f"[dim]{done}[/dim]")
    else:
        print(f"  {done}")


def _offer_clipboard_rich(passwords: list[str], clear_seconds: int = 30) -> None:
    console = _console()
    if len(passwords) == 1:
        if Confirm.ask("\n[bold]Copy to clipboard?[/bold]", default=True):
            _copy_and_clear(passwords[0], clear_seconds, console=console)
    else:
        if Confirm.ask(
            "\n[bold]Copy all (newline-separated) to clipboard?[/bold]", default=False
        ):
            _copy_and_clear("\n".join(passwords), clear_seconds, console=console)
    console.print()


def _offer_clipboard_plain(passwords: list[str], clear_seconds: int = 30) -> None:
    if len(passwords) == 1:
        if _input_yes_no("Copy to clipboard?", True):
            _copy_and_clear(passwords[0], clear_seconds)
    else:
        if _input_yes_no("Copy all (newline-separated) to clipboard?", False):
            _copy_and_clear("\n".join(passwords), clear_seconds)
    print()


def interactive_mode() -> None:
    """Run interactive password generation."""
    if RICH_AVAILABLE:
        _interactive_rich()
    else:
        _interactive_plain()


def _interactive_rich() -> None:
    console = _console()
    console.print(
        Panel(
            "[bold]Secure Password Generator[/bold]\n"
            "[dim]Cryptographically secure • Configurable[/dim]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )
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

        choice = Prompt.ask(
            "\n[bold cyan]Choice[/bold cyan]", choices=["1", "2", "3", "4", "5"]
        )
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


def _ask_int_rich(
    prompt: str, default: int, min_val: int, max_val: int, console: Any
) -> int | None:
    raw = Prompt.ask(prompt, default=str(default))
    try:
        return _safe_int(raw, default, min_val, max_val)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return None


def _interactive_random_password_rich() -> None:
    console = _console()
    length = _ask_int_rich("Password length", 16, 4, 256, console)
    if length is None:
        return
    uppercase = Confirm.ask("Include uppercase (A-Z)?", default=True)
    lowercase = Confirm.ask("Include lowercase (a-z)?", default=True)
    digits = Confirm.ask("Include digits (0-9)?", default=True)
    symbols = Confirm.ask("Include symbols (!@#...)?", default=True)
    exclude_ambiguous = Confirm.ask(
        "Exclude ambiguous chars (l, I, 1, O, 0)?", default=False
    )
    count = _ask_int_rich("How many passwords?", 1, 1, 100, console)
    if count is None:
        return

    try:
        config = GeneratorConfig(
            length=length,
            uppercase=uppercase,
            lowercase=lowercase,
            digits=digits,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating...", total=None)
        passwords = [generate(config) for _ in range(count)]
        progress.update(task, completed=True)

    _print_passwords_rich(passwords, f"password(s) ({length} chars)")
    _print_strength_rich(analyze(passwords[0]))
    _offer_clipboard_rich(passwords)


def _interactive_passphrase_rich() -> None:
    console = _console()
    words = _ask_int_rich("Number of words", 4, 2, 10, console)
    if words is None:
        return
    console.print(
        "  [dim]1. Hyphen (-)   2. Space   3. Period (.)   4. Underscore (_)[/dim]"
    )
    sep_choice = Prompt.ask("Separator", choices=["1", "2", "3", "4"], default="1")
    separator = {"1": "-", "2": " ", "3": ".", "4": "_"}[sep_choice]
    capitalize = Confirm.ask("Capitalize words?", default=False)
    count = _ask_int_rich("How many passphrases?", 1, 1, 100, console)
    if count is None:
        return

    try:
        config = PassphraseConfig(
            words=words, separator=separator, capitalize=capitalize
        )
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating...", total=None)
        passphrases = [generate_passphrase(config) for _ in range(count)]
        progress.update(task, completed=True)

    _print_passwords_rich(passphrases, f"passphrase(s) ({words} words)")
    _print_strength_rich(analyze(passphrases[0]))
    _offer_clipboard_rich(passphrases)


def _interactive_pin_rich() -> None:
    console = _console()
    length = _ask_int_rich("PIN length", 4, 1, 12, console)
    if length is None:
        return
    avoid_repeats = Confirm.ask("Avoid repeated digits (no 1111)?", default=False)
    avoid_sequential = Confirm.ask(
        "Avoid sequential runs (no 1234)?", default=False
    )
    count = _ask_int_rich("How many PINs?", 1, 1, 100, console)
    if count is None:
        return

    try:
        config = PinConfig(
            length=length,
            avoid_repeats=avoid_repeats,
            avoid_sequential=avoid_sequential,
        )
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return

    try:
        pins = [generate_pin(config) for _ in range(count)]
    except RuntimeError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return

    _print_passwords_rich(pins, f"PIN(s) ({length} digits)")
    _offer_clipboard_rich(pins)


def _interactive_analyze_rich() -> None:
    console = _console()
    password = getpass.getpass("Password to analyze: ")
    if not password:
        console.print("[red]No password entered.[/red]")
        return
    _print_strength_rich(analyze(password))


def _interactive_plain() -> None:
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


def _interactive_random_password_plain() -> None:
    length = _input_int(
        "Password length (4-256, default 16): ", default=16, min_val=4, max_val=256
    )
    uppercase = _input_yes_no("Include uppercase (A-Z)?", True)
    lowercase = _input_yes_no("Include lowercase (a-z)?", True)
    digits = _input_yes_no("Include digits (0-9)?", True)
    symbols = _input_yes_no("Include symbols (!@#...)?", True)
    exclude_ambiguous = _input_yes_no(
        "Exclude ambiguous chars (l, I, 1, O, 0)?", False
    )
    count = _input_int(
        "How many passwords? (1-100, default 1): ", default=1, min_val=1, max_val=100
    )
    try:
        config = GeneratorConfig(
            length=length,
            uppercase=uppercase,
            lowercase=lowercase,
            digits=digits,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
    except ValueError as exc:
        print(f"\nError: {exc}\n")
        return
    passwords = [generate(config) for _ in range(count)]
    _print_passwords_plain(passwords, f"password(s) ({length} chars)")
    _print_strength_plain(analyze(passwords[0]))
    _offer_clipboard_plain(passwords)


def _interactive_passphrase_plain() -> None:
    words = _input_int("Number of words (2-10, default 4): ", default=4, min_val=2, max_val=10)
    print("Separator options:  1. Hyphen (-)  2. Space  3. Period (.)  4. Underscore (_)")
    sep_choice = input("Choice (1-4, default 1): ").strip()
    separator = {"1": "-", "2": " ", "3": ".", "4": "_"}.get(sep_choice, "-")
    capitalize = _input_yes_no("Capitalize words?", False)
    count = _input_int(
        "How many passphrases? (1-100, default 1): ", default=1, min_val=1, max_val=100
    )
    try:
        config = PassphraseConfig(
            words=words, separator=separator, capitalize=capitalize
        )
    except ValueError as exc:
        print(f"\nError: {exc}\n")
        return
    passphrases = [generate_passphrase(config) for _ in range(count)]
    _print_passwords_plain(passphrases, f"passphrase(s) ({words} words)")
    _print_strength_plain(analyze(passphrases[0]))
    _offer_clipboard_plain(passphrases)


def _interactive_pin_plain() -> None:
    length = _input_int("PIN length (1-12, default 4): ", default=4, min_val=1, max_val=12)
    avoid_repeats = _input_yes_no("Avoid repeated digits (no 1111)?", False)
    avoid_sequential = _input_yes_no("Avoid sequential runs (no 1234)?", False)
    count = _input_int("How many PINs? (1-100, default 1): ", default=1, min_val=1, max_val=100)
    try:
        config = PinConfig(
            length=length,
            avoid_repeats=avoid_repeats,
            avoid_sequential=avoid_sequential,
        )
    except ValueError as exc:
        print(f"\nError: {exc}\n")
        return
    try:
        pins = [generate_pin(config) for _ in range(count)]
    except RuntimeError as exc:
        print(f"\nError: {exc}\n")
        return
    _print_passwords_plain(pins, f"PIN(s) ({length} digits)")
    _offer_clipboard_plain(pins)


def _interactive_analyze_plain() -> None:
    password = getpass.getpass("Password to analyze: ")
    if not password:
        print("No password entered.\n")
        return
    _print_strength_plain(analyze(password))


def _input_int(prompt: str, default: int, min_val: int = 1, max_val: int = 1000) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            return _safe_int(raw, default, min_val, max_val)
        except ValueError:
            print(f"Please enter a number between {min_val} and {max_val}.")


def _input_yes_no(prompt: str, default: bool = True) -> bool:
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


def cli_mode(args: argparse.Namespace) -> None:
    """Run CLI mode with parsed arguments."""
    console = _console() if RICH_AVAILABLE else None

    if args.analyze:
        password = _read_password_securely()
        if not password:
            msg = "No password provided."
            if console:
                console.print(f"[red]{msg}[/red]")
            else:
                print(msg)
            sys.exit(1)
        report = analyze(password)
        if args.json:
            print(
                json.dumps(
                    {
                        "score": report.score,
                        "entropy": report.entropy,
                        "guesses": report.guesses,
                        "crack_times": report.crack_times,
                        "feedback": report.feedback,
                        "patterns": report.patterns,
                    },
                    indent=2,
                )
            )
        elif RICH_AVAILABLE:
            _print_strength_rich(report)
        else:
            _print_strength_plain(report)
        return

    if args.count < 1 or args.count > 1000:
        msg = "count must be between 1 and 1000"
        if console:
            console.print(f"[bold red]Error:[/bold red] {msg}")
        else:
            print(f"Error: {msg}")
        sys.exit(2)

    try:
        if args.passphrase:
            config = PassphraseConfig(
                words=args.words,
                separator=args.separator,
                capitalize=args.capitalize,
            )
            passwords = [generate_passphrase(config) for _ in range(args.count)]
            label = f"passphrase(s) ({args.words} words)"
            kind = "passphrase"
        elif args.pin:
            config = PinConfig(
                length=args.pin_length,
                avoid_repeats=args.avoid_repeats,
                avoid_sequential=args.avoid_sequential,
            )
            passwords = [generate_pin(config) for _ in range(args.count)]
            label = f"PIN(s) ({args.pin_length} digits)"
            kind = "pin"
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
            kind = "password"
    except (ValueError, RuntimeError) as exc:
        if console:
            console.print(f"[bold red]Error:[/bold red] {exc}")
        else:
            print(f"Error: {exc}")
        sys.exit(2)

    if args.json:
        print(
            json.dumps(
                {
                    "type": kind,
                    "count": args.count,
                    "passwords": passwords,
                },
                indent=2,
            )
        )
    elif RICH_AVAILABLE:
        _print_passwords_rich(passwords, label)
    else:
        _print_passwords_plain(passwords, label)

    if args.clipboard:
        joined = passwords[0] if args.count == 1 else "\n".join(passwords)
        _copy_and_clear(joined, args.clipboard_clear, console=console)


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="password-gen",
        description="Secure Password Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  password-gen                              Interactive mode
  password-gen --length 20 --count 5        Generate 5 passwords
  password-gen --passphrase --words 4       XKCD-style passphrase
  password-gen --pin --pin-length 6 --avoid-repeats
  echo -n 'secret' | password-gen --analyze # Analyze via stdin (secure)
  password-gen --analyze                    Analyze via hidden prompt
  password-gen --length 20 --json           Output as JSON
        """,
    )

    parser.add_argument("--length", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("--count", type=int, default=1, help="Number of passwords (default: 1)")
    parser.add_argument(
        "--uppercase", action="store_true", default=True, help="Include uppercase (default: True)"
    )
    parser.add_argument(
        "--no-uppercase", dest="uppercase", action="store_false", help="Exclude uppercase"
    )
    parser.add_argument(
        "--lowercase", action="store_true", default=True, help="Include lowercase (default: True)"
    )
    parser.add_argument(
        "--no-lowercase", dest="lowercase", action="store_false", help="Exclude lowercase"
    )
    parser.add_argument(
        "--digits", action="store_true", default=True, help="Include digits (default: True)"
    )
    parser.add_argument("--no-digits", dest="digits", action="store_false", help="Exclude digits")
    parser.add_argument("--no-symbols", dest="no_symbols", action="store_true", help="Exclude symbols")
    parser.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Exclude ambiguous chars (l, I, 1, O, 0)",
    )

    parser.add_argument(
        "--passphrase", action="store_true", help="Generate passphrase instead of password"
    )
    parser.add_argument(
        "--words", type=int, default=4, help="Number of words for passphrase (default: 4)"
    )
    parser.add_argument(
        "--separator", default="-", help="Word separator for passphrase (default: -)"
    )
    parser.add_argument(
        "--capitalize", action="store_true", help="Capitalize passphrase words"
    )

    parser.add_argument("--pin", action="store_true", help="Generate PIN instead of password")
    parser.add_argument(
        "--pin-length", type=int, default=4, help="PIN length (default: 4)"
    )
    parser.add_argument(
        "--avoid-repeats", action="store_true", help="Avoid repeated digits in PIN"
    )
    parser.add_argument(
        "--avoid-sequential", action="store_true", help="Avoid sequential digit runs in PIN"
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze a password (reads from stdin if piped, else hidden prompt; never from argv)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--clipboard", action="store_true", help="Copy to clipboard")
    parser.add_argument(
        "--clipboard-clear",
        type=int,
        default=30,
        help="Clipboard auto-clear seconds; CLI blocks until cleared (default: 30)",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for the password-gen command.

    Args:
        argv: Optional argument list (defaults to sys.argv[1:]).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Interactive when no meaningful generation/analyze flags are given.
    if argv is None:
        raw_args = sys.argv[1:]
    else:
        raw_args = list(argv)

    if not raw_args:
        interactive_mode()
    else:
        cli_mode(args)


if __name__ == "__main__":
    main()
