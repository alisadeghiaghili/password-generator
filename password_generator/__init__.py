"""
password_generator - A secure, configurable password generation toolkit.

Usage:
    from password_generator import generate, generate_passphrase, generate_pin, analyze

    # Random password
    pwd = generate(length=20, uppercase=True, digits=True, symbols=True)

    # Passphrase
    phrase = generate_passphrase(words=5, separator="-", capitalize=True)

    # PIN
    pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)

    # Strength analysis
    report = analyze("P@ssw0rd123")
"""

from password_generator.generator import generate, GeneratorConfig
from password_generator.passphrase import generate_passphrase, PassphraseConfig
from password_generator.pin import generate_pin, PinConfig
from password_generator.strength import analyze, StrengthReport, PasswordPolicy, PolicyResult
from password_generator.clipboard import copy_to_clipboard, clear_clipboard
from password_generator.breach import check_breach, BreachResult
from password_generator.export import export_json, export_csv, export_keepass, PasswordEntry

__version__ = "2.0.0"
__all__ = [
    "generate",
    "generate_passphrase",
    "generate_pin",
    "analyze",
    "copy_to_clipboard",
    "clear_clipboard",
    "check_breach",
    "BreachResult",
    "export_json",
    "export_csv",
    "export_keepass",
    "PasswordEntry",
    "GeneratorConfig",
    "PassphraseConfig",
    "PinConfig",
    "StrengthReport",
    "PasswordPolicy",
    "PolicyResult",
]
