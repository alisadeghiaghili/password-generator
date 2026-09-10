"""
password_generator - A secure, configurable password generation toolkit.

Usage:
    from password_generator import generate, generate_passphrase, generate_pin, analyze

    pwd = generate(length=20, uppercase=True, digits=True, symbols=True)
    phrase = generate_passphrase(words=5, separator="-", capitalize=True)
    pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
    report = analyze("not-on-argv")
"""

from password_generator.clipboard import clear_clipboard, copy_to_clipboard
from password_generator.generator import GeneratorConfig, calculate_entropy, generate
from password_generator.passphrase import (
    PassphraseConfig,
    generate_passphrase,
    passphrase_entropy,
)
from password_generator.pin import PinConfig, generate_pin
from password_generator.strength import StrengthReport, analyze
from password_generator.zxcvbn_backend import zxcvbn_available

__version__ = "2.2.0"
__all__ = [
    "generate",
    "generate_passphrase",
    "generate_pin",
    "analyze",
    "copy_to_clipboard",
    "clear_clipboard",
    "calculate_entropy",
    "passphrase_entropy",
    "zxcvbn_available",
    "GeneratorConfig",
    "PassphraseConfig",
    "PinConfig",
    "StrengthReport",
    "__version__",
]
