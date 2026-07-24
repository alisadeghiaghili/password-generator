# Password Generator

[![PyPI version](https://img.shields.io/pypi/v/password-generator.svg)](https://pypi.org/project/password-generator/)
[![Python versions](https://img.shields.io/pypi/pyversions/password-generator.svg)](https://pypi.org/project/password-generator/)
[![Downloads](https://img.shields.io/pypi/dm/password-generator.svg)](https://pypi.org/project/password-generator/)
[![License](https://img.shields.io/pypi/l/password-generator.svg)](https://github.com/alisadeghiaghili/password-generator/blob/master/LICENSE)

[English](README.md) | [فارسی](README-fa.md) | [Deutsch](README-de.md)

A secure, configurable password generation toolkit for Python. Generate random passwords, XKCD-style passphrases, numeric PINs, and analyze password strength — all from a simple API or an interactive CLI.

**Version:** 2.0.0 | **License:** Apache 2.0 | **Python:** 3.10+

---

## Features

- **Random Passwords** — Cryptographically secure, fully customizable character sets
- **Passphrases** — XKCD-style memorable passphrases from a 2048-word list
- **PINs** — Numeric codes with repeat/sequence avoidance
- **Strength Analysis** — Entropy scoring, crack-time estimates, pattern detection
- **Clipboard Integration** — Auto-copy with timed auto-clear (cross-platform)
- **Interactive CLI** — Beautiful rich terminal UI with colored panels and strength bars
- **JSON Output** — Machine-readable output for scripting and automation
- **Cross-Platform** — Windows, macOS, Linux

---

## Installation

### From PyPI (recommended)

```bash
# Core library (zero dependencies)
pip install password-generator

# With beautiful CLI output (rich terminal UI)
pip install password-generator[cli]
```

### From Source

```bash
git clone https://github.com/alisadeghiaghili/password-generator.git
cd password-generator
pip install -e ".[cli]"
```

### Development

```bash
pip install -e ".[dev,cli]"
pytest
```

---

## Quick Start

### As a Python Library

```python
from password_generator import generate, generate_passphrase, generate_pin, analyze

# Generate a random 20-character password
password = generate(length=20)
print(password)  # e.g. "k8#Qx!2mNp@Lw9Rz"

# Generate a 5-word passphrase
passphrase = generate_passphrase(words=5, separator=" ", capitalize=True)
print(passphrase)  # e.g. "Correct Horse Battery Staple Moon"

# Generate a 6-digit PIN
pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
print(pin)  # e.g. "849205"

# Analyze password strength
report = analyze("P@ssw0rd123")
print(f"Score: {report.score}/4")
print(f"Entropy: {report.entropy:.0f} bits")
print(f"Crack time (offline): {report.crack_times['offline_fast_hashing_1e10_per_second']}")
```

### As a CLI Tool

```bash
# Interactive mode
python cli.py

# Generate 5 passwords of length 20
python cli.py --length 20 --count 5

# Generate a passphrase
python cli.py --passphrase --words 4 --separator " "

# Generate a 6-digit PIN
python cli.py --pin --pin-length 6 --avoid-repeats

# Analyze a password
python cli.py --analyze "MyP@ssw0rd"

# JSON output
python cli.py --length 24 --json

# Copy to clipboard
python cli.py --length 16 --clipboard
```

---

## API Reference

### `generate(config=None, **kwargs) -> str`

Generate a cryptographically secure random password.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `length` | `int` | `16` | Password length (4–256) |
| `uppercase` | `bool` | `True` | Include uppercase letters (A–Z) |
| `lowercase` | `bool` | `True` | Include lowercase letters (a–z) |
| `digits` | `bool` | `True` | Include digits (0–9) |
| `symbols` | `bool` | `True` | Include symbols |
| `symbol_chars` | `str` | `!@#$%^&*()_+-=[]{}|;:,.<>?` | Custom symbol characters |
| `exclude_ambiguous` | `bool` | `False` | Exclude ambiguous chars: `l`, `I`, `1`, `O`, `0`, `o` |

```python
from password_generator import generate, GeneratorConfig

# Using kwargs
pwd = generate(length=24, uppercase=True, digits=True, symbols=False)

# Using a config object
config = GeneratorConfig(length=32, exclude_ambiguous=True)
pwd = generate(config)
```

### `generate_passphrase(config=None, **kwargs) -> str`

Generate an XKCD-style memorable passphrase.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `words` | `int` | `4` | Number of words (2–10) |
| `separator` | `str` | `-` | Word separator character |
| `capitalize` | `bool` | `False` | Capitalize first letter of each word |
| `wordlist_path` | `str \| None` | `None` | Custom wordlist file path (min 100 words) |

```python
from password_generator import generate_passphrase, PassphraseConfig

# Default: 4 words, hyphen-separated
phrase = generate_passphrase()
# e.g. "correct-horse-battery-staple"

# Custom: 6 words, space-separated, capitalized
phrase = generate_passphrase(words=6, separator=" ", capitalize=True)
# e.g. "Correct Horse Battery Staple Moon River"

# Custom wordlist
config = PassphraseConfig(words=4, wordlist_path="/path/to/wordlist.txt")
phrase = generate_passphrase(config)
```

### `generate_pin(config=None, **kwargs) -> str`

Generate a random numeric PIN.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `length` | `int` | `4` | PIN length (1–12) |
| `avoid_repeats` | `bool` | `False` | Avoid 3+ identical digits in a row |
| `avoid_sequential` | `bool` | `False` | Avoid ascending/descending sequences |

```python
from password_generator import generate_pin, PinConfig

# Basic 4-digit PIN
pin = generate_pin()

# 6-digit, no repeats, no sequences
pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)

# Using config
config = PinConfig(length=8, avoid_sequential=True)
pin = generate_pin(config)
```

### `analyze(password: str) -> StrengthReport`

Analyze password strength with detailed feedback.

```python
from password_generator import analyze

report = analyze("MyP@ssw0rd123!")

# Score (0–4): 0=Very Weak, 1=Weak, 2=Fair, 3=Strong, 4=Very Strong
print(report.score)

# Entropy in bits
print(report.entropy)

# Estimated number of guesses to crack
print(report.guesses)

# Human-readable crack time estimates
print(report.crack_times)
# {
#   "online_throttled_100_per_hour": "centuries",
#   "online_no_throttling_10_per_second": "years",
#   "offline_slow_hashing_1e4_per_second": "hours",
#   "offline_fast_hashing_1e10_per_second": "seconds"
# }

# Raw crack times in seconds
print(report.crack_times_seconds)

# Actionable feedback
print(report.feedback)
# e.g. ["Good password!"]

# Detected patterns
print(report.patterns)
# e.g. [] (empty = no weak patterns found)
```

**Detected patterns:** `common_password`, `keyboard_pattern`, `sequence`, `repetition`, `date`

### `copy_to_clipboard(text, auto_clear_seconds=0) -> bool`

Copy text to clipboard with optional auto-clear.

```python
from password_generator import copy_to_clipboard, clear_clipboard

# Copy to clipboard
copy_to_clipboard("my_secure_password")

# Copy with 30-second auto-clear
copy_to_clipboard("my_secure_password", auto_clear_seconds=30)

# Manually clear clipboard
clear_clipboard()
```

### `calculate_entropy(pool_size, length) -> int`

Calculate password entropy in bits.

```python
from password_generator.generator import calculate_entropy

# 8 lowercase letters: 26^8 possibilities
entropy = calculate_entropy(26, 8)  # ~37 bits
```

### `passphrase_entropy(word_count, wordlist_size=2048) -> int`

Calculate passphrase entropy in bits.

```python
from password_generator.passphrase import passphrase_entropy

# 4 words from 2048-word list
entropy = passphrase_entropy(4)  # ~44 bits

# 6 words
entropy = passphrase_entropy(6)  # ~66 bits
```

---

## CLI Reference

### Interactive Mode

Run without arguments to start the interactive wizard:

```bash
python cli.py
```

The wizard guides you through:
1. Choosing generation type (password / passphrase / PIN / analyze)
2. Configuring options
3. Viewing results with strength analysis
4. Optionally copying to clipboard

### Command-Line Arguments

| Argument | Description | Default |
|---|---|---|
| `--length N` | Password length (4–256) | `16` |
| `--count N` | Number of passwords to generate | `1` |
| `--uppercase` / `--no-uppercase` | Include/exclude uppercase | `True` |
| `--lowercase` / `--no-lowercase` | Include/exclude lowercase | `True` |
| `--digits` / `--no-digits` | Include/exclude digits | `True` |
| `--no-symbols` | Exclude symbols | `False` |
| `--exclude-ambiguous` | Exclude ambiguous characters | `False` |
| `--passphrase` | Generate passphrase mode | — |
| `--words N` | Word count for passphrase (2–10) | `4` |
| `--separator CHAR` | Word separator | `-` |
| `--capitalize` | Capitalize passphrase words | `False` |
| `--pin` | Generate PIN mode | — |
| `--pin-length N` | PIN length (1–12) | `4` |
| `--avoid-repeats` | Avoid repeated digits in PIN | `False` |
| `--avoid-sequential` | Avoid sequential digits in PIN | `False` |
| `--analyze PASSWORD` | Analyze a password | — |
| `--json` | Output as JSON | `False` |
| `--clipboard` | Copy result to clipboard | `False` |
| `--clipboard-clear N` | Clipboard auto-clear seconds | `30` |

### Examples

```bash
# Generate 10 uppercase-only passwords, 12 chars each
python cli.py --length 12 --count 10 --no-lowercase --no-digits --no-symbols

# Passphrase with space separator, capitalized
python cli.py --passphrase --words 5 --separator " " --capitalize

# 8-digit PIN, avoid repeats and sequences
python cli.py --pin --pin-length 8 --avoid-repeats --avoid-sequential

# Analyze and output as JSON
python cli.py --analyze "Tr0ub4dor&3" --json

# Generate and copy to clipboard
python cli.py --length 24 --clipboard --clipboard-clear 60
```

---

## Use Cases

### 1. Application Password Storage

Generate unique passwords for each account:

```python
from password_generator import generate

accounts = ["email", "bank", "social", "cloud"]
for account in accounts:
    pwd = generate(length=20, symbols=True)
    print(f"{account}: {pwd}")
```

### 2. Secure Passphrases for Encryption Keys

Use passphrases for memorable yet strong keys:

```python
from password_generator import generate_passphrase

# Disk encryption passphrase
phrase = generate_passphrase(words=6, capitalize=True, separator=" ")
print(f"Encryption key: {phrase}")
# e.g. "Correct Horse Battery Staple Moon River"
```

### 3. PIN Generation for Two-Factor Authentication

Generate secure PINs for 2FA apps:

```python
from password_generator import generate_pin

# 6-digit TOTP backup codes
for i in range(5):
    pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
    print(f"Backup code {i+1}: {pin}")
```

### 4. Batch Password Generation for DevOps

Generate multiple passwords for infrastructure:

```python
from password_generator import generate, generate_pin
import json

# Generate database credentials
db_password = generate(length=32, exclude_ambiguous=True)
api_key = generate(length=48, uppercase=True, lowercase=True, digits=True, symbols=False)
admin_pin = generate_pin(length=8, avoid_sequential=True)

config = {
    "database_password": db_password,
    "api_key": api_key,
    "admin_pin": admin_pin
}
print(json.dumps(config, indent=2))
```

### 5. Password Strength Audit

Audit existing passwords in your application:

```python
from password_generator import analyze

user_passwords = ["password123", "Tr0ub4dor&3", "k8#Qx!2mNp@Lw9Rz"]

for pwd in user_passwords:
    report = analyze(pwd)
    status = "OK" if report.score >= 3 else "WEAK"
    print(f"[{status}] score={report.score} entropy={report.entropy:.0f}b feedback={report.feedback}")
```

### 6. Integration with Password Managers

Export generated passwords as JSON for import:

```python
from password_generator import generate, generate_passphrase
import json

entries = []
for service in ["github", "gitlab", "npm", "pypi"]:
    entries.append({
        "service": service,
        "username": f"user_{service}",
        "password": generate(length=20),
    })

with open("passwords_export.json", "w") as f:
    json.dump(entries, f, indent=2)
```

### 7. Automated Testing with JSON Output

Use JSON output in CI/CD pipelines:

```bash
# Generate test credentials as JSON
python cli.py --length 16 --json | jq '.passwords[0]'
```

### 8. Clipboard Auto-Clear for Security

Copy passwords with automatic cleanup:

```python
from password_generator import generate, copy_to_clipboard

pwd = generate(length=24)
copy_to_clipboard(pwd, auto_clear_seconds=30)
print("Password copied — clipboard clears in 30 seconds")
```

---

## Security Details

- Uses Python's `secrets` module for cryptographically secure random generation
- Fisher-Yates shuffle ensures uniform distribution
- PIN generation retries up to 10,000 times to satisfy constraints
- Strength analyzer checks against a database of 157 common/breached passwords
- Detects keyboard patterns, sequences, repetitions, and date patterns
- Clipboard auto-clear prevents password exposure after use
- Passwords are masked in `StrengthReport` output (never exposed)

---

## Project Structure

```
password-generator/
├── password_generator/          # Core Python package
│   ├── __init__.py              # Public API exports
│   ├── generator.py             # Random password generation
│   ├── passphrase.py            # XKCD-style passphrase generation
│   ├── pin.py                   # Numeric PIN generation
│   ├── strength.py              # Password strength analyzer
│   ├── clipboard.py             # Cross-platform clipboard ops
│   ├── wordlist.txt             # 2048-word list for passphrases
│   └── common_passwords.txt     # 157 common/breached passwords
├── tests/
│   └── test_all.py              # Comprehensive test suite
├── cli.py                       # Interactive CLI & argparse
├── PasswordGenerator.py         # Entry point wrapper
├── pyproject.toml               # Build configuration
└── README.md                    # This file
```

---

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test class
pytest tests/test_all.py::TestGenerate -v
```

---

## Requirements

- Python 3.10 or higher
- No external dependencies (uses only stdlib: `secrets`, `string`, `math`, `re`, `dataclasses`, `subprocess`)
- Optional: `rich` for beautiful CLI output (`pip install password-generator[cli]`)
- Linux clipboard requires `xclip` or `xsel`

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

Copyright 2024-2026 Ali Sadeghi Aghili. You may not use this work except in compliance with the License.

---

## Author

**Ali Sadeghi Aghili** - [alisadeghiaghili@gmail.com](mailto:alisadeghiaghili@gmail.com)

Repository: [github.com/alisadeghiaghili/password-generator](https://github.com/alisadeghiaghili/password-generator)
