"""Password strength analyzer inspired by zxcvbn."""

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

_COMMON_PASSWORDS_PATH = Path(__file__).parent / "common_passwords.txt"

# Keyboard patterns to detect
_KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "`~!@#$%^&*()_+-=",
    "[]\\{}|;':\",./<>?",
]

# Common sequential patterns
_SEQUENCES = {
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "0123456789",
    "9876543210",
}


def _load_common_passwords() -> set[str]:
    """Load common passwords from file."""
    if not _COMMON_PASSWORDS_PATH.exists():
        return set()
    passwords = set()
    for line in _COMMON_PASSWORDS_PATH.read_text(encoding="utf-8").splitlines():
        pwd = line.strip()
        if pwd:
            passwords.add(pwd.lower())
    return passwords


COMMON_PASSWORDS = _load_common_passwords()


def _detect_keyboard_pattern(password: str) -> bool:
    """Detect if password contains keyboard patterns."""
    lower = password.lower()
    for row in _KEYBOARD_ROWS:
        # Check forward and reverse, length 4+
        for length in range(4, min(len(row) + 1, len(lower) + 1)):
            for i in range(len(row) - length + 1):
                pattern = row[i : i + length]
                if pattern in lower or pattern[::-1] in lower:
                    return True
    return False


def _detect_sequence(password: str) -> bool:
    """Detect sequential patterns like abc, 123, cba."""
    lower = password.lower()
    for seq in _SEQUENCES:
        for length in range(3, min(len(seq) + 1, len(lower) + 1)):
            for i in range(len(seq) - length + 1):
                pattern = seq[i : i + length]
                if pattern in lower:
                    return True
    return False


def _detect_repeats(password: str) -> bool:
    """Detect repeated characters like aaa, 1111."""
    for length in range(3, len(password) + 1):
        for i in range(len(password) - length + 1):
            chunk = password[i : i + length]
            if len(set(chunk)) == 1:
                return True
    return False


def _detect_dates(password: str) -> bool:
    """Detect date-like patterns."""
    # YYYY, MM/DD, DD/MM
    date_patterns = [
        r"\b(19|20)\d{2}\b",  # Years
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",  # Date formats
        r"\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b",
    ]
    for pattern in date_patterns:
        if re.search(pattern, password):
            return True
    return False


def _estimate_guesses(password: str) -> float:
    """Estimate the number of guesses needed to crack the password."""
    length = len(password)

    # Estimate pool size based on character types
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # printable ASCII symbols

    if pool == 0:
        pool = 26

    # Base guesses: pool^length
    guesses = pool**length

    # Reduce for patterns
    if _detect_keyboard_pattern(password):
        guesses *= 0.01
    if _detect_sequence(password):
        guesses *= 0.1
    if _detect_repeats(password):
        guesses *= 0.1
    if _detect_dates(password):
        guesses *= 0.5

    # Check common passwords
    if password.lower() in COMMON_PASSWORDS:
        guesses = min(guesses, 100)

    return max(guesses, 1)


@dataclass
class StrengthReport:
    """Password strength analysis result."""

    password: str
    score: int  # 0-4
    guesses: float
    entropy: float
    crack_times: dict[str, str]
    crack_times_seconds: dict[str, float]
    feedback: list[str]
    patterns: list[str]


def analyze(password: str) -> StrengthReport:
    """Analyze password strength.

    Args:
        password: The password to analyze.

    Returns:
        StrengthReport with score, crack times, and feedback.

    Examples:
        >>> report = analyze("P@ssw0rd123")
        >>> print(report.score)  # 0-4
        >>> print(report.crack_times)
    """
    if not password:
        return StrengthReport(
            password="",
            score=0,
            guesses=0,
            entropy=0,
            crack_times={},
            crack_times_seconds={},
            feedback=["Password is empty"],
            patterns=[],
        )

    guesses = _estimate_guesses(password)

    # Calculate entropy
    entropy = math.log2(max(guesses, 1))

    # Crack time estimates (seconds)
    rates = {
        "online_throttled_100_per_hour": 100 / 3600,  # 100 attempts per hour
        "online_no_throttling_10_per_second": 10,
        "offline_slow_hashing_1e4_per_second": 10_000,
        "offline_fast_hashing_1e10_per_second": 10_000_000_000,
    }

    crack_times_seconds = {}
    crack_times = {}
    for scenario, rate in rates.items():
        seconds = guesses / rate / 2  # Average case: half the keyspace
        crack_times_seconds[scenario] = seconds
        crack_times[scenario] = _format_time(seconds)

    # Score (0-4)
    if guesses < 1_000:
        score = 0
    elif guesses < 1_000_000:
        score = 1
    elif guesses < 100_000_000:
        score = 2
    elif guesses < 10_000_000_000:
        score = 3
    else:
        score = 4

    # Detect patterns
    patterns = []
    if password.lower() in COMMON_PASSWORDS:
        patterns.append("common_password")
    if _detect_keyboard_pattern(password):
        patterns.append("keyboard_pattern")
    if _detect_sequence(password):
        patterns.append("sequence")
    if _detect_repeats(password):
        patterns.append("repetition")
    if _detect_dates(password):
        patterns.append("date")

    # Generate feedback
    feedback = []
    if "common_password" in patterns:
        feedback.append("This is a commonly used password")
    if "keyboard_pattern" in patterns:
        feedback.append("Contains keyboard pattern (e.g., qwerty)")
    if "sequence" in patterns:
        feedback.append("Contains sequential characters (e.g., abc, 123)")
    if "repetition" in patterns:
        feedback.append("Contains repeated characters (e.g., aaa)")
    if "date" in patterns:
        feedback.append("Contains date-like patterns")
    if len(password) < 8:
        feedback.append("Password is too short (minimum 8 characters)")
    if score >= 3 and not feedback:
        feedback.append("Good password!")

    return StrengthReport(
        password="*" * len(password),  # Don't expose the password
        score=score,
        guesses=guesses,
        entropy=entropy,
        crack_times=crack_times,
        crack_times_seconds=crack_times_seconds,
        feedback=feedback,
        patterns=patterns,
    )


def _format_time(seconds: float) -> str:
    """Format seconds into human-readable time."""
    if seconds < 0.001:
        return "instantly"
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} hours"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.0f} days"
    if seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365):.0f} years"
    if seconds < 86400 * 365 * 1_000_000:
        return f"{seconds / (86400 * 365 * 1000):.0f} thousand years"
    if seconds < 86400 * 365 * 1_000_000_000:
        return f"{seconds / (86400 * 365 * 1_000_000):.0f} million years"
    return f"{seconds / (86400 * 365 * 1_000_000_000):.0f} billion years"
