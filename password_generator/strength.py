"""Password strength analyzer inspired by zxcvbn."""

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

__all__ = ["analyze", "StrengthReport", "PasswordPolicy"]

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
    """Load common passwords from file.

    Returns:
        Set of lowercase common passwords.
    """
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
    """Detect if password contains keyboard patterns.

    Args:
        password: Password string to check.

    Returns:
        True if password contains qwerty, asdf, or similar patterns.

    Examples:
        >>> _detect_keyboard_pattern("qwerty")
        True
        >>> _detect_keyboard_pattern("myP@ss1")
        False
    """
    lower: str = password.lower()
    for row in _KEYBOARD_ROWS:
        # Check forward and reverse, length 4+
        for length in range(4, min(len(row) + 1, len(lower) + 1)):
            for i in range(len(row) - length + 1):
                pattern: str = row[i : i + length]
                if pattern in lower or pattern[::-1] in lower:
                    return True
    return False


def _detect_sequence(password: str) -> bool:
    """Detect sequential patterns like abc, 123, cba.

    Args:
        password: Password string to check.

    Returns:
        True if password contains sequential characters.

    Examples:
        >>> _detect_sequence("abcdef")
        True
        >>> _detect_sequence("321")
        True
        >>> _detect_sequence("aX9m!")
        False
    """
    lower: str = password.lower()
    for seq in _SEQUENCES:
        for length in range(3, min(len(seq) + 1, len(lower) + 1)):
            for i in range(len(seq) - length + 1):
                pattern: str = seq[i : i + length]
                if pattern in lower:
                    return True
    return False


def _detect_repeats(password: str) -> bool:
    """Detect repeated characters like aaa, 1111.

    Args:
        password: Password string to check.

    Returns:
        True if password contains 3+ identical consecutive characters.

    Examples:
        >>> _detect_repeats("aaa111")
        True
        >>> _detect_repeats("abab")
        False
    """
    for length in range(3, len(password) + 1):
        for i in range(len(password) - length + 1):
            chunk: str = password[i : i + length]
            if len(set(chunk)) == 1:
                return True
    return False


def _detect_dates(password: str) -> bool:
    """Detect date-like patterns.

    Args:
        password: Password string to check.

    Returns:
        True if password contains date patterns (YYYY, MM/DD, etc.).

    Examples:
        >>> _detect_dates("born2024")
        True
        >>> _detect_dates("01/15/2024")
        True
        >>> _detect_dates("abcXYZ")
        False
    """
    # YYYY, MM/DD, DD/MM
    date_patterns: list[str] = [
        r"\b(19|20)\d{2}\b",  # Years
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",  # Date formats
        r"\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b",
    ]
    for pattern in date_patterns:
        if re.search(pattern, password):
            return True
    return False


def _estimate_guesses(password: str) -> float:
    """Estimate the number of guesses needed to crack the password.

    Args:
        password: Password string to estimate.

    Returns:
        Estimated number of guesses (minimum 1).
    """
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

    # Base guesses: pool^length (capped to prevent overflow)
    guesses = min(pool**length, 1e20)

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

    # Cap guesses to avoid overflow in crack time calculations
    guesses = min(guesses, 1e20)

    return max(guesses, 1)


def _detect_user_input(password: str, user_inputs: list[str]) -> bool:
    """Detect if password contains user-provided personal information.

    Args:
        password: Password string to check.
        user_inputs: List of user-provided strings (name, birthdate, etc.).

    Returns:
        True if password contains any user input.

    Examples:
        >>> _detect_user_input("John123!", ["John", "Smith"])
        True
        >>> _detect_user_input("Xy9#mK2p", ["John", "Smith"])
        False
    """
    lower = password.lower()
    for user_input in user_inputs:
        if len(user_input) >= 3 and user_input.lower() in lower:
            return True
    return False


PatternType = Literal[
    "common_password", "keyboard_pattern", "sequence", "repetition", "date", "user_input"
]


@dataclass
class StrengthReport:
    """Password strength analysis result.

    Attributes:
        password: Masked password (shown as asterisks).
        score: Strength score (0=Very Weak, 4=Very Strong).
        guesses: Estimated number of guesses to crack.
        entropy: Password entropy in bits.
        crack_times: Human-readable crack time estimates.
        crack_times_seconds: Crack times in seconds.
        feedback: Actionable suggestions to improve password.
        patterns: Detected weak patterns in the password.
    """

    password: str
    score: Literal[0, 1, 2, 3, 4]
    guesses: float
    entropy: float
    crack_times: dict[str, str]
    crack_times_seconds: dict[str, float]
    feedback: list[str]
    patterns: list[PatternType]


def analyze(
    password: str,
    user_inputs: list[str] | None = None,
    custom_dictionaries: list[set[str]] | None = None,
) -> StrengthReport:
    """Analyze password strength.

    Args:
        password: The password to analyze.
        user_inputs: List of user-provided strings (name, birthdate, etc.) to check against.
        custom_dictionaries: List of custom word sets to check against (like breach databases).

    Returns:
        StrengthReport with score, crack times, and feedback.

    Examples:
        >>> report = analyze("P@ssw0rd123")
        >>> print(report.score)  # 0-4
        >>> print(report.crack_times)

        >>> # With user inputs for better pattern detection
        >>> report = analyze("John123!", user_inputs=["John", "Smith"])

        >>> # With custom dictionaries
        >>> my_words = {"password123", "qwerty456"}
        >>> report = analyze("password123", custom_dictionaries=[my_words])
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

    # Check custom dictionaries
    if custom_dictionaries:
        for dictionary in custom_dictionaries:
            if password.lower() in {w.lower() for w in dictionary}:
                guesses = min(guesses, 100)
                break

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
    patterns: list[PatternType] = []
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
    if user_inputs and _detect_user_input(password, user_inputs):
        patterns.append("user_input")

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
    if "user_input" in patterns:
        feedback.append("Contains personal information you provided")
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
    """Format seconds into human-readable time.

    Args:
        seconds: Time duration in seconds.

    Returns:
        Human-readable string (e.g., "3 years", "instantly").

    Examples:
        >>> _format_time(0.0001)
        'instantly'
        >>> _format_time(3600)
        '1 hours'
        >>> _format_time(86400 * 365 * 1000)
        '1000 years'
    """
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


@dataclass
class PasswordPolicy:
    """Password policy for validation against configurable rules.

    Attributes:
        min_length: Minimum password length (0 = disabled).
        max_length: Maximum password length (0 = disabled).
        min_uppercase: Minimum uppercase letters required (0 = disabled).
        min_lowercase: Minimum lowercase letters required (0 = disabled).
        min_digits: Minimum digits required (0 = disabled).
        min_symbols: Minimum symbols required (0 = disabled).
        min_entropy: Minimum entropy in bits (0 = disabled).
        max_repeats: Maximum consecutive repeated characters (0 = disabled).
        exclude_patterns: List of regex patterns that must NOT match.

    Examples:
        >>> policy = PasswordPolicy(min_length=8, min_uppercase=1, min_digits=1)
        >>> result = policy.test("MyP@ss123")
        >>> print(result.is_valid)
        True

        >>> policy = PasswordPolicy(min_entropy=50)
        >>> result = policy.test("abc")
        >>> print(result.is_valid)
        False
        >>> print(result.errors)
        ['Password entropy too low (14 bits, need 50)']
    """

    min_length: int = 0
    max_length: int = 0
    min_uppercase: int = 0
    min_lowercase: int = 0
    min_digits: int = 0
    min_symbols: int = 0
    min_entropy: int = 0
    max_repeats: int = 0
    exclude_patterns: list[str] = field(default_factory=list)

    def test(self, password: str) -> "PolicyResult":
        """Test a password against this policy.

        Args:
            password: Password string to test.

        Returns:
            PolicyResult with validation results.

        Examples:
            >>> policy = PasswordPolicy(min_length=8)
            >>> result = policy.test("short")
            >>> print(result.is_valid)
            False
        """
        return _check_policy(password, self)


@dataclass
class PolicyResult:
    """Result of a password policy check.

    Attributes:
        is_valid: Whether the password passes all rules.
        errors: List of error messages for failed rules.
        score: Password strength score (0-4).
        entropy: Password entropy in bits.
    """

    is_valid: bool
    errors: list[str]
    score: Literal[0, 1, 2, 3, 4]
    entropy: float


def _check_policy(password: str, policy: PasswordPolicy) -> PolicyResult:
    """Check a password against a policy.

    Args:
        password: Password string to check.
        policy: PasswordPolicy with rules to check against.

    Returns:
        PolicyResult with validation results.

    Examples:
        >>> policy = PasswordPolicy(min_length=8)
        >>> result = _check_policy("short", policy)
        >>> print(result.is_valid)
        False
    """
    errors: list[str] = []

    # Length checks
    if policy.min_length > 0 and len(password) < policy.min_length:
        errors.append(f"Password too short ({len(password)} chars, need {policy.min_length})")
    if policy.max_length > 0 and len(password) > policy.max_length:
        errors.append(f"Password too long ({len(password)} chars, max {policy.max_length})")

    # Character type checks
    uppercase_count = sum(1 for c in password if c.isupper())
    lowercase_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    symbol_count = sum(1 for c in password if not c.isalnum())

    if policy.min_uppercase > 0 and uppercase_count < policy.min_uppercase:
        errors.append(
            f"Not enough uppercase letters ({uppercase_count}, need {policy.min_uppercase})"
        )
    if policy.min_lowercase > 0 and lowercase_count < policy.min_lowercase:
        errors.append(
            f"Not enough lowercase letters ({lowercase_count}, need {policy.min_lowercase})"
        )
    if policy.min_digits > 0 and digit_count < policy.min_digits:
        errors.append(f"Not enough digits ({digit_count}, need {policy.min_digits})")
    if policy.min_symbols > 0 and symbol_count < policy.min_symbols:
        errors.append(f"Not enough symbols ({symbol_count}, need {policy.min_symbols})")

    # Entropy check
    report = analyze(password)
    if policy.min_entropy > 0 and report.entropy < policy.min_entropy:
        errors.append(
            f"Password entropy too low ({report.entropy:.0f} bits, need {policy.min_entropy})"
        )

    # Repeat check
    if policy.max_repeats > 0:
        for length in range(policy.max_repeats + 1, len(password) + 1):
            for i in range(len(password) - length + 1):
                chunk = password[i : i + length]
                if len(set(chunk)) == 1:
                    errors.append(
                        f"Contains {length} repeated characters in a row (max {policy.max_repeats})"
                    )
                    break
            else:
                continue
            break

    # Pattern exclusion
    for pattern in policy.exclude_patterns:
        if re.search(pattern, password):
            errors.append(f"Matches excluded pattern: {pattern}")

    return PolicyResult(
        is_valid=len(errors) == 0,
        errors=errors,
        score=report.score,
        entropy=report.entropy,
    )
