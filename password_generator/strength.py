"""Password strength analyzer.

Heuristic estimator inspired by zxcvbn. All guess math is done in log10
space so long passwords never overflow. Not a substitute for a full
zxcvbn model — see README security notes.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

_COMMON_PASSWORDS_PATH = Path(__file__).parent / "common_passwords.txt"

# Keyboard rows used for pattern detection
_KEYBOARD_ROWS: tuple[str, ...] = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "`~!@#$%^&*()_+-=",
    "[]\\{}|;':\",./<>?",
)

_SEQUENCES: frozenset[str] = frozenset(
    {
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "0123456789",
        "9876543210",
    }
)

# Leet-speak normalization map (lowercase input assumed)
_LEET_TABLE = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "8": "b",
        "(": "c",
        "3": "e",
        "6": "g",
        "1": "l",
        "!": "i",
        "|": "i",
        "0": "o",
        "$": "s",
        "5": "s",
        "7": "t",
        "+": "t",
        "2": "z",
    }
)

# Log10 penalty multipliers applied when a pattern is found
_KEYBOARD_LOG10_PENALTY = -2.0  # * 0.01
_SEQUENCE_LOG10_PENALTY = -1.0  # * 0.1
_REPEAT_LOG10_PENALTY = -1.0  # * 0.1
_DATE_LOG10_PENALTY = math.log10(0.5)
_COMMON_PASSWORD_LOG10_GUESSES = 2.0  # cap at 100 guesses

# Only apply date penalty when the password is short enough that a year
# is a meaningful fraction of the secret (avoids false positives on
# random 16+ char passwords that happen to contain 19xx/20xx).
_DATE_MAX_LENGTH = 14
_YEAR_PATTERN = re.compile(r"(19|20)\d{2}")
_DATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"),
    re.compile(r"\d{4}[/-]\d{1,2}[/-]\d{1,2}"),
)


def _load_common_passwords() -> set[str]:
    """Load lowercase common/breached passwords from the bundled file.

    Returns:
        Set of lowercase password strings. Empty if the file is missing.
    """
    if not _COMMON_PASSWORDS_PATH.exists():
        return set()
    passwords: set[str] = set()
    for line in _COMMON_PASSWORDS_PATH.read_text(encoding="utf-8").splitlines():
        pwd = line.strip()
        if pwd and not pwd.startswith("#"):
            passwords.add(pwd.lower())
    return passwords


COMMON_PASSWORDS: set[str] = _load_common_passwords()


# Precompute keyboard n-grams (length 4+) for O(1) membership checks
def _build_keyboard_ngrams(min_len: int = 4) -> frozenset[str]:
    ngrams: set[str] = set()
    for row in _KEYBOARD_ROWS:
        for length in range(min_len, len(row) + 1):
            for i in range(len(row) - length + 1):
                chunk = row[i : i + length]
                ngrams.add(chunk)
                ngrams.add(chunk[::-1])
    return frozenset(ngrams)


def _build_sequence_ngrams(min_len: int = 3) -> frozenset[str]:
    ngrams: set[str] = set()
    for seq in _SEQUENCES:
        for length in range(min_len, len(seq) + 1):
            for i in range(len(seq) - length + 1):
                ngrams.add(seq[i : i + length])
    return frozenset(ngrams)


_KEYBOARD_NGRAMS: frozenset[str] = _build_keyboard_ngrams(4)
_SEQUENCE_NGRAMS: frozenset[str] = _build_sequence_ngrams(3)


def _detect_keyboard_pattern(password: str) -> bool:
    """Detect keyboard walks of length 4+ (forward or reverse).

    Args:
        password: Password to inspect.

    Returns:
        True if any known keyboard n-gram appears in the password.
    """
    lower = password.lower()
    for i in range(len(lower) - 3):
        if lower[i : i + 4] in _KEYBOARD_NGRAMS:
            # Confirm with longer match when possible
            for end in range(i + 4, min(i + 12, len(lower) + 1)):
                if lower[i:end] in _KEYBOARD_NGRAMS:
                    return True
            return True
    return False


def _detect_sequence(password: str) -> bool:
    """Detect alphabetic or numeric runs of length 3+.

    Args:
        password: Password to inspect.

    Returns:
        True if a known sequential n-gram appears.
    """
    lower = password.lower()
    return any(lower[i : i + 3] in _SEQUENCE_NGRAMS for i in range(len(lower) - 2))


def _detect_repeats(password: str) -> bool:
    """Detect three or more identical characters in a row (O(n)).

    Args:
        password: Password to inspect.

    Returns:
        True if any character repeats 3+ consecutive times.
    """
    return any(password[i] == password[i + 1] == password[i + 2] for i in range(len(password) - 2))


def _detect_dates(password: str) -> bool:
    """Detect year or date-like patterns (no word-boundary requirement).

    Args:
        password: Password to inspect.

    Returns:
        True if a date-like pattern is present.
    """
    if len(password) > _DATE_MAX_LENGTH:
        return False
    if _YEAR_PATTERN.search(password):
        return True
    return any(pattern.search(password) for pattern in _DATE_PATTERNS)


def _normalize_leet(password: str) -> str:
    """Map common leet-speak substitutions to letters (lowercased)."""
    return password.lower().translate(_LEET_TABLE)


def _is_common_password(password: str) -> bool:
    """Check common-password list with exact, leet, and substring matches.

    Args:
        password: Candidate password.

    Returns:
        True if the password is a common/breached password or embeds one
        as a substring of length >= 5.
    """
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        return True
    normalized = _normalize_leet(password)
    if normalized in COMMON_PASSWORDS:
        return True
    for common in COMMON_PASSWORDS:
        if len(common) < 5:
            continue
        if common in lower or common in normalized:
            return True
    return False


def _pool_size(password: str) -> int:
    """Estimate character-set size from classes present in the password."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    return pool or 26


def _estimate_log10_guesses(password: str) -> float:
    """Estimate log10 of the number of guesses needed to crack the password.

    Works entirely in log space so long inputs cannot overflow.

    Args:
        password: Password to estimate.

    Returns:
        log10(guesses), always >= 0 (i.e. guesses >= 1).

    Examples:
        >>> round(_estimate_log10_guesses("password"), 2)
        2.0
        >>> _estimate_log10_guesses("A" * 256) > 100
        True
    """
    length = len(password)
    if length == 0:
        return 0.0

    pool = _pool_size(password)
    log10_guesses = length * math.log10(pool)

    if _is_common_password(password):
        return min(log10_guesses, _COMMON_PASSWORD_LOG10_GUESSES)

    if _detect_keyboard_pattern(password):
        log10_guesses += _KEYBOARD_LOG10_PENALTY
    if _detect_sequence(password):
        log10_guesses += _SEQUENCE_LOG10_PENALTY
    if _detect_repeats(password):
        log10_guesses += _REPEAT_LOG10_PENALTY
    if _detect_dates(password):
        log10_guesses += _DATE_LOG10_PENALTY

    return max(log10_guesses, 0.0)


# float64 max is ~1.8e308; avoid OverflowError when converting log10 -> linear.
_MAX_FLOAT_LOG10 = 300.0


def _estimate_guesses(password: str) -> float:
    """Estimate guesses as a float (capped to avoid overflow to inf)."""
    log10_guesses = _estimate_log10_guesses(password)
    if log10_guesses > _MAX_FLOAT_LOG10:
        return float("inf")
    return 10.0**log10_guesses


@dataclass(frozen=True)
class StrengthReport:
    """Password strength analysis result.

    Attributes:
        password: Masked placeholder (never the raw password).
        score: 0-4 strength score.
        guesses: Estimated number of guesses (float, may be large).
        entropy: Approximate entropy in bits (log2 of guesses).
        crack_times: Human-readable crack time per scenario.
        crack_times_seconds: Crack time in seconds per scenario.
        feedback: Actionable feedback strings.
        patterns: Detected weak pattern names.
    """

    password: str
    score: int
    guesses: float
    entropy: float
    crack_times: dict[str, str]
    crack_times_seconds: dict[str, float]
    feedback: list[str]
    patterns: list[str]


def _score_from_log10(log10_guesses: float) -> int:
    """Map log10(guesses) to a 0-4 score.

    Thresholds:
        0: < 1e3, 1: < 1e6, 2: < 1e8, 3: < 1e10, 4: otherwise.
    """
    if log10_guesses < 3:
        return 0
    if log10_guesses < 6:
        return 1
    if log10_guesses < 8:
        return 2
    if log10_guesses < 10:
        return 3
    return 4


def _zxcvbn_is_available() -> bool:
    from password_generator.zxcvbn_backend import zxcvbn_available

    return zxcvbn_available()


def _empty_report(message: str) -> StrengthReport:
    return StrengthReport(
        password="",
        score=0,
        guesses=0.0,
        entropy=0.0,
        crack_times={},
        crack_times_seconds={},
        feedback=[message],
        patterns=[],
    )


def _analyze_heuristic(password: str) -> StrengthReport:
    """Built-in heuristic analyzer (zero dependencies, log-space safe)."""
    log10_guesses = _estimate_log10_guesses(password)
    guesses = float("inf") if log10_guesses > _MAX_FLOAT_LOG10 else 10.0**log10_guesses
    entropy = log10_guesses * math.log2(10)

    rates: dict[str, float] = {
        "online_throttled_100_per_hour": 100 / 3600,
        "online_no_throttling_10_per_second": 10.0,
        "offline_slow_hashing_1e4_per_second": 10_000.0,
        "offline_fast_hashing_1e10_per_second": 10_000_000_000.0,
    }

    crack_times_seconds: dict[str, float] = {}
    crack_times: dict[str, str] = {}
    for scenario, rate in rates.items():
        seconds = guesses / rate / 2.0
        crack_times_seconds[scenario] = seconds
        crack_times[scenario] = _format_time(seconds)

    score = 0 if _is_common_password(password) else _score_from_log10(log10_guesses)

    patterns: list[str] = []
    if _is_common_password(password):
        patterns.append("common_password")
    if _detect_keyboard_pattern(password):
        patterns.append("keyboard_pattern")
    if _detect_sequence(password):
        patterns.append("sequence")
    if _detect_repeats(password):
        patterns.append("repetition")
    if _detect_dates(password):
        patterns.append("date")

    feedback: list[str] = []
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
        password="*" * len(password),
        score=score,
        guesses=guesses,
        entropy=entropy,
        crack_times=crack_times,
        crack_times_seconds=crack_times_seconds,
        feedback=feedback,
        patterns=patterns,
    )


def analyze(password: str, *, backend: str = "heuristic") -> StrengthReport:
    """Analyze password strength.

    Args:
        password: The password to analyze. Never stored in the report.
        backend: ``"heuristic"`` (default, zero deps), ``"zxcvbn"`` (requires
            optional extra), or ``"auto"`` (zxcvbn if installed, else heuristic).

    Returns:
        StrengthReport with score, crack times, patterns, and feedback.

    Raises:
        ValueError: If ``backend`` is unknown.
        RuntimeError: If ``backend="zxcvbn"`` and the optional package is missing.

    Examples:
        >>> report = analyze("password")
        >>> report.score
        0
        >>> "common_password" in report.patterns
        True
        >>> report = analyze("")
        >>> report.score
        0
    """
    if backend not in {"heuristic", "zxcvbn", "auto"}:
        raise ValueError(f"Unknown backend {backend!r}; expected 'heuristic', 'zxcvbn', or 'auto'")

    if not password:
        return _empty_report("Password is empty")

    if backend == "zxcvbn" or (backend == "auto" and _zxcvbn_is_available()):
        from password_generator.zxcvbn_backend import analyze_with_zxcvbn

        data = analyze_with_zxcvbn(password)
        return StrengthReport(
            password="*" * len(password),
            score=int(data["score"]),
            guesses=float(data["guesses"]),
            entropy=float(data["entropy"]),
            crack_times=dict(data["crack_times"]),
            crack_times_seconds=dict(data["crack_times_seconds"]),
            feedback=list(data["feedback"]),
            patterns=list(data["patterns"]),
        )

    return _analyze_heuristic(password)


def _format_time(seconds: float) -> str:
    """Format seconds into a human-readable duration string.

    Args:
        seconds: Non-negative duration in seconds (may be extremely large).

    Returns:
        Human-readable string such as ``3 hours`` or ``centuries``.

    Examples:
        >>> _format_time(0.0001)
        'instantly'
        >>> _format_time(45)
        '45 seconds'
        >>> _format_time(120)
        '2 minutes'
    """
    if math.isinf(seconds) or seconds != seconds:  # inf or NaN
        return "centuries"
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
    year = 86400 * 365
    if seconds < year:
        return f"{seconds / 86400:.0f} days"
    if seconds < year * 1000:
        return f"{seconds / year:.0f} years"
    if seconds < year * 1_000_000:
        return f"{seconds / (year * 1000):.0f} thousand years"
    if seconds < year * 1_000_000_000:
        return f"{seconds / (year * 1_000_000):.0f} million years"
    if seconds < year * 1_000_000_000_000:
        return f"{seconds / (year * 1_000_000_000):.0f} billion years"
    return "centuries"
