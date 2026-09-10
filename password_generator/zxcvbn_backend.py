"""Optional zxcvbn backend for password strength analysis.

When the ``zxcvbn`` package is installed (``password-generator[zxcvbn]``),
:func:`analyze` can use Dropbox's zxcvbn model for guess estimation.
The built-in heuristic remains the default and always works with zero deps.
"""

from __future__ import annotations

import math
from typing import Any

try:  # pragma: no cover - exercised only when zxcvbn is installed
    from zxcvbn import zxcvbn as _zxcvbn

    ZXCVBN_AVAILABLE = True
except ImportError:  # pragma: no cover
    _zxcvbn = None
    ZXCVBN_AVAILABLE = False

# zxcvbn score is already 0-4; map to our report fields.
_SCORE_LABELS = {
    0: "very weak",
    1: "weak",
    2: "fair",
    3: "strong",
    4: "very strong",
}


def zxcvbn_available() -> bool:
    """Return True when the optional zxcvbn package is importable.

    Returns:
        True if zxcvbn can be used as an analysis backend.

    Examples:
        >>> from password_generator.zxcvbn_backend import zxcvbn_available
        >>> isinstance(zxcvbn_available(), bool)
        True
    """
    return ZXCVBN_AVAILABLE


def analyze_with_zxcvbn(password: str) -> dict[str, Any]:
    """Analyze a password with the zxcvbn library.

    Args:
        password: Password to analyze (never stored in the result).

    Returns:
        Dict with keys:
            - ``score``: int 0-4
            - ``guesses``: float estimated guesses
            - ``entropy``: float bits (log2 of guesses)
            - ``crack_times``: mapping scenario -> human-readable string
            - ``crack_times_seconds``: mapping scenario -> float seconds
            - ``feedback``: list of feedback strings
            - ``patterns``: list of pattern names from zxcvbn sequence

    Raises:
        RuntimeError: If zxcvbn is not installed.
        ValueError: If password is empty.

    Examples:
        >>> # doctest requires optional dependency
        >>> result = analyze_with_zxcvbn("password") if zxcvbn_available() else {"score": 0}
        >>> result["score"]
        0
    """
    if not ZXCVBN_AVAILABLE or _zxcvbn is None:
        raise RuntimeError(
            "zxcvbn is not installed. Install with: pip install password-generator[zxcvbn]"
        )
    if not password:
        raise ValueError("password must be non-empty")

    raw = _zxcvbn(password)
    guesses = float(raw["guesses"])
    entropy = math.log2(guesses) if guesses > 0 else 0.0

    crack_times = dict(raw["crack_times_display"])
    crack_times_seconds = {key: float(value) for key, value in raw["crack_times_seconds"].items()}

    feedback_items: list[str] = []
    fb = raw.get("feedback") or {}
    warning = fb.get("warning")
    if warning:
        feedback_items.append(str(warning))
    for suggestion in fb.get("suggestions") or []:
        feedback_items.append(str(suggestion))

    patterns: list[str] = []
    for match in raw.get("sequence") or []:
        pattern = match.get("pattern")
        if pattern and pattern not in patterns:
            patterns.append(str(pattern))

    score = int(raw.get("score", 0))
    if score >= 3 and not feedback_items:
        feedback_items.append("Good password!")

    return {
        "score": score,
        "guesses": guesses,
        "entropy": entropy,
        "crack_times": crack_times,
        "crack_times_seconds": crack_times_seconds,
        "feedback": feedback_items,
        "patterns": patterns,
        "backend": "zxcvbn",
    }
