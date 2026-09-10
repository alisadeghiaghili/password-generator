"""PIN and numeric code generation."""

from __future__ import annotations

from dataclasses import dataclass
from secrets import randbelow as _secure_randbelow

_MIN_LENGTH: int = 1
_MAX_LENGTH: int = 12
_DEFAULT_SEQUENCE_RUN: int = 4
_MAX_ATTEMPTS: int = 10_000


@dataclass
class PinConfig:
    """Configuration for PIN generation.

    Attributes:
        length: Number of digits (1-12).
        avoid_repeats: Reject PINs with 3+ identical digits in a row.
        avoid_sequential: Reject PINs containing an ascending or
            descending run of ``sequence_run`` digits (default 4).
        sequence_run: Length of sequential run to reject when
            ``avoid_sequential`` is True.
    """

    length: int = 4
    avoid_repeats: bool = False
    avoid_sequential: bool = False
    sequence_run: int = _DEFAULT_SEQUENCE_RUN

    def __post_init__(self) -> None:
        if not _MIN_LENGTH <= self.length <= _MAX_LENGTH:
            raise ValueError(
                f"PIN length must be between {_MIN_LENGTH} and {_MAX_LENGTH}, got {self.length}"
            )
        if self.sequence_run < 2:
            raise ValueError("sequence_run must be at least 2")


def _has_repeats(digits: list[int], threshold: int = 3) -> bool:
    """Return True if ``threshold`` identical digits appear in a row.

    Args:
        digits: Digit sequence.
        threshold: Minimum consecutive identical digits to treat as a repeat.

    Returns:
        True when a repeat run of length ``threshold`` exists.

    Examples:
        >>> _has_repeats([1, 1, 1, 2])
        True
        >>> _has_repeats([1, 1, 2, 2])
        False
    """
    if len(digits) < threshold:
        return False
    return any(len(set(digits[i : i + threshold])) == 1 for i in range(len(digits) - threshold + 1))


def _has_sequential_run(digits: list[int], min_len: int = 4) -> bool:
    """Return True if any window of ``min_len`` digits is strictly sequential.

    Sequential means constant +1 (ascending) or -1 (descending) steps.
    Embedded runs count: ``91234567`` contains the ascending run ``1234567``.

    Args:
        digits: Digit sequence.
        min_len: Minimum window length to consider.

    Returns:
        True when a sequential run of at least ``min_len`` digits exists.

    Examples:
        >>> _has_sequential_run([1, 2, 3, 4])
        True
        >>> _has_sequential_run([9, 1, 2, 3, 4, 5, 6, 7], min_len=4)
        True
        >>> _has_sequential_run([1, 2, 4, 8], min_len=4)
        False
    """
    n = len(digits)
    if n < min_len:
        return False
    for i in range(n - min_len + 1):
        window = digits[i : i + min_len]
        ascending = all(window[j] == window[j - 1] + 1 for j in range(1, min_len))
        if ascending:
            return True
        descending = all(window[j] == window[j - 1] - 1 for j in range(1, min_len))
        if descending:
            return True
    return False


def generate_pin(config: PinConfig | None = None, **kwargs: object) -> str:
    """Generate a random numeric PIN.

    Args:
        config: PinConfig instance. If None, built from ``kwargs``.
        **kwargs: Keyword arguments forwarded to ``PinConfig``.

    Returns:
        A numeric PIN string.

    Raises:
        ValueError: If the configuration is invalid.
        RuntimeError: If constraints cannot be satisfied within the attempt
            budget (does not silently return a PIN that violates the request).

    Examples:
        >>> pin = generate_pin()
        >>> len(pin) == 4 and pin.isdigit()
        True
        >>> pin = generate_pin(length=6, avoid_repeats=True)
        >>> pin.isdigit()
        True
    """
    if config is None:
        config = PinConfig(**kwargs)  # type: ignore[arg-type]

    for _ in range(_MAX_ATTEMPTS):
        digits = [_secure_randbelow(10) for _ in range(config.length)]

        if config.avoid_repeats and _has_repeats(digits):
            continue
        if config.avoid_sequential and _has_sequential_run(digits, config.sequence_run):
            continue

        return "".join(str(d) for d in digits)

    raise RuntimeError(
        f"Could not generate a PIN satisfying constraints within {_MAX_ATTEMPTS} attempts "
        f"(length={config.length}, avoid_repeats={config.avoid_repeats}, "
        f"avoid_sequential={config.avoid_sequential})"
    )
