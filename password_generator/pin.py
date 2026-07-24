"""PIN and numeric code generation."""

import secrets
from dataclasses import dataclass

__all__ = ["generate_pin", "PinConfig"]


@dataclass
class PinConfig:
    """Configuration for PIN generation.

    Attributes:
        length: PIN length in digits (1-12).
        avoid_repeats: Avoid 3+ identical digits in a row.
        avoid_sequential: Avoid ascending/descending sequences.

    Raises:
        ValueError: If length is out of range.

    Examples:
        >>> config = PinConfig(length=6, avoid_repeats=True)
        >>> config = PinConfig(length=8, avoid_sequential=True)
    """

    length: int = 4
    avoid_repeats: bool = False
    avoid_sequential: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.length <= 12:
            raise ValueError("PIN length must be between 1 and 12")


def _is_sequential(digits: list[int]) -> bool:
    """Check if digits form a sequential pattern.

    Args:
        digits: List of digit values.

    Returns:
        True if digits form ascending or descending sequence.

    Examples:
        >>> _is_sequential([1, 2, 3, 4])
        True
        >>> _is_sequential([9, 8, 7, 6])
        True
        >>> _is_sequential([1, 3, 5, 7])
        False
    """
    if len(digits) < 2:
        return False
    # Check ascending: 1234, 5678
    ascending = all(digits[i] == digits[i - 1] + 1 for i in range(1, len(digits)))
    # Check descending: 4321, 8765
    descending = all(digits[i] == digits[i - 1] - 1 for i in range(1, len(digits)))
    return ascending or descending


def _has_repeats(digits: list[int], threshold: int = 3) -> bool:
    """Check if digits have repeated patterns (3+ same in a row).

    Args:
        digits: List of digit values.
        threshold: Minimum consecutive repeats to flag.

    Returns:
        True if any digit repeats threshold+ times consecutively.

    Examples:
        >>> _has_repeats([1, 1, 1, 2])
        True
        >>> _has_repeats([1, 2, 1, 2])
        False
    """
    if len(digits) < threshold:
        return False
    for i in range(len(digits) - threshold + 1):
        if len(set(digits[i : i + threshold])) == 1:
            return True
    return False


def generate_pin(config: PinConfig | None = None, **kwargs) -> str:
    """Generate a random numeric PIN.

    Args:
        config: PinConfig instance, or None to use kwargs.
        **kwargs: Keyword arguments to create PinConfig.

    Returns:
        A numeric PIN string.

    Examples:
        >>> generate_pin()
        >>> generate_pin(length=6, avoid_repeats=True)
        >>> generate_pin(PinConfig(length=8, avoid_sequential=True))
    """
    if config is None:
        config = PinConfig(**kwargs)

    max_attempts = 10000
    for _ in range(max_attempts):
        digits = [secrets.randbelow(10) for _ in range(config.length)]

        if config.avoid_repeats and _has_repeats(digits):
            continue
        if config.avoid_sequential and _is_sequential(digits):
            continue

        return "".join(str(d) for d in digits)

    # Fallback: return without restrictions if we can't find one
    digits = [secrets.randbelow(10) for _ in range(config.length)]
    return "".join(str(d) for d in digits)
