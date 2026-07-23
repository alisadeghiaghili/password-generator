"""PIN and numeric code generation."""

import secrets
from dataclasses import dataclass


@dataclass
class PinConfig:
    """Configuration for PIN generation."""

    length: int = 4
    avoid_repeats: bool = False
    avoid_sequential: bool = False

    def __post_init__(self):
        if not 1 <= self.length <= 12:
            raise ValueError("PIN length must be between 1 and 12")


def _is_sequential(digits: list[int]) -> bool:
    """Check if digits form a sequential pattern."""
    if len(digits) < 2:
        return False
    # Check ascending: 1234, 5678
    ascending = all(digits[i] == digits[i - 1] + 1 for i in range(1, len(digits)))
    # Check descending: 4321, 8765
    descending = all(digits[i] == digits[i - 1] - 1 for i in range(1, len(digits)))
    return ascending or descending


def _has_repeats(digits: list[int], threshold: int = 3) -> bool:
    """Check if digits have repeated patterns (3+ same in a row)."""
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
