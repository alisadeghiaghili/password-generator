"""Core password generation logic."""

import math
import secrets
import string
from dataclasses import dataclass

__all__ = ["generate", "GeneratorConfig", "calculate_entropy", "AMBIGUOUS_CHARS"]


AMBIGUOUS_CHARS = set("lI1O0o")


@dataclass
class GeneratorConfig:
    """Configuration for password generation.

    Attributes:
        length: Password length in characters (4-256).
        uppercase: Include uppercase letters (A-Z).
        lowercase: Include lowercase letters (a-z).
        digits: Include digits (0-9).
        symbols: Include special symbols.
        symbol_chars: Custom symbol characters to use.
        exclude_ambiguous: Exclude ambiguous chars (l, I, 1, O, 0, o).

    Raises:
        ValueError: If length is out of range or no categories enabled.

    Examples:
        >>> config = GeneratorConfig(length=20, uppercase=True, symbols=False)
        >>> config = GeneratorConfig(length=32, exclude_ambiguous=True)
    """

    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    symbol_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    exclude_ambiguous: bool = False

    def __post_init__(self) -> None:
        if not 4 <= self.length <= 256:
            raise ValueError("Length must be between 4 and 256")
        pools = self._get_pools()
        if not pools:
            raise ValueError("At least one character category must be enabled")
        if self.length < len(pools):
            raise ValueError(
                f"Length ({self.length}) is too short for {len(pools)} enabled categories. "
                f"Minimum: {len(pools)}"
            )

    def _get_pools(self) -> dict[str, list[str]]:
        """Build character pools based on config.

        Returns:
            Dictionary mapping pool name to list of allowed characters.
        """
        pools = {}
        if self.lowercase:
            pools["lowercase"] = list(string.ascii_lowercase)
        if self.uppercase:
            pools["uppercase"] = list(string.ascii_uppercase)
        if self.digits:
            pools["digits"] = list(string.digits)
        if self.symbols:
            pools["symbols"] = list(self.symbol_chars)

        if self.exclude_ambiguous:
            for key in pools:
                pools[key] = [c for c in pools[key] if c not in AMBIGUOUS_CHARS]

        return pools


def generate(config: GeneratorConfig | None = None, **kwargs) -> str:
    """Generate a secure random password.

    Args:
        config: GeneratorConfig instance, or None to use kwargs.
        **kwargs: Keyword arguments to create GeneratorConfig.

    Returns:
        A random password string.

    Examples:
        >>> generate(length=20)
        >>> generate(uppercase=True, digits=False, symbols=False)
        >>> generate(GeneratorConfig(length=16, exclude_ambiguous=True))
    """
    if config is None:
        config = GeneratorConfig(**kwargs)

    pools = config._get_pools()
    pool_names = list(pools.keys())

    # Seed with one character from each enabled pool
    password = [secrets.choice(pools[name]) for name in pool_names]

    # Build combined pool for remaining characters
    combined = []
    for chars in pools.values():
        combined.extend(chars)

    # Fill the rest
    for _ in range(config.length - len(password)):
        password.append(secrets.choice(combined))

    # Fisher-Yates shuffle with secrets
    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]

    return "".join(password)


def calculate_entropy(pool_size: int, length: int) -> int:
    """Calculate password entropy in bits.

    Args:
        pool_size: Number of unique characters in the pool.
        length: Password length.

    Returns:
        Entropy in bits (rounded to nearest integer).

    Examples:
        >>> calculate_entropy(26, 8)  # 8 lowercase letters
        37
        >>> calculate_entropy(62, 12)  # 12 alphanumeric chars
        71
        >>> calculate_entropy(0, 10)
        0
    """
    if pool_size <= 0 or length <= 0:
        return 0
    return round(length * math.log2(pool_size))
