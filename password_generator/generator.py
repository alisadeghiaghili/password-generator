"""Core password generation logic."""

import math
import secrets
import string
from dataclasses import dataclass, field


AMBIGUOUS_CHARS = set("lI1O0o")


@dataclass
class GeneratorConfig:
    """Configuration for password generation."""

    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    symbol_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    exclude_ambiguous: bool = False

    def __post_init__(self):
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
        """Build character pools based on config."""
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
    """Calculate password entropy in bits."""
    if pool_size <= 0 or length <= 0:
        return 0
    return round(length * math.log2(pool_size))
