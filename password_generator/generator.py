"""Core password generation logic."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

AMBIGUOUS_CHARS: frozenset[str] = frozenset("lI1O0o")

_MIN_LENGTH: int = 4
_MAX_LENGTH: int = 256


@dataclass
class GeneratorConfig:
    """Configuration for password generation.

    Attributes:
        length: Password length (4-256).
        uppercase: Include A-Z.
        lowercase: Include a-z.
        digits: Include 0-9.
        symbols: Include symbol characters.
        symbol_chars: Characters used when ``symbols`` is True.
        exclude_ambiguous: Remove ``l I 1 O 0 o`` from all pools.
    """

    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    symbol_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    exclude_ambiguous: bool = False

    def __post_init__(self) -> None:
        if not _MIN_LENGTH <= self.length <= _MAX_LENGTH:
            raise ValueError(
                f"Length must be between {_MIN_LENGTH} and {_MAX_LENGTH}, got {self.length}"
            )
        pools = self.get_pools()
        if not any(pools.values()):
            raise ValueError(
                "At least one non-empty character category must be enabled "
                "(after applying exclude_ambiguous)"
            )
        if self.length < len(pools):
            raise ValueError(
                f"Length ({self.length}) is too short for {len(pools)} enabled categories. "
                f"Minimum: {len(pools)}"
            )

    def get_pools(self) -> dict[str, list[str]]:
        """Build character pools based on config.

        Returns:
            Mapping of category name to list of allowed characters.
            Categories may be present with empty lists when filters remove all chars;
            callers must treat empty pools as disabled.

        Examples:
            >>> config = GeneratorConfig(uppercase=True, lowercase=False, digits=False, symbols=False)
            >>> sorted(config.get_pools().keys())
            ['uppercase']
        """
        pools: dict[str, list[str]] = {}
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

    def non_empty_pools(self) -> dict[str, list[str]]:
        """Return only pools that still have characters after filtering."""
        return {k: v for k, v in self.get_pools().items() if v}


def generate(config: GeneratorConfig | None = None, **kwargs: object) -> str:
    """Generate a cryptographically secure random password.

    Args:
        config: GeneratorConfig instance. If None, built from ``kwargs``.
        **kwargs: Keyword arguments forwarded to ``GeneratorConfig`` when
            ``config`` is None.

    Returns:
        A random password string of ``config.length`` characters.

    Raises:
        ValueError: If the configuration is invalid or all pools are empty.

    Examples:
        >>> pwd = generate(length=20)
        >>> len(pwd)
        20
        >>> pwd = generate(uppercase=True, digits=False, symbols=False, lowercase=True)
        >>> any(c.islower() for c in pwd)
        True
        >>> pwd = generate(GeneratorConfig(length=16, exclude_ambiguous=True))
        >>> not any(c in "lI1O0o" for c in pwd)
        True
    """
    if config is None:
        config = GeneratorConfig(**kwargs)  # type: ignore[arg-type]

    pools = config.non_empty_pools()
    pool_names = list(pools.keys())

    password: list[str] = [secrets.choice(pools[name]) for name in pool_names]

    combined: list[str] = []
    for chars in pools.values():
        combined.extend(chars)

    for _ in range(config.length - len(password)):
        password.append(secrets.choice(combined))

    # Fisher-Yates with CSPRNG
    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]

    return "".join(password)


def calculate_entropy(pool_size: int, length: int) -> int:
    """Calculate password entropy in bits for a uniform charset.

    Args:
        pool_size: Number of distinct characters available.
        length: Password length.

    Returns:
        Entropy in bits, rounded to the nearest integer. Zero if either
        argument is non-positive.

    Examples:
        >>> calculate_entropy(26, 8)
        37
        >>> calculate_entropy(0, 10)
        0
    """
    if pool_size <= 0 or length <= 0:
        return 0
    return round(length * math.log2(pool_size))
