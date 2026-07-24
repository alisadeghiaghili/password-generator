"""Passphrase generation (XKCD-style)."""

import math
import secrets
from dataclasses import dataclass
from pathlib import Path

__all__ = ["generate_passphrase", "PassphraseConfig", "passphrase_entropy"]

_WORDLIST_PATH = Path(__file__).parent / "wordlist.txt"


@dataclass
class PassphraseConfig:
    """Configuration for passphrase generation.

    Attributes:
        words: Number of words (2-10).
        separator: Character(s) between words.
        capitalize: Capitalize first letter of each word.
        wordlist_path: Path to custom wordlist file (min 100 words).

    Raises:
        ValueError: If word count is out of range.

    Examples:
        >>> config = PassphraseConfig(words=5, separator=" ", capitalize=True)
        >>> config = PassphraseConfig(words=3, separator=".", wordlist_path="words.txt")
    """

    words: int = 4
    separator: str = "-"
    capitalize: bool = False
    wordlist_path: str | None = None

    def __post_init__(self) -> None:
        if not 2 <= self.words <= 10:
            raise ValueError("Word count must be between 2 and 10")


def _load_wordlist(path: str | None = None) -> list[str]:
    """Load word list from file.

    Args:
        path: Path to wordlist file, or None for default.

    Returns:
        List of words from the file.

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If word list has fewer than 100 words.
    """
    wordlist_file = Path(path) if path else _WORDLIST_PATH
    if not wordlist_file.exists():
        raise FileNotFoundError(f"Word list not found: {wordlist_file}")
    words = []
    for line in wordlist_file.read_text(encoding="utf-8").splitlines():
        word = line.strip()
        if word and not word.startswith("#"):
            words.append(word)
    if len(words) < 100:
        raise ValueError(f"Word list too small: {len(words)} words (need at least 100)")
    return words


def generate_passphrase(config: PassphraseConfig | None = None, **kwargs) -> str:
    """Generate a memorable XKCD-style passphrase.

    Args:
        config: PassphraseConfig instance, or None to use kwargs.
        **kwargs: Keyword arguments to create PassphraseConfig.

    Returns:
        A passphrase string like "correct-horse-battery-staple".

    Examples:
        >>> generate_passphrase()
        >>> generate_passphrase(words=5, separator=" ", capitalize=True)
        >>> generate_passphrase(PassphraseConfig(words=3, separator="."))
    """
    if config is None:
        config = PassphraseConfig(**kwargs)

    wordlist = _load_wordlist(config.wordlist_path)
    selected = [secrets.choice(wordlist) for _ in range(config.words)]

    if config.capitalize:
        selected = [w.capitalize() for w in selected]

    return config.separator.join(selected)


def passphrase_entropy(word_count: int, wordlist_size: int = 2048) -> int:
    """Calculate the entropy of a passphrase.

    Args:
        word_count: Number of words in the passphrase.
        wordlist_size: Size of the word list (default 2048 for our wordlist).

    Returns:
        Entropy in bits.

    Examples:
        >>> passphrase_entropy(4)
        44
        >>> passphrase_entropy(6)
        66
        >>> passphrase_entropy(4, wordlist_size=10000)
        53
    """
    return round(word_count * math.log2(wordlist_size))
