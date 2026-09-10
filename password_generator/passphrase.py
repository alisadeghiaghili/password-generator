"""Passphrase generation (XKCD-style)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from secrets import choice as _secure_choice

_WORDLIST_PATH = Path(__file__).parent / "wordlist.txt"

_MIN_WORDS: int = 2
_MAX_WORDS: int = 10
_MIN_WORDLIST_SIZE: int = 100


@dataclass
class PassphraseConfig:
    """Configuration for passphrase generation.

    Attributes:
        words: Number of words (2-10).
        separator: String inserted between words.
        capitalize: Capitalize the first letter of each word.
        wordlist_path: Optional custom wordlist path (min 100 words).
    """

    words: int = 4
    separator: str = "-"
    capitalize: bool = False
    wordlist_path: str | None = None

    def __post_init__(self) -> None:
        if not _MIN_WORDS <= self.words <= _MAX_WORDS:
            raise ValueError(
                f"Word count must be between {_MIN_WORDS} and {_MAX_WORDS}, got {self.words}"
            )


def _load_wordlist(path: str | None = None) -> list[str]:
    """Load a word list from a text file.

    Args:
        path: File path. If None, uses the bundled wordlist.

    Returns:
        List of words (non-empty, non-comment lines).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If fewer than 100 words are present.
    """
    wordlist_file = Path(path) if path else _WORDLIST_PATH
    if not wordlist_file.exists():
        raise FileNotFoundError(f"Word list not found: {wordlist_file}")
    words: list[str] = []
    for line in wordlist_file.read_text(encoding="utf-8").splitlines():
        word = line.strip()
        if word and not word.startswith("#"):
            words.append(word)
    if len(words) < _MIN_WORDLIST_SIZE:
        raise ValueError(
            f"Word list too small: {len(words)} words (need at least {_MIN_WORDLIST_SIZE})"
        )
    return words


def generate_passphrase(
    config: PassphraseConfig | None = None, **kwargs: object
) -> str:
    """Generate a memorable XKCD-style passphrase.

    Args:
        config: PassphraseConfig instance. If None, built from ``kwargs``.
        **kwargs: Keyword arguments forwarded to ``PassphraseConfig``.

    Returns:
        A passphrase such as ``correct-horse-battery-staple``.

    Raises:
        ValueError: If word count is out of range.
        FileNotFoundError: If a custom wordlist path is missing.

    Examples:
        >>> phrase = generate_passphrase()
        >>> len(phrase.split("-"))
        4
        >>> phrase = generate_passphrase(words=5, separator=" ", capitalize=True)
        >>> len(phrase.split(" "))
        5
    """
    if config is None:
        config = PassphraseConfig(**kwargs)  # type: ignore[arg-type]

    wordlist = _load_wordlist(config.wordlist_path)
    selected = [_secure_choice(wordlist) for _ in range(config.words)]

    if config.capitalize:
        selected = [w.capitalize() for w in selected]

    return config.separator.join(selected)


def passphrase_entropy(
    word_count: int, wordlist_size: int | None = None
) -> int:
    """Calculate passphrase entropy in bits.

    Args:
        word_count: Number of words in the passphrase.
        wordlist_size: Size of the word list. If None, uses the bundled
            wordlist size (not a hardcoded theoretical value).

    Returns:
        Entropy in bits: ``round(word_count * log2(wordlist_size))``.

    Examples:
        >>> from password_generator.passphrase import _load_wordlist
        >>> expected = round(4 * math.log2(len(_load_wordlist())))
        >>> passphrase_entropy(4) == expected
        True
        >>> passphrase_entropy(2, 1024)
        20
    """
    if word_count <= 0:
        return 0
    if wordlist_size is None:
        wordlist_size = len(_load_wordlist())
    if wordlist_size <= 1:
        return 0
    return round(word_count * math.log2(wordlist_size))
