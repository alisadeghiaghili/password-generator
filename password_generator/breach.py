"""HaveIBeenPwned integration for checking breached passwords."""

import hashlib
import urllib.request
from dataclasses import dataclass

__all__ = ["check_breach", "BreachResult"]


@dataclass
class BreachResult:
    """Result of a breach check.

    Attributes:
        is_breached: Whether the password was found in a breach.
        count: Number of times the password appeared in breaches.
        message: Human-readable message about the result.
    """

    is_breached: bool
    count: int
    message: str


def _sha1_hash(password: str) -> str:
    """Generate SHA-1 hash of password.

    Args:
        password: Password to hash.

    Returns:
        Uppercase hex SHA-1 hash.

    Examples:
        >>> _sha1_hash("password")
        '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_breach(password: str) -> BreachResult:
    """Check if password has been breached using HaveIBeenPwned API.

    Uses k-anonymity model: only sends first 5 chars of SHA-1 hash,
    never the full hash or password.

    Args:
        password: Password to check.

    Returns:
        BreachResult with breach status and count.

    Examples:
        >>> result = check_breach("password")
        >>> print(result.is_breached)
        True
        >>> print(result.count)  # Number of times found in breaches

        >>> result = check_breach("Xy9#mK2p!qR4")
        >>> print(result.is_breached)
        False
    """
    try:
        sha1 = _sha1_hash(password)
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        request = urllib.request.Request(url, headers={"User-Agent": "password-generator"})
        response = urllib.request.urlopen(request, timeout=5)
        data = response.read().decode("utf-8")

        for line in data.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix.strip() == suffix:
                return BreachResult(
                    is_breached=True,
                    count=int(count),
                    message=f"Password found {int(count):,} times in data breaches",
                )

        return BreachResult(
            is_breached=False,
            count=0,
            message="Password not found in known breaches",
        )
    except Exception:
        return BreachResult(
            is_breached=False,
            count=0,
            message="Unable to check breach database",
        )
