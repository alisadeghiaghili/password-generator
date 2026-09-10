"""Cross-platform clipboard operations with optional explicit clear."""

from __future__ import annotations

import platform
import subprocess
import threading


def _run_clip(system: str, data: bytes) -> bool:
    """Write bytes to the system clipboard.

    Args:
        system: ``platform.system()`` value.
        data: Raw bytes to place on the clipboard.

    Returns:
        True if the clipboard tool exited successfully.
    """
    try:
        if system == "Windows":
            # `clip` accepts UTF-16LE on modern Windows consoles.
            process = subprocess.Popen(
                ["clip"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif system == "Darwin":
            process = subprocess.Popen(
                ["pbcopy"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif system == "Linux":
            try:
                process = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                process = subprocess.Popen(
                    ["xsel", "--clipboard", "--input"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        else:
            return False
        process.communicate(data)
        return process.returncode == 0
    except FileNotFoundError:
        return False


def copy_to_clipboard(text: str, auto_clear_seconds: int = 0) -> bool:
    """Copy text to the system clipboard.

    Note:
        ``auto_clear_seconds`` uses a daemon thread. In short-lived CLI
        processes the thread is killed at exit and the clear never runs.
        Long-running apps may use this; CLIs should block and call
        :func:`clear_clipboard` explicitly.

    Args:
        text: Text to copy.
        auto_clear_seconds: If > 0, schedule a clear after this many seconds.

    Returns:
        True if the copy succeeded, False otherwise.

    Examples:
        >>> copy_to_clipboard("secret")  # doctest: +SKIP
        True
        >>> copy_to_clipboard("secret", auto_clear_seconds=30)  # doctest: +SKIP
        True
    """
    system = platform.system()
    payload = text.encode("utf-16-le") if system == "Windows" else text.encode("utf-8")

    if not _run_clip(system, payload):
        return False

    if auto_clear_seconds > 0:
        timer = threading.Timer(auto_clear_seconds, clear_clipboard)
        timer.daemon = True
        timer.start()

    return True


def clear_clipboard() -> bool:
    """Clear the clipboard immediately.

    Returns:
        True if the clipboard tool succeeded.

    Examples:
        >>> clear_clipboard()  # doctest: +SKIP
        True
    """
    return _run_clip(platform.system(), b"")
