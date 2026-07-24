"""Cross-platform clipboard operations with auto-clear."""

import platform
import subprocess
import threading

__all__ = ["copy_to_clipboard", "clear_clipboard"]


def copy_to_clipboard(text: str, auto_clear_seconds: int = 0) -> bool:
    """Copy text to clipboard.

    Args:
        text: Text to copy.
        auto_clear_seconds: If > 0, clear clipboard after this many seconds.

    Returns:
        True if successful, False otherwise.

    Examples:
        >>> copy_to_clipboard("my_password")
        >>> copy_to_clipboard("my_password", auto_clear_seconds=30)
    """
    system: str = platform.system()
    try:
        if system == "Windows":
            process: subprocess.Popen[bytes] = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            process.communicate(text.encode("utf-16-le"))
        elif system == "Darwin":
            process = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            process.communicate(text.encode("utf-8"))
        elif system == "Linux":
            try:
                process = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                )
                process.communicate(text.encode("utf-8"))
            except FileNotFoundError:
                process = subprocess.Popen(
                    ["xsel", "--clipboard", "--input"],
                    stdin=subprocess.PIPE,
                )
                process.communicate(text.encode("utf-8"))
        else:
            return False

        if auto_clear_seconds > 0:
            timer: threading.Timer = threading.Timer(
                auto_clear_seconds, _clear_clipboard_thread, args=(system,)
            )
            timer.daemon = True
            timer.start()

        return True
    except FileNotFoundError:
        return False


def clear_clipboard() -> bool:
    """Clear the clipboard immediately.

    Returns:
        True if successful, False otherwise.

    Examples:
        >>> clear_clipboard()
        True
    """
    return _clear_clipboard_thread(platform.system())


def _clear_clipboard_thread(system: str) -> bool:
    """Clear clipboard (used by timer thread).

    Args:
        system: Operating system name from platform.system().

    Returns:
        True if successful, False otherwise.
    """
    try:
        if system == "Windows":
            process = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            process.communicate(b"")
        elif system == "Darwin":
            process = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            process.communicate(b"")
        elif system == "Linux":
            try:
                process = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                )
                process.communicate(b"")
            except FileNotFoundError:
                process = subprocess.Popen(
                    ["xsel", "--clipboard", "--input"],
                    stdin=subprocess.PIPE,
                )
                process.communicate(b"")
        else:
            return False
        return True
    except FileNotFoundError:
        return False
