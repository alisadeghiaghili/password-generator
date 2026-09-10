#!/usr/bin/env python3
"""Backward-compatible entry point for ``python cli.py``.

Prefer the installed command ``password-gen`` or
``python -m password_generator.cli``.
"""

from password_generator.cli import main

if __name__ == "__main__":
    main()
