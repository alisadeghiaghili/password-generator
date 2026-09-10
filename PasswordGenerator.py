"""Backward-compatible wrapper. Prefer ``password-gen`` after install."""

from password_generator.cli import main

if __name__ == "__main__":
    main()
