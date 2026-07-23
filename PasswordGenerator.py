#!/usr/bin/env python3
"""
Password Generator - Interactive CLI wrapper.

This is a thin wrapper around the password_generator package.
For the full API, see: from password_generator import generate, generate_passphrase, generate_pin, analyze
"""

import sys
import os

# Add parent directory to path so we can import the package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == "__main__":
    main()
