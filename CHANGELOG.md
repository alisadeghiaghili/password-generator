# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-23

### Added
- Rich CLI with beautiful terminal output (colored panels, strength bars, tables)
- PIN generation with repeat/sequence avoidance
- Clipboard integration with auto-clear
- Trilingual documentation (English, German, Persian)
- JSON output for scripting and automation
- Comprehensive test suite
- Interactive mode with guided prompts

### Changed
- Complete API redesign with dataclass configs (GeneratorConfig, PassphraseConfig, PinConfig)
- Improved strength analyzer with pattern detection
- Better documentation structure with 10+ pages per language
- Zero dependencies for core library

### Security
- Uses Python's `secrets` module for cryptographically secure generation
- Fisher-Yates shuffle for uniform distribution
- Passwords masked in StrengthReport output

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Basic password generation with character set control
- Passphrase generation (XKCD-style) from 2048-word list
- Password strength analysis with entropy scoring
- Cross-platform clipboard support
