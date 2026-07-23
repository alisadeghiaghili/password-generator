# Contributing to Password Generator

Thank you for your interest in contributing! This guide will help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [License Agreement](#license-agreement)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)

---

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for everyone

---

## License Agreement

By contributing to this project, you agree that your contributions will be licensed under the **Apache License 2.0**.

**Your contributions must:**

1. Include the Apache 2.0 license header in new source files
2. Not remove or alter existing copyright notices
3. Include a clear description of changes in your PR

**Example file header:**

```python
# Copyright 2024-2026 Ali Sadeghi Aghili
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
```

---

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/alisadeghiaghili/password-generator/issues) first
2. Open a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the use case and expected behavior
3. Wait for maintainer approval before implementing

### Submitting Code

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Git
- pip

### Installation

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/password-generator.git
cd password-generator

# Install in development mode
pip install -e ".[dev,cli]"

# Verify installation
pytest
```

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -e ".[dev,cli]"
```

---

## Project Structure

```
password-generator/
├── password_generator/          # Core Python package
│   ├── __init__.py              # Public API exports
│   ├── generator.py             # Random password generation
│   ├── passphrase.py            # XKCD-style passphrase generation
│   ├── pin.py                   # Numeric PIN generation
│   ├── strength.py              # Password strength analyzer
│   ├── clipboard.py             # Cross-platform clipboard ops
│   ├── wordlist.txt             # 2048-word list for passphrases
│   └── common_passwords.txt     # 157 common/breached passwords
├── tests/
│   └── test_all.py              # Test suite
├── cli.py                       # CLI interface
├── PasswordGenerator.py         # Entry point wrapper
├── pyproject.toml               # Build configuration
├── README.md                    # English documentation
├── README-fa.md                 # Persian documentation
├── README-de.md                 # German documentation
├── LICENSE                      # Apache 2.0 license
└── CONTRIBUTING.md              # This file
```

---

## Development Workflow

### 1. Create a Branch

```bash
# From main branch
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/your-feature-name
```

**Branch naming conventions:**

| Prefix | Purpose |
|---|---|
| `feature/` | New functionality |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `test/` | Adding or updating tests |
| `refactor/` | Code restructuring |

### 2. Make Changes

- Follow [coding standards](#coding-standards)
- Add tests for new functionality
- Update documentation if needed

### 3. Test Your Changes

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific tests
pytest tests/test_all.py::TestGenerate -v

# Check coverage
pytest --cov=password_generator
```

### 4. Commit Your Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add custom wordlist support to passphrase generator"
```

**Commit message format:**

```
<type>: <short description>

<optional body>

<optional footer>
```

**Types:**

| Type | Description |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `test` | Adding tests |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `style` | Formatting, no code change |
| `chore` | Maintenance tasks |

---

## Coding Standards

### Python Style

- Follow PEP 8
- Use type hints for all public functions
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Example

```python
def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Generate a secure random password.

    Args:
        length: Password length (4-256).
        uppercase: Include uppercase letters.
        lowercase: Include lowercase letters.
        digits: Include digits.
        symbols: Include symbols.

    Returns:
        A random password string.
    """
    # Implementation here
    pass
```

### Docstrings

- Use Google-style docstrings
- Document all public functions
- Include examples in docstrings

### Comments

- Write comments explaining **why**, not **what**
- Keep comments up-to-date
- Remove commented-out code

---

## Testing

### Writing Tests

- Add tests for all new functionality
- Test edge cases and error conditions
- Use descriptive test names

### Test Structure

```python
class TestFeature:
    def test_default_behavior(self):
        """Test that default settings work correctly."""
        result = function()
        assert result == expected

    def test_custom_settings(self):
        """Test that custom settings are applied."""
        result = function(custom_param=True)
        assert result == expected

    def test_invalid_input(self):
        """Test that invalid input raises error."""
        with pytest.raises(ValueError):
            function(invalid_param=-1)
```

### Running Tests

```bash
# All tests
pytest

# Specific module
pytest tests/test_all.py::TestGenerate

# With coverage
pytest --cov=password_generator --cov-report=term-missing
```

---

## Submitting a Pull Request

### Before Submitting

- [ ] Tests pass locally
- [ ] Code follows project style
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] Branch is up-to-date with main

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring
- [ ] Other (describe)

## Testing

Describe tests added/modified.

## Checklist

- [ ] Code follows project style
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. Maintainer will review within 1-2 weeks
2. Address any feedback
3. Once approved, your PR will be merged

---

## Reporting Bugs

### Bug Report Template

```markdown
## Description

Clear description of the bug.

## Steps to Reproduce

1. Step one
2. Step two
3. Step three

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens.

## Environment

- Python version:
- OS:
- Package version:
```

---

## Requesting Features

### Feature Request Template

```markdown
## Description

Clear description of the feature.

## Use Case

Why is this feature needed?

## Proposed Solution

How should it work?

## Alternatives Considered

Other approaches you've thought about.
```

---

## Questions?

Open an issue with the `question` label or start a [discussion](https://github.com/alisadeghiaghili/password-generator/discussions).

---

Thank you for contributing!
