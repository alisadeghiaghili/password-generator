# 🔐 Password Generator

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A secure, user-friendly Python script that generates strong, random passwords with an interactive command-line interface.

## ✨ Features

- 🛡️ **Secure Password Generation** - Creates cryptographically strong 16-character passwords
- 🎯 **Guaranteed Complexity** - Each password contains at least one character from each category:
  - Lowercase letters (a-z)
  - Uppercase letters (A-Z)
  - Digits (0-9)
  - Special symbols (!@#$%^&*()_+-=[]{}|;:,.<>?)
- 🖥️ **Interactive CLI** - Easy-to-use command-line interface
- 📝 **Flexible Generation** - Single password or batch generation options
- ⚙️ **Customizable** - Adjustable password length and count

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/alisadeghiaghili/password-generator.git
cd password-generator

# Install dependencies
pip install -r requirements.txt

# Run the generator
python PasswordGenerator.py
```

## 📋 Requirements

- **Python 3.x**
- **Dependencies:**
  ```
  altgraph==0.17.4
  packaging==25.0
  pefile==2023.2.7
  pyinstaller==6.15.0
  pyinstaller-hooks-contrib==2025.8
  pywin32-ctypes==0.2.3
  setuptools==80.9.0
  ```

## 🔧 Installation

### Option 1: Using requirements.txt
```bash
pip install -r requirements.txt
```

### Option 2: Manual installation
```bash
pip install altgraph==0.17.4 packaging==25.0 pefile==2023.2.7 pyinstaller==6.15.0 pyinstaller-hooks-contrib==2025.8 pywin32-ctypes==0.2.3 setuptools==80.9.0
```

## 💻 Usage

### Interactive Mode

Run the script to access the interactive menu:

```bash
python PasswordGenerator.py
```

**Menu Options:**
1. Generate a single password
2. Generate 5 passwords
3. Generate custom number of passwords
4. Exit

### Example Output

```
=== 16-Character Password Generator ===

Options:
1. Generate a single password
2. Generate 5 passwords
3. Generate custom number of passwords
4. Exit

Enter your choice (1-4): 2

Generated 5 secure 16-character passwords:

1. K7@mP9xR#4nW8qL2
2. B3$vH6yT&1sF5jC9
3. X2%gM8kN!7pD4rE6
4. Q5^bV9wA*3lS7hU1
5. Z8#cJ4mR&6tK2nP5
```

### Programmatic Usage

You can also import and use the functions directly:

```python
from PasswordGenerator import generate_password, generate_multiple_passwords

# Generate a single password
password = generate_password()
print(f"Your password: {password}")

# Generate multiple passwords
generate_multiple_passwords(3)

# Generate custom length password
long_password = generate_password(24)
print(f"24-char password: {long_password}")
```

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **Character Diversity** | Guarantees at least one character from each category |
| **Randomization** | Uses Python's random module with shuffling |
| **No Patterns** | Eliminates predictable password structures |
| **Customizable Length** | Adjustable password length (default: 16 chars) |

### Character Sets

| Category | Characters | Count |
|----------|------------|-------|
| Lowercase | `abcdefghijklmnopqrstuvwxyz` | 26 |
| Uppercase | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | 26 |
| Digits | `0123456789` | 10 |
| Symbols | `!@#$%^&*()_+-=[]{}|;:,.<>?` | 23 |
| **Total** | | **85** |

## 📦 Building Executable

This project includes PyInstaller for creating standalone executables:

```bash
# Create a standalone executable
pyinstaller --onefile PasswordGenerator.py

# The executable will be in the dist/ folder
```

## ⚙️ Configuration

### Custom Character Sets

Modify the character sets in the `generate_password()` function:

```python
# Simplified symbols for better compatibility
symbols = "!@#$%^&*()"

# Extended symbols
symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?~`"
```

### Default Password Length

Change the default length:

```python
def generate_password(length=20):  # Changed from 16 to 20
```

## 🛡️ Best Practices

- ✅ Use generated passwords immediately
- ✅ Store passwords in a secure password manager
- ✅ Generate unique passwords for each account
- ✅ Update passwords regularly
- ✅ Never share passwords through unsecured channels

## 📁 Project Structure

```
password-generator/
├── PasswordGenerator.py    # Main script
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── dist/                  # Built executables (after PyInstaller)
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Note

This generator uses Python's `random` module, which is suitable for most use cases but may not be cryptographically secure for highly sensitive applications. For maximum security, consider using the `secrets` module instead of `random`.

## 👨‍💻 Author

**Ali Sadeghi Aghili**  
[![GitHub](https://img.shields.io/badge/GitHub-alisadeghiaghili-181717?logo=github)](https://github.com/alisadeghiaghili)

---

⭐ **Star this repository if you find it helpful!**