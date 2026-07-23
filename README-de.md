# Password Generator

[English](README.md) | [فارسی](README-fa.md) | [Deutsch](README-de.md)

Ein sicheres, konfigurierbares Passwort-Generierungs-Toolkit für Python. Erstellen Sie zufällige Passwörter, XKCD-style Passphrasen, numerische PINs und analysieren Sie Passwortstärke — alles über eine einfache API oder ein interaktives CLI.

**Version:** 2.0.0 | **Lizenz:** MIT | **Python:** 3.10+

---

## Funktionen

- **Zufällige Passwörter** — Kryptographisch sicher, vollständig anpassbare Zeichensätze
- **Passphrasen** — XKCD-style einprägsame Passphrasen aus einer 2048-Wörter-Liste
- **PINs** — Numerische Codes mit Wiederholungs-/Sequenzvermeidung
- **Stärkeanalyse** — Entropie-Bewertung, Knackzeit-Schätzungen, Mustererkennung
- **Zwischenablage** — Automatisches Kopieren mit zeitgesteuerter Löschung (plattformübergreifend)
- **Interaktives CLI** — Menügesteuerter Assistent für technische Laien
- **JSON-Ausgabe** — Maschinenlesbare Ausgabe für Skripting und Automatisierung
- **Plattformübergreifend** — Windows, macOS, Linux

---

## Installation

### Über PyPI (empfohlen)

```bash
pip install password-generator
```

### Aus Quellcode

```bash
git clone https://github.com/alisadeghiaghili/password-generator.git
cd password-generator
pip install -e .
```

### Entwicklung

```bash
pip install -e ".[dev]"
pytest
```

---

## Schnellstart

### Als Python-Bibliothek

```python
from password_generator import generate, generate_passphrase, generate_pin, analyze

# Ein zufälliges 20-Zeichen-Passwort generieren
password = generate(length=20)
print(password)  # z.B. "k8#Qx!2mNp@Lw9Rz"

# Eine 5-Wörter-Passphrase generieren
passphrase = generate_passphrase(words=5, separator=" ", capitalize=True)
print(passphrase)  # z.B. "Correct Horse Battery Staple Moon"

# Eine 6-stellige PIN generieren
pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
print(pin)  # z.B. "849205"

# Passwortstärke analysieren
report = analyze("P@ssw0rd123")
print(f"Bewertung: {report.score}/4")
print(f"Entropie: {report.entropy:.0f} Bits")
print(f"Knackzeit (offline): {report.crack_times['offline_fast_hashing_1e10_per_second']}")
```

### Als CLI-Werkzeug

```bash
# Interaktiver Modus
python cli.py

# 5 Passwörter mit Länge 20 generieren
python cli.py --length 20 --count 5

# Passphrase generieren
python cli.py --passphrase --words 4 --separator " "

# 6-stellige PIN generieren
python cli.py --pin --pin-length 6 --avoid-repeats

# Passwort analysieren
python cli.py --analyze "MyP@ssw0rd"

# JSON-Ausgabe
python cli.py --length 24 --json

# In Zwischenablage kopieren
python cli.py --length 16 --clipboard
```

---

## API-Referenz

### `generate(config=None, **kwargs) -> str`

Generiert ein kryptographisch sicheres zufälliges Passwort.

| Parameter | Typ | Standard | Beschreibung |
|---|---|---|---|
| `length` | `int` | `16` | Passwortlänge (4–256) |
| `uppercase` | `bool` | `True` | Großbuchstaben einschließen (A–Z) |
| `lowercase` | `bool` | `True` | Kleinbuchstaben einschließen (a–z) |
| `digits` | `bool` | `True` | Ziffern einschließen (0–9) |
| `symbols` | `bool` | `True` | Symbole einschließen |
| `symbol_chars` | `str` | `!@#$%^&*()_+-=[]{}|;:,.<>?` | Benutzerdefinierte Symbolzeichen |
| `exclude_ambiguous` | `bool` | `False` | Mehrdeutige Zeichen ausschließen: `l`, `I`, `1`, `O`, `0`, `o` |

```python
from password_generator import generate, GeneratorConfig

# Mit kwargs
pwd = generate(length=24, uppercase=True, digits=True, symbols=False)

# Mit Konfigurationsobjekt
config = GeneratorConfig(length=32, exclude_ambiguous=True)
pwd = generate(config)
```

### `generate_passphrase(config=None, **kwargs) -> str`

Generiert eine einprägsame XKCD-style Passphrase.

| Parameter | Typ | Standard | Beschreibung |
|---|---|---|---|
| `words` | `int` | `4` | Anzahl der Wörter (2–10) |
| `separator` | `str` | `-` | Wort-Trennzeichen |
| `capitalize` | `bool` | `False` | Ersten Buchstaben jedes Wortes großschreiben |
| `wordlist_path` | `str \| None` | `None` | Pfad zur benutzerdefinierten Wortliste (min. 100 Wörter) |

```python
from password_generator import generate_passphrase, PassphraseConfig

# Standard: 4 Wörter, mit Bindestrich getrennt
phrase = generate_passphrase()
# z.B. "correct-horse-battery-staple"

# Benutzerdefiniert: 6 Wörter, mit Leerzeichen getrennt, großgeschrieben
phrase = generate_passphrase(words=6, separator=" ", capitalize=True)
# z.B. "Correct Horse Battery Staple Moon River"

# Benutzerdefinierte Wortliste
config = PassphraseConfig(words=4, wordlist_path="/path/to/wordlist.txt")
phrase = generate_passphrase(config)
```

### `generate_pin(config=None, **kwargs) -> str`

Generiert eine zufällige numerische PIN.

| Parameter | Typ | Standard | Beschreibung |
|---|---|---|---|
| `length` | `int` | `4` | PIN-Länge (1–12) |
| `avoid_repeats` | `bool` | `False` | 3+ identische Ziffern hintereinander vermeiden |
| `avoid_sequential` | `bool` | `False` | Auf-/absteigende Sequenzen vermeiden |

```python
from password_generator import generate_pin, PinConfig

# Basis 4-stellige PIN
pin = generate_pin()

# 6-stellig, keine Wiederholungen, keine Sequenzen
pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)

# Mit Konfiguration
config = PinConfig(length=8, avoid_sequential=True)
pin = generate_pin(config)
```

### `analyze(password: str) -> StrengthReport`

Analysiert die Passwortstärke mit detailliertem Feedback.

```python
from password_generator import analyze

report = analyze("MyP@ssw0rd123!")

# Bewertung (0–4): 0=Sehr schwach, 1=Schwach, 2=Fair, 3=Stark, 4=Sehr stark
print(report.score)

# Entropie in Bits
print(report.entropy)

# Geschätzte Anzahl der Versuche zum Knacken
print(report.guesses)

# Lesbare Knackzeit-Schätzungen
print(report.crack_times)

# Aktionbares Feedback
print(report.feedback)

# Erkannte Muster
print(report.patterns)
```

**Erkannte Muster:** `common_password`, `keyboard_pattern`, `sequence`, `repetition`, `date`

### `copy_to_clipboard(text, auto_clear_seconds=0) -> bool`

Kopiert Text in die Zwischenablage mit optionaler automatischer Löschung.

```python
from password_generator import copy_to_clipboard, clear_clipboard

# In Zwischenablage kopieren
copy_to_clipboard("mein_sicheres_passwort")

# Mit 30-Sekunden-Autolöschung kopieren
copy_to_clipboard("mein_sicheres_passwort", auto_clear_seconds=30)

# Zwischenablage manuell löschen
clear_clipboard()
```

### `calculate_entropy(pool_size, length) -> int`

Berechnet die Passwort-Entropie in Bits.

```python
from password_generator.generator import calculate_entropy

# 8 Kleinbuchstaben: 26^8 Möglichkeiten
entropy = calculate_entropy(26, 8)  # ~37 Bits
```

### `passphrase_entropy(word_count, wordlist_size=2048) -> int`

Berechnet die Passphrase-Entropie in Bits.

```python
from password_generator.passphrase import passphrase_entropy

# 4 Wörter aus einer 2048-Wörter-Liste
entropy = passphrase_entropy(4)  # ~44 Bits

# 6 Wörter
entropy = passphrase_entropy(6)  # ~66 Bits
```

---

## CLI-Referenz

### Interaktiver Modus

Ohne Argumente ausführen, um den interaktiven Assistenten zu starten:

```bash
python cli.py
```

Der Assistent führt Sie durch:
1. Auswahl des Generationstyps (Passwort / Passphrase / PIN / Analyse)
2. Konfiguration der Optionen
3. Anzeige der Ergebnisse mit Stärkeanalyse
4. Optionales Kopieren in die Zwischenablage

### Kommandozeilen-Argumente

| Argument | Beschreibung | Standard |
|---|---|---|
| `--length N` | Passwortlänge (4–256) | `16` |
| `--count N` | Anzahl zu generierender Passwörter | `1` |
| `--uppercase` / `--no-uppercase` | Großbuchstaben ein-/ausschließen | `True` |
| `--lowercase` / `--no-lowercase` | Kleinbuchstaben ein-/ausschließen | `True` |
| `--digits` / `--no-digits` | Ziffern ein-/ausschließen | `True` |
| `--no-symbols` | Symbole ausschließen | `False` |
| `--exclude-ambiguous` | Mehrdeutige Zeichen ausschließen | `False` |
| `--passphrase` | Passphrase-Generierungsmodus | — |
| `--words N` | Wortanzahl für Passphrase (2–10) | `4` |
| `--separator CHAR` | Wort-Trennzeichen | `-` |
| `--capitalize` | Passphrasewörter großschreiben | `False` |
| `--pin` | PIN-Generierungsmodus | — |
| `--pin-length N` | PIN-Länge (1–12) | `4` |
| `--avoid-repeats` | Wiederholte Ziffern in PIN vermeiden | `False` |
| `--avoid-sequential` | Sequenzielle Ziffern in PIN vermeiden | `False` |
| `--analyze PASSWORD` | Ein Passwort analysieren | — |
| `--json` | Als JSON ausgeben | `False` |
| `--clipboard` | Ergebnis in Zwischenablage kopieren | `False` |
| `--clipboard-clear N` | Sekunden bis zur Autolöschung der Zwischenablage | `30` |

### Beispiele

```bash
# 10 nur-Großbuchstaben-Passwörter, je 12 Zeichen
python cli.py --length 12 --count 10 --no-lowercase --no-digits --no-symbols

# Passphrase mit Leerzeichen-Trennzeichen, großgeschrieben
python cli.py --passphrase --words 5 --separator " " --capitalize

# 8-stellige PIN, Wiederholungen und Sequenzen vermeiden
python cli.py --pin --pin-length 8 --avoid-repeats --avoid-sequential

# Analysieren und als JSON ausgeben
python cli.py --analyze "Tr0ub4dor&3" --json

# Generieren und in Zwischenablage kopieren
python cli.py --length 24 --clipboard --clipboard-clear 60
```

---

## Anwendungsfälle

### 1. Passwortspeicherung in Anwendungen

Einzigartige Passwörter für jedes Konto generieren:

```python
from password_generator import generate

accounts = ["email", "bank", "social", "cloud"]
for account in accounts:
    pwd = generate(length=20, symbols=True)
    print(f"{account}: {pwd}")
```

### 2. Sichere Passphrasen für Verschlüsselungsschlüssel

Passphrasen für einprägsame aber starke Schlüssel verwenden:

```python
from password_generator import generate_passphrase

# Festplattenverschlüsselung-Passphrase
phrase = generate_passphrase(words=6, capitalize=True, separator=" ")
print(f"Verschlüsselungsschlüssel: {phrase}")
# z.B. "Correct Horse Battery Staple Moon River"
```

### 3. PIN-Generierung für Zwei-Faktor-Authentifizierung

Sichere PINs für 2FA-Apps generieren:

```python
from password_generator import generate_pin

# 6-stellige TOTP-Backup-Codes
for i in range(5):
    pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
    print(f"Backup-Code {i+1}: {pin}")
```

### 4. Stapel-Passwortgenerierung für DevOps

Mehrere Passwörter für die Infrastruktur generieren:

```python
from password_generator import generate, generate_pin
import json

# Datenbank-Zugangsdaten generieren
db_password = generate(length=32, exclude_ambiguous=True)
api_key = generate(length=48, uppercase=True, lowercase=True, digits=True, symbols=False)
admin_pin = generate_pin(length=8, avoid_sequential=True)

config = {
    "database_password": db_password,
    "api_key": api_key,
    "admin_pin": admin_pin
}
print(json.dumps(config, indent=2))
```

### 5. Passwort-Stärke-Audit

Bestehende Passwörter in Ihrer Anwendung prüfen:

```python
from password_generator import analyze

user_passwords = ["password123", "Tr0ub4dor&3", "k8#Qx!2mNp@Lw9Rz"]

for pwd in user_passwords:
    report = analyze(pwd)
    status = "OK" if report.score >= 3 else "SCHWACH"
    print(f"[{status}] Bewertung={report.score} Entropie={report.entropy:.0f}b Feedback={report.feedback}")
```

### 6. Integration mit Passwort-Managern

Generierte Passwörter als JSON für den Import exportieren:

```python
from password_generator import generate, generate_passphrase
import json

entries = []
for service in ["github", "gitlab", "npm", "pypi"]:
    entries.append({
        "service": service,
        "username": f"user_{service}",
        "password": generate(length=20),
    })

with open("passwords_export.json", "w") as f:
    json.dump(entries, f, indent=2)
```

### 7. Automatisiertes Testen mit JSON-Ausgabe

JSON-Ausgabe in CI/CD-Pipelines verwenden:

```bash
# Test-Zugangsdaten als JSON generieren
python cli.py --length 16 --json | jq '.passwords[0]'
```

### 8. Zwischenablage-Autolöschung für Sicherheit

Passwörter mit automatischer Bereinigung kopieren:

```python
from password_generator import generate, copy_to_clipboard

pwd = generate(length=24)
copy_to_clipboard(pwd, auto_clear_seconds=30)
print("Passwort kopiert — Zwischenablage wird in 30 Sekunden gelöscht")
```

---

## Sicherheitsdetails

- Verwendet Pythons `secrets`-Modul für kryptographisch sichere Zufallsgenerierung
- Fisher-Yates-Shuffle gewährleistet gleichmäßige Verteilung
- PIN-Generierung versucht bis zu 10.000 Male, um Einschränkungen einzuhalten
- Stärkeanalyse prüft gegen eine Datenbank von 157 häufigen/geleckten Passwörtern
- Erkennt Tastaturmuster, Sequenzen, Wiederholungen und Datumsformate
- Zwischenablage-Autolöschung verhindert Passwortoffenlegung nach Gebrauch
- Passwörter werden in `StrengthReport`-Ausgabe maskiert (nie offengelegt)

---

## Projektstruktur

```
password-generator/
├── password_generator/          # Kern-Python-Paket
│   ├── __init__.py              # Öffentliche API-Exports
│   ├── generator.py             # Zufällige Passwortgenerierung
│   ├── passphrase.py            # XKCD-style Passphrasengenerierung
│   ├── pin.py                   # Numerische PIN-Generierung
│   ├── strength.py              # Passwort-Stärkeanalysator
│   ├── clipboard.py             # Plattformübergreifende Zwischenablagen-Operationen
│   ├── wordlist.txt             # 2048-Wörter-Liste für Passphrasen
│   └── common_passwords.txt     # 157 häufige/geleckte Passwörter
├── tests/
│   └── test_all.py              # Umfassende TestSuite
├── cli.py                       # Interaktives CLI & argparse
├── PasswordGenerator.py         # Einstiegspunkt-Wrapper
├── pyproject.toml               # Build-Konfiguration
└── README.md                    # Diese Datei
```

---

## Tests ausführen

```bash
# Entwicklungsabhängigkeiten installieren
pip install -e ".[dev]"

# Alle Tests ausführen
pytest

# Mit ausführlicher Ausgabe ausführen
pytest -v

# Bestimmte Testklasse ausführen
pytest tests/test_all.py::TestGenerate -v
```

---

## Anforderungen

- Python 3.10 oder höher
- Keine externen Abhängigkeiten (verwendet nur stdlib: `secrets`, `string`, `math`, `re`, `dataclasses`, `subprocess`)
- Linux-Zwischenablage erfordert `xclip` oder `xsel`

---

## Beiträge

1. Repository forken
2. Feature-Branch erstellen (`git checkout -b feature/tolles-feature`)
3. Änderungen committen (`git commit -m 'Tolles Feature hinzufügen'`)
4. zum Branch pushen (`git push origin feature/tolles-feature`)
5. Pull Request öffnen

---

## Lizenz

MIT-Lizenz — siehe [LICENSE](LICENSE) für Details.

---

## Autor

**Ali Sadeghi Aghili** - [alisadeghiaghili@gmail.com](mailto:alisadeghiaghili@gmail.com)

Repository: [github.com/alisadeghiaghili/password-generator](https://github.com/alisadeghiaghili/password-generator)
