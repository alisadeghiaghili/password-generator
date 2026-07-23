# Password Generator

[English](README.md) | [فارسی](README-fa.md) | [Deutsch](README-de.md)

ابزار جامع و قابل تنظیم برای تولید رمز عبور در پایتون. رمزهای عبور تصادفی، عبارات عبور XKCD، کدهای PIN عددی و تحلیل قوت رمز عبور — همه از یک API ساده یا CLI تعاملی.

**نسخه:** 2.0.0 | **لایسنس:** Apache 2.0 | **پایتون:** 3.10+

---

## قابلیت‌ها

- **رمزهای عبور تصادفی** — تولید رمزنگارانه ایمن با مجموعه کاراکترهای کاملاً قابل تنظیم
- **عبارات عبور** — عبارات عبور به یادماندنی XKCD از لیست 2048 کلمه‌ای
- **کدهای PIN** — کدهای عددی با جلوگیری از تکرار و توالی
- **تحلیل قوت** — امتیازدهی آنتروپی، برآورد زمان شکستن، تشخیص الگو
- **ادغام کلیپ‌بورد** — کپی خودکار با پاکسازی زمان‌بندی‌شده (چندپلتفرمی)
- **CLI تعاملی** — راهنمای منویی برای کاربران غیرفنی
- **خروجی JSON** — خروجی خوانا توسط ماشین برای اسکریپت‌نویسی و اتوماسیون
- **چندپلتفرمی** — ویندوز، macOS، لینوکس

---

## نصب

### از PyPI (توصیه‌شده)

```bash
pip install password-generator
```

### از سورس

```bash
git clone https://github.com/alisadeghiaghili/password-generator.git
cd password-generator
pip install -e .
```

### توسعه

```bash
pip install -e ".[dev]"
pytest
```

---

## شروع سریع

### به عنوان کتابخانه پایتون

```python
from password_generator import generate, generate_passphrase, generate_pin, analyze

# تولید رمز عبور تصادفی 20 کاراکتری
password = generate(length=20)
print(password)  # مثلاً: "k8#Qx!2mNp@Lw9Rz"

# تولید عبارت عبور 5 کلمه‌ای
passphrase = generate_passphrase(words=5, separator=" ", capitalize=True)
print(passphrase)  # مثلاً: "Correct Horse Battery Staple Moon"

# تولید کد PIN 6 رقمی
pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
print(pin)  # مثلاً: "849205"

# تحلیل قوت رمز عبور
report = analyze("P@ssw0rd123")
print(f"امتیاز: {report.score}/4")
print(f"آنتروپی: {report.entropy:.0f} بیت")
print(f"زمان شکستن (آفلاین): {report.crack_times['offline_fast_hashing_1e10_per_second']}")
```

### به عنوان ابزار خط فرمان

```bash
# حالت تعاملی
python cli.py

# تولید 5 رمز عبور با طول 20
python cli.py --length 20 --count 5

# تولید عبارت عبور
python cli.py --passphrase --words 4 --separator " "

# تولید کد PIN 6 رقمی
python cli.py --pin --pin-length 6 --avoid-repeats

# تحلیل رمز عبور
python cli.py --analyze "MyP@ssw0rd"

# خروجی JSON
python cli.py --length 24 --json

# کپی در کلیپ‌بورد
python cli.py --length 16 --clipboard
```

---

## مرجع API

### `generate(config=None, **kwargs) -> str`

تولید رمز عبور تصادفی رمزنگارانه ایمن.

| پارامتر | نوع | پیش‌فرض | توضیح |
|---|---|---|---|
| `length` | `int` | `16` | طول رمز عبور (4–256) |
| `uppercase` | `bool` | `True` | شامل حروف بزرگ (A–Z) |
| `lowercase` | `bool` | `True` | شامل حروف کوچک (a–z) |
| `digits` | `bool` | `True` | شامل اعداد (0–9) |
| `symbols` | `bool` | `True` | شامل نمادها |
| `symbol_chars` | `str` | `!@#$%^&*()_+-=[]{}|;:,.<>?` | کاراکترهای نماد سفارشی |
| `exclude_ambiguous` | `bool` | `False` | حذف کاراکترهای مبهم: `l`، `I`، `1`، `O`، `0`، `o` |

```python
from password_generator import generate, GeneratorConfig

# با استفاده از kwargs
pwd = generate(length=24, uppercase=True, digits=True, symbols=False)

# با استفاده از شیء تنظیمات
config = GeneratorConfig(length=32, exclude_ambiguous=True)
pwd = generate(config)
```

### `generate_passphrase(config=None, **kwargs) -> str`

تولید عبارت عبور به یادماندنی به سبک XKCD.

| پارامتر | نوع | پیش‌فرض | توضیح |
|---|---|---|---|
| `words` | `int` | `4` | تعداد کلمات (2–10) |
| `separator` | `str` | `-` | کاراکتر جداکننده |
| `capitalize` | `bool` | `False` | بزرگ نوشتن حرف اول هر کلمه |
| `wordlist_path` | `str \| None` | `None` | مسیر فایل لیست کلمات سفارشی (حداقل 100 کلمه) |

```python
from password_generator import generate_passphrase, PassphraseConfig

# پیش‌فرض: 4 کلمه، جداشده با خط تیره
phrase = generate_passphrase()
# مثلاً: "correct-horse-battery-staple"

# سفارشی: 6 کلمه، جداشده با فاصله، با حرف بزرگ
phrase = generate_passphrase(words=6, separator=" ", capitalize=True)
# مثلاً: "Correct Horse Battery Staple Moon River"

# لیست کلمات سفارشی
config = PassphraseConfig(words=4, wordlist_path="/path/to/wordlist.txt")
phrase = generate_passphrase(config)
```

### `generate_pin(config=None, **kwargs) -> str`

تولید کد PIN عددی تصادفی.

| پارامتر | نوع | پیش‌فرض | توضیح |
|---|---|---|---|
| `length` | `int` | `4` | طول PIN (1–12) |
| `avoid_repeats` | `bool` | `False` | جلوگیری از 3+ رقم تکراری پشت سر هم |
| `avoid_sequential` | `bool` | `False` | جلوگیری از توالی صعودی/نزولی |

```python
from password_generator import generate_pin, PinConfig

# کد PIN 4 رقمی پایه
pin = generate_pin()

# 6 رقمی، بدون تکرار، بدون توالی
pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)

# با استفاده از تنظیمات
config = PinConfig(length=8, avoid_sequential=True)
pin = generate_pin(config)
```

### `analyze(password: str) -> StrengthReport`

تحلیل قوت رمز عبور با بازخورد دقیق.

```python
from password_generator import analyze

report = analyze("MyP@ssw0rd123!")

# امتیاز (0–4): 0=خیلی ضعیف، 1=ضعیف، 2=متوسط، 3=قوی، 4=خیلی قوی
print(report.score)

# آنتروپی بر حسب بیت
print(report.entropy)

# تعداد تخمینی حدس‌ها برای شکستن
print(report.guesses)

# برآورد زمان شکستن به صورت خوانا
print(report.crack_times)

# بازخورد عملی
print(report.feedback)

# الگوهای تشخیص‌داده‌شده
print(report.patterns)
```

**الگوهای تشخیص‌داده‌شده:** `common_password`، `keyboard_pattern`، `sequence`، `repetition`، `date`

### `copy_to_clipboard(text, auto_clear_seconds=0) -> bool`

کپی متن در کلیپ‌بورد با پاکسازی خودکار اختیاری.

```python
from password_generator import copy_to_clipboard, clear_clipboard

# کپی در کلیپ‌بورد
copy_to_clipboard("رمز_عبور_امن_من")

# کپی با پاکسازی خودکار 30 ثانیه‌ای
copy_to_clipboard("رمز_عبور_امن_من", auto_clear_seconds=30)

# پاکسازی دستی کلیپ‌بورد
clear_clipboard()
```

### `calculate_entropy(pool_size, length) -> int`

محاسبه آنتروپی رمز عبور بر حسب بیت.

```python
from password_generator.generator import calculate_entropy

# 8 حرف کوچک: 26^8 احتمالات
entropy = calculate_entropy(26, 8)  # ~37 بیت
```

### `passphrase_entropy(word_count, wordlist_size=2048) -> int`

محاسبه آنتروپی عبارت عبور بر حسب بیت.

```python
from password_generator.passphrase import passphrase_entropy

# 4 کلمه از لیست 2048 کلمه‌ای
entropy = passphrase_entropy(4)  # ~44 بیت

# 6 کلمه
entropy = passphrase_entropy(6)  # ~66 بیت
```

---

## مرجع CLI

### حالت تعاملی

بدون آرگومان اجرا کنید تا راهنمای تعاملی شروع شود:

```bash
python cli.py
```

راهنما شما را از مراحل زیر راهنمایی می‌کند:
1. انتخاب نوع تولید (رمز عبور / عبارت عبور / PIN / تحلیل)
2. پیکربندی گزینه‌ها
3. مشاهده نتایج با تحلیل قوت
4. کپی اختیاری در کلیپ‌بورد

### آرگومان‌های خط فرمان

| آرگومان | توضیح | پیش‌فرض |
|---|---|---|
| `--length N` | طول رمز عبور (4–256) | `16` |
| `--count N` | تعداد رمزهای عبور تولیدشده | `1` |
| `--uppercase` / `--no-uppercase` | شامل/حذف حروف بزرگ | `True` |
| `--lowercase` / `--no-lowercase` | شامل/حذف حروف کوچک | `True` |
| `--digits` / `--no-digits` | شامل/حذف اعداد | `True` |
| `--no-symbols` | حذف نمادها | `False` |
| `--exclude-ambiguous` | حذف کاراکترهای مبهم | `False` |
| `--passphrase` | حالت تولید عبارت عبور | — |
| `--words N` | تعداد کلمات عبارت عبور (2–10) | `4` |
| `--separator CHAR` | جداکننده کلمات | `-` |
| `--capitalize` | بزرگ نوشتن کلمات عبارت عبور | `False` |
| `--pin` | حالت تولید PIN | — |
| `--pin-length N` | طول PIN (1–12) | `4` |
| `--avoid-repeats` | جلوگیری از ارقام تکراری در PIN | `False` |
| `--avoid-sequential` | جلوگیری از ارقام توالی‌دار در PIN | `False` |
| `--analyze PASSWORD` | تحلیل یک رمز عبور | — |
| `--json` | خروجی به صورت JSON | `False` |
| `--clipboard` | کپی نتیجه در کلیپ‌بورد | `False` |
| `--clipboard-clear N` | ثانیه‌های پاکسازی خودکار کلیپ‌بورد | `30` |

### مثال‌ها

```bash
# تولید 10 رمز عبور فقط با حروف بزرگ، طول 12
python cli.py --length 12 --count 10 --no-lowercase --no-digits --no-symbols

# عبارت عبور با جداکننده فاصله و حرف بزرگ
python cli.py --passphrase --words 5 --separator " " --capitalize

# PIN 8 رقمی، جلوگیری از تکرار و توالی
python cli.py --pin --pin-length 8 --avoid-repeats --avoid-sequential

# تحلیل و خروجی JSON
python cli.py --analyze "Tr0ub4dor&3" --json

# تولید و کپی در کلیپ‌بورد
python cli.py --length 24 --clipboard --clipboard-clear 60
```

---

## موارد استفاده

### 1. ذخیره رمز عبور در برنامه‌ها

تولید رمزهای عبور منحصربفرد برای هر حساب کاربری:

```python
from password_generator import generate

accounts = ["ایمیل", "بانک", "شبکه_اجتماعی", "کلاود"]
for account in accounts:
    pwd = generate(length=20, symbols=True)
    print(f"{account}: {pwd}")
```

### 2. عبارات عبور امن برای کلیدهای رمزنگاری

استفاده از عبارات عبور برای کلیدهای به یادماندنی اما قوی:

```python
from password_generator import generate_passphrase

# عبارت عبور رمزنگاری دیسک
phrase = generate_passphrase(words=6, capitalize=True, separator=" ")
print(f"کلید رمزنگاری: {phrase}")
# مثلاً: "Correct Horse Battery Staple Moon River"
```

### 3. تولید PIN برای احراز هویت دوعاملی

تولید کدهای PIN امن برای برنامه‌های 2FA:

```python
from password_generator import generate_pin

# کدهای پشتیبان TOTP 6 رقمی
for i in range(5):
    pin = generate_pin(length=6, avoid_repeats=True, avoid_sequential=True)
    print(f"کد پشتیبان {i+1}: {pin}")
```

### 4. تولید دسته‌ای رمز عبور برای DevOps

تولید چندین رمز عبور برای زیرساخت:

```python
from password_generator import generate, generate_pin
import json

# تولید اطلاعات ورود دیتابیس
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

### 5. ممیزی قوت رمز عبور

ممیزی رمزهای عبور موجود در برنامه شما:

```python
from password_generator import analyze

user_passwords = ["password123", "Tr0ub4dor&3", "k8#Qx!2mNp@Lw9Rz"]

for pwd in user_passwords:
    report = analyze(pwd)
    status = "OK" if report.score >= 3 else "ضعیف"
    print(f"[{status}] امتیاز={report.score} آنتروپی={report.entropy:.0f}ب بازخورد={report.feedback}")
```

### 6. ادغام با مدیران رمز عبور

خروجی رمزهای تولیدشده به صورت JSON برای وارد کردن:

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

### 7. تست خودکار با خروجی JSON

استفاده از خروجی JSON در خطوط لوله CI/CD:

```bash
# تولید اطلاعات ورود تست به صورت JSON
python cli.py --length 16 --json | jq '.passwords[0]'
```

### 8. پاکسازی خودکار کلیپ‌بورد برای امنیت

کپی رمزهای عبور با پاکسازی خودکار:

```python
from password_generator import generate, copy_to_clipboard

pwd = generate(length=24)
copy_to_clipboard(pwd, auto_clear_seconds=30)
print("رمز عبور کپی شد — کلیپ‌بورد در 30 ثانیه پاک می‌شود")
```

---

## جزئیات امنیتی

- از ماژول `secrets` پایتون برای تولید تصادفی رمزنگارانه ایمن استفاده می‌کند
- شافل Fisher-Yates توزیع یکنواخت را تضمین می‌کند
- تولید PIN تا 10,000 بار تلاش می‌کند تا محدودیت‌ها را رعایت کند
- تحلیلگر قوت علیه پایگاه داده 157 رمز عبور رایج/نشت‌شده بررسی می‌کند
- الگوهای صفحه کلید، توالی‌ها، تکرارها و الگوهای تاریخی را تشخیص می‌دهد
- پاکسازی خودکار کلیپ‌بورد از افشای رمز عبور پس از استفاده جلوگیری می‌کند
- رمزهای عبور در خروجی `StrengthReport` پنهان می‌شوند (هرگز فاش نمی‌شوند)

---

## ساختار پروژه

```
password-generator/
├── password_generator/          # بسته اصلی پایتون
│   ├── __init__.py              # خروجی API عمومی
│   ├── generator.py             # تولید رمز عبور تصادفی
│   ├── passphrase.py            # تولید عبارت عبور XKCD
│   ├── pin.py                   # تولید کد PIN عددی
│   ├── strength.py              # تحلیلگر قوت رمز عبور
│   ├── clipboard.py             # عملیات کلیپ‌بورد چندپلتفرمی
│   ├── wordlist.txt             # لیست 2048 کلمه‌ای برای عبارات عبور
│   └── common_passwords.txt     # 157 رمز عبور رایج/نشت‌شده
├── tests/
│   └── test_all.py              # مجموعه تست جامع
├── cli.py                       # CLI تعاملی و argparse
├── PasswordGenerator.py         # نقطه ورود wrapper
├── pyproject.toml               # پیکربندی ساخت
└── README.md                    # این فایل
```

---

## اجرای تست‌ها

```bash
# نصب وابستگی‌های توسعه
pip install -e ".[dev]"

# اجرای تمام تست‌ها
pytest

# اجرا با خروجی مفصل
pytest -v

# اجرای یک کلاس تست خاص
pytest tests/test_all.py::TestGenerate -v
```

---

## پیش‌نیازها

- پایتون 3.10 یا بالاتر
- بدون وابستگی‌های خارجی (فقط از stdlib استفاده می‌کند: `secrets`، `string`، `math`، `re`، `dataclasses`، `subprocess`)
- کلیپ‌بورد لینوکس نیاز به `xclip` یا `xsel` دارد

---

## مشارکت

1. مخزن را فورک کنید
2. شاخه ویژگی بسازید (`git checkout -b feature/ویژگی_شگفت‌انگیز`)
3. تغییرات خود را کامیت کنید (`git commit -m 'افزودن ویژگی شگفت‌انگیز'`)
4. به شاخه پوش کنید (`git push origin feature/ویژگی_شگفت‌انگیز`)
5. Pull Request باز کنید

---

## لایسنس

لایسنس Apache 2.0 - جزئیات در [LICENSE](LICENSE).

Copyright 2024-2026 علی صادقی آقیلی. شما مجاز به استفاده از این اثر نیستید مگر در مطابقت با لایسنس.

---

## نویسنده

**علی صادقی آقیلی** - [alisadeghiaghili@gmail.com](mailto:alisadeghiaghili@gmail.com)

مخزن: [github.com/alisadeghiaghili/password-generator](https://github.com/alisadeghiaghili/password-generator)
