from pathlib import Path

REPLACEMENTS = [
    ("v2.0.0", "v2.1.1"),
    ("2048-word list", "~1060-word bundled list"),
    ("2048-Wörter-Liste", "~1060-Wörter-Liste"),
    ("لیست 2048 کلمه‌ای", "لیست ~1060 کلمه‌ای"),
    (
        'python cli.py --analyze "MyP@ssw0rd123!"',
        "echo -n 'MyP@ssw0rd123!' | python cli.py --analyze",
    ),
    (
        'python cli.py --analyze "MyP@ssw0rd"',
        "echo -n 'MyP@ssw0rd' | python cli.py --analyze",
    ),
    (
        'python cli.py --analyze "Tr0ub4dor&3" --json',
        "echo -n 'Tr0ub4dor&3' | python cli.py --analyze --json",
    ),
    ("--analyze PASSWORD", "--analyze (stdin/prompt)"),
    ("--analyze PWD", "--analyze (stdin/prompt)"),
    ("~44 bits (default)", "~40 bits (bundled list)"),
    ("~44 Bits (Standard)", "~40 Bits (mitgelieferte Liste)"),
    ("~44 بیت (پیش‌فرض)", "~40 بیت (لیست بسته‌بندی‌شده)"),
    ("<td>~44 bits</td>", "<td>~40 bits</td>"),
    ("<td>~44 Bits</td>", "<td>~40 Bits</td>"),
    ("<td>~44 بیت</td>", "<td>~40 بیت</td>"),
    ("4 words (~44 bits)", "4 words (~40 bits)"),
    ("6+ words (~66 bits)", "6+ words (~60 bits)"),
    ("4 Wörter (~44 Bits)", "4 Wörter (~40 Bits)"),
    ("6+ Wörter (~66 Bits)", "6+ Wörter (~60 Bits)"),
    ("4 کلمه (~44 بیت)", "4 کلمه (~40 بیت)"),
    ("6+ کلمه (~66 بیت)", "6+ کلمه (~60 بیت)"),
    ("# ~44 bits", "# ~40 bits"),
    ("# ~44 Bits", "# ~40 Bits"),
    ("# ~44 بیت", "# ~40 بیت"),
    (
        "entropy = passphrase_entropy(word_count=4)  # ~44 bits",
        "entropy = passphrase_entropy(word_count=4)  # ~40 bits",
    ),
    (
        "entropy = passphrase_entropy(word_count=4)  # ~44 Bits",
        "entropy = passphrase_entropy(word_count=4)  # ~40 Bits",
    ),
]


def main() -> None:
    root = Path(__file__).resolve().parent.parent / "docs"
    changed = []
    for path in sorted(root.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        orig = text
        for old, new in REPLACEMENTS:
            text = text.replace(old, new)
        if text != orig:
            path.write_text(text, encoding="utf-8", newline="\n")
            changed.append(path)
    print(f"updated {len(changed)} files")
    for path in changed:
        print(" ", path.relative_to(root.parent))
    print("--- leftovers ---")
    for path in sorted(root.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for needle in ("2048", "~44", "v2.0.0", '--analyze "'):
            if needle in text:
                print(path, needle)


if __name__ == "__main__":
    main()
