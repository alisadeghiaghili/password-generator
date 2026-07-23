"""Tests for password_generator package."""

import pytest
from password_generator import generate, generate_passphrase, generate_pin, analyze
from password_generator.generator import GeneratorConfig, calculate_entropy
from password_generator.passphrase import PassphraseConfig, passphrase_entropy
from password_generator.pin import PinConfig
from password_generator.strength import StrengthReport


# ===== Generator Tests =====

class TestGenerate:
    def test_default_length(self):
        pwd = generate()
        assert len(pwd) == 16

    def test_custom_length(self):
        pwd = generate(length=20)
        assert len(pwd) == 20

    def test_min_length(self):
        pwd = generate(length=4)
        assert len(pwd) == 4

    def test_max_length(self):
        pwd = generate(length=256)
        assert len(pwd) == 256

    def test_contains_uppercase(self):
        pwd = generate(uppercase=True, lowercase=False, digits=False, symbols=False)
        assert any(c.isupper() for c in pwd)

    def test_contains_lowercase(self):
        pwd = generate(uppercase=False, lowercase=True, digits=False, symbols=False)
        assert any(c.islower() for c in pwd)

    def test_contains_digits(self):
        pwd = generate(uppercase=False, lowercase=False, digits=True, symbols=False)
        assert any(c.isdigit() for c in pwd)

    def test_contains_symbols(self):
        pwd = generate(uppercase=False, lowercase=False, digits=False, symbols=True)
        assert any(not c.isalnum() for c in pwd)

    def test_exclude_ambiguous(self):
        ambiguous = set("lI1O0o")
        for _ in range(100):
            pwd = generate(length=20, exclude_ambiguous=True)
            assert not any(c in ambiguous for c in pwd)

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError):
            generate(length=3)
        with pytest.raises(ValueError):
            generate(length=257)

    def test_no_categories_raises(self):
        with pytest.raises(ValueError):
            generate(uppercase=False, lowercase=False, digits=False, symbols=False)

    def test_too_short_for_categories(self):
        with pytest.raises(ValueError):
            generate(length=3, uppercase=True, lowercase=True, digits=True)


class TestGeneratorConfig:
    def test_valid_config(self):
        config = GeneratorConfig(length=20)
        assert config.length == 20

    def test_pools_built_correctly(self):
        config = GeneratorConfig(uppercase=True, lowercase=False, digits=False, symbols=False)
        pools = config._get_pools()
        assert "uppercase" in pools
        assert "lowercase" not in pools


# ===== Passphrase Tests =====

class TestGeneratePassphrase:
    def test_default_words(self):
        phrase = generate_passphrase()
        words = phrase.split("-")
        assert len(words) == 4

    def test_custom_words(self):
        phrase = generate_passphrase(words=5)
        words = phrase.split("-")
        assert len(words) == 5

    def test_custom_separator(self):
        phrase = generate_passphrase(separator=" ")
        words = phrase.split(" ")
        assert len(words) == 4

    def test_capitalize(self):
        phrase = generate_passphrase(capitalize=True)
        words = phrase.split("-")
        for word in words:
            assert word[0].isupper()

    def test_invalid_words_raises(self):
        with pytest.raises(ValueError):
            generate_passphrase(words=1)
        with pytest.raises(ValueError):
            generate_passphrase(words=11)


class TestPassphraseEntropy:
    def test_entropy_calculation(self):
        entropy = passphrase_entropy(4, 2048)
        assert 40 < entropy < 50  # ~44 bits

    def test_more_words_more_entropy(self):
        e4 = passphrase_entropy(4)
        e5 = passphrase_entropy(5)
        assert e5 > e4


# ===== PIN Tests =====

class TestGeneratePin:
    def test_default_length(self):
        pin = generate_pin()
        assert len(pin) == 4
        assert pin.isdigit()

    def test_custom_length(self):
        pin = generate_pin(length=6)
        assert len(pin) == 6

    def test_avoid_repeats(self):
        for _ in range(100):
            pin = generate_pin(length=4, avoid_repeats=True)
            # Should not have 3+ same digits in a row
            for i in range(len(pin) - 2):
                assert not (pin[i] == pin[i+1] == pin[i+2])

    def test_avoid_sequential(self):
        for _ in range(100):
            pin = generate_pin(length=4, avoid_sequential=True)
            digits = [int(d) for d in pin]
            # Check no ascending/descending sequence
            ascending = all(digits[i] == digits[i-1] + 1 for i in range(1, len(digits)))
            descending = all(digits[i] == digits[i-1] - 1 for i in range(1, len(digits)))
            assert not (ascending or descending)


class TestPinConfig:
    def test_valid_config(self):
        config = PinConfig(length=6)
        assert config.length == 6

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError):
            PinConfig(length=0)
        with pytest.raises(ValueError):
            PinConfig(length=13)


# ===== Strength Analyzer Tests =====

class TestAnalyze:
    def test_empty_password(self):
        report = analyze("")
        assert report.score == 0

    def test_common_password(self):
        report = analyze("password")
        assert report.score == 0
        assert "common_password" in report.patterns

    def test_keyboard_pattern(self):
        report = analyze("qwerty")
        assert "keyboard_pattern" in report.patterns

    def test_sequence(self):
        report = analyze("abcdef")
        assert "sequence" in report.patterns

    def test_repetition(self):
        report = analyze("aaa111")
        assert "repetition" in report.patterns

    def test_strong_password(self):
        report = generate(length=20)
        report = analyze(report)
        assert report.score >= 3

    def test_score_range(self):
        for _ in range(50):
            pwd = generate(length=16)
            report = analyze(pwd)
            assert 0 <= report.score <= 4

    def test_crack_times_exist(self):
        report = analyze("test")
        assert "online_throttled_100_per_hour" in report.crack_times
        assert "offline_fast_hashing_1e10_per_second" in report.crack_times

    def test_feedback_for_weak(self):
        report = analyze("abc")
        assert len(report.feedback) > 0

    def test_feedback_for_strong(self):
        pwd = generate(length=24)
        report = analyze(pwd)
        # Strong passwords should have positive or no negative feedback
        assert not any("common" in f.lower() for f in report.feedback)


class TestStrengthReport:
    def test_report_fields(self):
        report = analyze("test")
        assert hasattr(report, "score")
        assert hasattr(report, "guesses")
        assert hasattr(report, "entropy")
        assert hasattr(report, "crack_times")
        assert hasattr(report, "crack_times_seconds")
        assert hasattr(report, "feedback")
        assert hasattr(report, "patterns")


# ===== Entropy Tests =====

class TestCalculateEntropy:
    def test_basic_entropy(self):
        entropy = calculate_entropy(26, 8)  # 8 lowercase chars
        assert 35 < entropy < 40

    def test_zero_pool(self):
        assert calculate_entropy(0, 10) == 0

    def test_zero_length(self):
        assert calculate_entropy(26, 0) == 0
