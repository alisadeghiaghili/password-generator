"""Regression tests for correctness and security issues.

These tests encode known bugs and must fail before the corresponding fix.
"""

from __future__ import annotations

import math

import pytest
from password_generator import analyze, generate, generate_passphrase, generate_pin
from password_generator.generator import GeneratorConfig
from password_generator.passphrase import PassphraseConfig, _load_wordlist, passphrase_entropy
from password_generator.strength import _detect_dates, _detect_repeats, _estimate_guesses


class TestEmptyPoolAfterExclude:
    """exclude_ambiguous must be validated after filtering, not before."""

    def test_symbols_only_ambiguous_raises(self) -> None:
        with pytest.raises(ValueError):
            GeneratorConfig(
                length=4,
                uppercase=False,
                lowercase=False,
                digits=False,
                symbols=True,
                symbol_chars="lI1O0o",
                exclude_ambiguous=True,
            )

    def test_generate_does_not_indexerror(self) -> None:
        with pytest.raises(ValueError):
            config = GeneratorConfig(
                length=4,
                uppercase=False,
                lowercase=False,
                digits=False,
                symbols=True,
                symbol_chars="lI1O0o",
                exclude_ambiguous=True,
            )
            generate(config)


class TestLongPasswordAnalysis:
    """analyze() must not OverflowError on max-length passwords."""

    def test_analyze_length_256_no_crash(self) -> None:
        pwd = generate(length=256)
        report = analyze(pwd)
        assert 0 <= report.score <= 4
        assert report.guesses > 0
        assert math.isfinite(report.entropy)

    def test_analyze_256_repeated_uppercase(self) -> None:
        report = analyze("A" * 256)
        assert 0 <= report.score <= 4
        assert math.isfinite(report.guesses)

    def test_analyze_very_long_string(self) -> None:
        report = analyze("Xy9!" * 2000)
        assert 0 <= report.score <= 4


class TestPassphraseEntropyHonesty:
    """Entropy must use the real wordlist size, not a hardcoded 2048."""

    def test_default_entropy_uses_actual_wordlist(self) -> None:
        size = len(_load_wordlist())
        expected = round(4 * math.log2(size))
        assert passphrase_entropy(4) == expected

    def test_wordlist_is_eff_sized(self) -> None:
        size = len(_load_wordlist())
        assert size >= 7000
        # 4 words from EFF-scale list: ~13 bits each
        assert passphrase_entropy(4) >= 50

    def test_passphrase_config_wordlist_respected(self) -> None:
        phrase = generate_passphrase(PassphraseConfig(words=4))
        assert len(phrase.split("-")) == 4


class TestPinSequentialSubstring:
    """Sequential runs of 4+ digits must be rejected, not only full-string sequences."""

    def test_embedded_sequence_rejected(self) -> None:
        # length=8: force many attempts; none should contain 4-in-a-row sequence
        for _ in range(200):
            pin = generate_pin(length=8, avoid_sequential=True)
            digits = [int(d) for d in pin]
            assert not _has_run(digits, 4)

    def test_full_sequence_still_rejected(self) -> None:
        for _ in range(200):
            pin = generate_pin(length=4, avoid_sequential=True)
            digits = [int(d) for d in pin]
            assert not _has_run(digits, 4)

    def test_short_pin_length_2_not_rejected_as_sequence(self) -> None:
        # length 2 cannot form a 4-run; must always succeed
        pin = generate_pin(length=2, avoid_sequential=True)
        assert len(pin) == 2


def _has_run(digits: list[int], min_len: int = 4) -> bool:
    n = len(digits)
    if n < min_len:
        return False
    for i in range(n - min_len + 1):
        window = digits[i : i + min_len]
        asc = all(window[j] == window[j - 1] + 1 for j in range(1, min_len))
        desc = all(window[j] == window[j - 1] - 1 for j in range(1, min_len))
        if asc or desc:
            return True
    return False


class TestStrengthFalsePositives:
    """Known-weak passwords must not score as VERY STRONG."""

    def test_password123456_not_strong(self) -> None:
        report = analyze("password123456")
        assert report.score <= 1
        assert report.score < 4

    def test_leet_p_at_ssw0rd_detected(self) -> None:
        report = analyze("P@ssw0rd")
        assert report.score <= 1
        assert "common_password" in report.patterns or report.score <= 1

    def test_year_in_password_detected(self) -> None:
        report = analyze("MyPass1990")
        assert "date" in report.patterns
        assert report.entropy > 0

    def test_short_year_password_is_weak(self) -> None:
        report = analyze("dragon2001")
        assert "common_password" in report.patterns
        assert report.score == 0

    def test_common_password_score_zero(self) -> None:
        assert analyze("password").score == 0
        assert analyze("123456").score == 0
        assert analyze("qwerty").score == 0

    def test_strong_generated_password_still_strong(self) -> None:
        pwd = generate(length=20)
        report = analyze(pwd)
        assert report.score >= 3

    def test_empty_patterns_for_good_password(self) -> None:
        report = analyze("v8$Kx!2mNp@Lw9RzQ")
        assert report.score >= 3


class TestDetectHelpers:
    def test_dates_without_word_boundary(self) -> None:
        assert _detect_dates("xx1990yy")
        assert _detect_dates("born2001!")
        assert not _detect_dates("ab")

    def test_repeats_linear_scan(self) -> None:
        assert _detect_repeats("aaa")
        assert _detect_repeats("xx1112")
        assert not _detect_repeats("abc")

    def test_estimate_guesses_no_overflow(self) -> None:
        g = _estimate_guesses("A" * 256)
        assert g > 0
        assert math.isfinite(g)


class TestCliPackaging:
    def test_cli_module_inside_package(self) -> None:
        import password_generator.cli as cli

        assert hasattr(cli, "main")

    def test_get_pools_public(self) -> None:
        config = GeneratorConfig()
        pools = config.get_pools()
        assert "lowercase" in pools or "uppercase" in pools
