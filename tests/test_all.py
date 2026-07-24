"""Tests for password_generator package."""

import json
import pytest
from password_generator import (
    generate,
    generate_passphrase,
    generate_pin,
    analyze,
    PasswordPolicy,
    PolicyResult,
    PasswordEntry,
    export_json,
    export_csv,
    export_keepass,
    BreachResult,
)
from password_generator.generator import GeneratorConfig, calculate_entropy
from password_generator.passphrase import PassphraseConfig, passphrase_entropy
from password_generator.pin import PinConfig
from password_generator.strength import StrengthReport, _detect_user_input, _check_policy
from password_generator.breach import _sha1_hash

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
                assert not (pin[i] == pin[i + 1] == pin[i + 2])

    def test_avoid_sequential(self):
        for _ in range(100):
            pin = generate_pin(length=4, avoid_sequential=True)
            digits = [int(d) for d in pin]
            # Check no ascending/descending sequence
            ascending = all(digits[i] == digits[i - 1] + 1 for i in range(1, len(digits)))
            descending = all(digits[i] == digits[i - 1] - 1 for i in range(1, len(digits)))
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


# ===== User Input Detection Tests =====


class TestDetectUserInput:
    def test_detects_name_in_password(self):
        assert _detect_user_input("John123!", ["John", "Smith"]) is True

    def test_no_match(self):
        assert _detect_user_input("Xy9#mK2p", ["John", "Smith"]) is False

    def test_case_insensitive(self):
        assert _detect_user_input("JOHN123", ["john"]) is True

    def test_short_input_ignored(self):
        # Inputs shorter than 3 chars should be ignored
        assert _detect_user_input("Jo123", ["Jo"]) is False

    def test_empty_user_inputs(self):
        assert _detect_user_input("password", []) is False

    def test_partial_match_not_counted(self):
        # "Jo" is too short, "Joh" would match "John"
        assert _detect_user_input("abcJo", ["Jo"]) is False

    def test_birthdate_in_password(self):
        assert _detect_user_input("1990MyPwd", ["1990", "My"]) is True

    def test_empty_password(self):
        assert _detect_user_input("", ["John"]) is False


# ===== Analyze with User Inputs Tests =====


class TestAnalyzeWithUserInputs:
    def test_user_input_detected(self):
        report = analyze("John123!", user_inputs=["John", "Smith"])
        assert "user_input" in report.patterns

    def test_user_input_feedback(self):
        report = analyze("John123!", user_inputs=["John"])
        assert any("personal information" in f.lower() for f in report.feedback)

    def test_no_user_input_when_not_matching(self):
        report = analyze("Xy9#mK2p!qR4", user_inputs=["John", "Smith"])
        assert "user_input" not in report.patterns

    def test_none_user_inputs(self):
        report = analyze("password", user_inputs=None)
        assert "user_input" not in report.patterns

    def test_empty_user_inputs(self):
        report = analyze("password", user_inputs=[])
        assert "user_input" not in report.patterns


# ===== Custom Dictionaries Tests =====


class TestAnalyzeWithCustomDictionaries:
    def test_password_in_custom_dict(self):
        my_dict = {"mypassword123", "qwerty456"}
        report = analyze("mypassword123", custom_dictionaries=[my_dict])
        assert report.guesses <= 100

    def test_password_not_in_custom_dict(self):
        my_dict = {"mypassword123", "qwerty456"}
        report = analyze("Xy9#mK2p!qR4", custom_dictionaries=[my_dict])
        assert report.guesses > 100

    def test_multiple_dictionaries(self):
        dict1 = {"word1"}
        dict2 = {"word2"}
        report = analyze("word2", custom_dictionaries=[dict1, dict2])
        assert report.guesses <= 100

    def test_empty_dictionaries(self):
        report = analyze("password", custom_dictionaries=[])
        assert report.guesses <= 100  # Still common password

    def test_case_insensitive_dict(self):
        my_dict = {"MyPassword"}
        report = analyze("mypassword", custom_dictionaries=[my_dict])
        assert report.guesses <= 100

    def test_none_dictionaries(self):
        report = analyze("password", custom_dictionaries=None)
        assert report.score == 0  # Still common password


# ===== PasswordPolicy Tests =====


class TestPasswordPolicy:
    def test_min_length_pass(self):
        policy = PasswordPolicy(min_length=8)
        result = policy.test("MyP@ss123")
        assert result.is_valid is True

    def test_min_length_fail(self):
        policy = PasswordPolicy(min_length=8)
        result = policy.test("short")
        assert result.is_valid is False
        assert any("too short" in e.lower() for e in result.errors)

    def test_max_length_pass(self):
        policy = PasswordPolicy(max_length=10)
        result = policy.test("short")
        assert result.is_valid is True

    def test_max_length_fail(self):
        policy = PasswordPolicy(max_length=5)
        result = policy.test("toolong")
        assert result.is_valid is False
        assert any("too long" in e.lower() for e in result.errors)

    def test_min_uppercase_pass(self):
        policy = PasswordPolicy(min_uppercase=2)
        result = policy.test("MyPaSSword")
        assert result.is_valid is True

    def test_min_uppercase_fail(self):
        policy = PasswordPolicy(min_uppercase=2)
        result = policy.test("mypassword")
        assert result.is_valid is False
        assert any("uppercase" in e.lower() for e in result.errors)

    def test_min_lowercase_pass(self):
        policy = PasswordPolicy(min_lowercase=3)
        result = policy.test("abc123XYZ")
        assert result.is_valid is True

    def test_min_lowercase_fail(self):
        policy = PasswordPolicy(min_lowercase=3)
        result = policy.test("ABC123")
        assert result.is_valid is False
        assert any("lowercase" in e.lower() for e in result.errors)

    def test_min_digits_pass(self):
        policy = PasswordPolicy(min_digits=2)
        result = policy.test("abc123")
        assert result.is_valid is True

    def test_min_digits_fail(self):
        policy = PasswordPolicy(min_digits=3)
        result = policy.test("abc12")
        assert result.is_valid is False
        assert any("digits" in e.lower() for e in result.errors)

    def test_min_symbols_pass(self):
        policy = PasswordPolicy(min_symbols=1)
        result = policy.test("abc123!")
        assert result.is_valid is True

    def test_min_symbols_fail(self):
        policy = PasswordPolicy(min_symbols=1)
        result = policy.test("abc123")
        assert result.is_valid is False
        assert any("symbols" in e.lower() for e in result.errors)

    def test_min_entropy_pass(self):
        policy = PasswordPolicy(min_entropy=50)
        result = policy.test("Xy9#mK2p!qR4nL8")
        assert result.is_valid is True

    def test_min_entropy_fail(self):
        policy = PasswordPolicy(min_entropy=100)
        result = policy.test("abc123")
        assert result.is_valid is False
        assert any("entropy" in e.lower() for e in result.errors)

    def test_max_repeats_pass(self):
        policy = PasswordPolicy(max_repeats=2)
        result = policy.test("aabb1122")
        assert result.is_valid is True

    def test_max_repeats_fail(self):
        policy = PasswordPolicy(max_repeats=2)
        result = policy.test("aaab1122")
        assert result.is_valid is False
        assert any("repeated" in e.lower() for e in result.errors)

    def test_exclude_pattern_pass(self):
        policy = PasswordPolicy(exclude_patterns=[r"\d{4}"])
        result = policy.test("abcXYZ")
        assert result.is_valid is True

    def test_exclude_pattern_fail(self):
        policy = PasswordPolicy(exclude_patterns=[r"\d{4}"])
        result = policy.test("abc1234XYZ")
        assert result.is_valid is False
        assert any("pattern" in e.lower() for e in result.errors)

    def test_multiple_rules(self):
        policy = PasswordPolicy(min_length=8, min_uppercase=1, min_digits=1)
        result = policy.test("MyP@ss123")
        assert result.is_valid is True
        assert result.score >= 0

    def test_all_rules_fail(self):
        policy = PasswordPolicy(min_length=20, min_uppercase=5, min_digits=5, min_entropy=100)
        result = policy.test("abc")
        assert result.is_valid is False
        assert len(result.errors) >= 3

    def test_disabled_rules(self):
        # All zeros = no restrictions
        policy = PasswordPolicy()
        result = policy.test("a")
        assert result.is_valid is True

    def test_result_has_score(self):
        policy = PasswordPolicy(min_length=8)
        result = policy.test("MyP@ss123")
        assert hasattr(result, "score")
        assert 0 <= result.score <= 4

    def test_result_has_entropy(self):
        policy = PasswordPolicy(min_length=8)
        result = policy.test("MyP@ss123")
        assert hasattr(result, "entropy")
        assert result.entropy >= 0


# ===== PolicyResult Tests =====


class TestPolicyResult:
    def test_valid_password(self):
        policy = PasswordPolicy(min_length=8)
        result = policy.test("MyP@ss123")
        assert isinstance(result, PolicyResult)
        assert result.is_valid is True
        assert result.errors == []

    def test_invalid_password(self):
        policy = PasswordPolicy(min_length=8)
        result = policy.test("short")
        assert isinstance(result, PolicyResult)
        assert result.is_valid is False
        assert len(result.errors) > 0


# ===== PasswordEntry Tests =====


class TestPasswordEntry:
    def test_basic_entry(self):
        entry = PasswordEntry("GitHub", "user@email.com", "s3cure!")
        assert entry.title == "GitHub"
        assert entry.username == "user@email.com"
        assert entry.password == "s3cure!"
        assert entry.url == ""
        assert entry.notes == ""
        assert entry.group == ""

    def test_full_entry(self):
        entry = PasswordEntry(
            title="GitHub",
            username="user@email.com",
            password="s3cure!",
            url="https://github.com",
            notes="Work account",
            group="Work",
        )
        assert entry.url == "https://github.com"
        assert entry.notes == "Work account"
        assert entry.group == "Work"


# ===== Export JSON Tests =====


class TestExportJson:
    def test_single_entry(self):
        entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        result = export_json(entries)
        data = json.loads(result)
        assert len(data) == 1
        assert data[0]["title"] == "GitHub"

    def test_multiple_entries(self):
        entries = [
            PasswordEntry("GitHub", "user@email.com", "pass1"),
            PasswordEntry("GitLab", "user@email.com", "pass2"),
        ]
        result = export_json(entries)
        data = json.loads(result)
        assert len(data) == 2

    def test_empty_entries(self):
        result = export_json([])
        data = json.loads(result)
        assert data == []

    def test_custom_indent(self):
        entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        result = export_json(entries, indent=4)
        assert "    " in result  # 4-space indent

    def test_optional_fields(self):
        entry = PasswordEntry("Test", "user", "pass", url="https://test.com")
        result = export_json([entry])
        data = json.loads(result)
        assert data[0]["url"] == "https://test.com"
        assert data[0]["notes"] == ""

    def test_special_characters(self):
        entry = PasswordEntry("Test", "user", "p@ss!#$%")
        result = export_json([entry])
        data = json.loads(result)
        assert data[0]["password"] == "p@ss!#$%"


# ===== Export CSV Tests =====


class TestExportCsv:
    def test_single_entry(self):
        entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        result = export_csv(entries)
        lines = result.strip().split("\n")
        assert len(lines) == 2  # Header + 1 row
        assert "title" in lines[0]
        assert "GitHub" in lines[1]

    def test_multiple_entries(self):
        entries = [
            PasswordEntry("GitHub", "user@email.com", "pass1"),
            PasswordEntry("GitLab", "user@email.com", "pass2"),
        ]
        result = export_csv(entries)
        lines = result.strip().split("\n")
        assert len(lines) == 3  # Header + 2 rows

    def test_empty_entries(self):
        result = export_csv([])
        lines = result.strip().split("\n")
        assert len(lines) == 1  # Just header

    def test_csv_header_columns(self):
        result = export_csv([])
        header = result.strip().split("\n")[0]
        columns = header.split(",")
        assert columns == ["title", "username", "password", "url", "notes", "group"]

    def test_special_characters_in_csv(self):
        entry = PasswordEntry("Test", "user", "p@ss,with,commas")
        result = export_csv([entry])
        assert "p@ss,with,commas" in result


# ===== Export KeePass Tests =====


class TestExportKeepass:
    def test_single_entry(self):
        entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        result = export_keepass(entries)
        assert "GitHub" in result
        assert "user@email.com" in result
        assert "s3cure!" in result

    def test_multiple_entries(self):
        entries = [
            PasswordEntry("GitHub", "user@email.com", "pass1"),
            PasswordEntry("GitLab", "user@email.com", "pass2"),
        ]
        result = export_keepass(entries)
        assert "GitHub" in result
        assert "GitLab" in result

    def test_empty_entries(self):
        result = export_keepass([])
        assert "KeePassFile" in result
        assert "Group" in result

    def test_xml_declaration(self):
        result = export_keepass([])
        assert result.startswith("<?xml")

    def test_optional_url(self):
        entry = PasswordEntry("Test", "user", "pass", url="https://test.com")
        result = export_keepass([entry])
        assert "https://test.com" in result

    def test_optional_notes(self):
        entry = PasswordEntry("Test", "user", "pass", notes="My notes")
        result = export_keepass([entry])
        assert "My notes" in result

    def test_no_url_when_empty(self):
        entry = PasswordEntry("Test", "user", "pass")
        result = export_keepass([entry])
        # URL element should not be present when empty
        assert "<URL></URL>" not in result


# ===== BreachResult Tests =====


class TestBreachResult:
    def test_breached_result(self):
        result = BreachResult(is_breached=True, count=12345, message="Found")
        assert result.is_breached is True
        assert result.count == 12345
        assert result.message == "Found"

    def test_safe_result(self):
        result = BreachResult(is_breached=False, count=0, message="Not found")
        assert result.is_breached is False
        assert result.count == 0

    def test_sha1_hash(self):
        # Known hash for "password"
        hash_val = _sha1_hash("password")
        assert hash_val == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def test_sha1_hash_empty(self):
        hash_val = _sha1_hash("")
        assert len(hash_val) == 40  # SHA-1 is always 40 hex chars


# ===== Edge Cases Tests =====


class TestEdgeCases:
    def test_unicode_password(self):
        report = analyze("Pässwörd123!")
        assert report.score >= 0

    def test_very_long_password(self):
        pwd = generate(length=256)
        assert len(pwd) == 256
        report = analyze(pwd)
        assert report.score == 4

    def test_single_char_password(self):
        report = analyze("a")
        assert report.score == 0
        assert len(report.feedback) > 0

    def test_only_symbols(self):
        pwd = generate(length=10, uppercase=False, lowercase=False, digits=False)
        assert all(not c.isalnum() for c in pwd)

    def test_mixed_case_entropy(self):
        report1 = analyze("abcdef")
        report2 = analyze("AbCdEf")
        assert report2.entropy > report1.entropy

    def test_passphrase_entropy_scales(self):
        e2 = passphrase_entropy(2)
        e4 = passphrase_entropy(4)
        e6 = passphrase_entropy(6)
        assert e2 < e4 < e6

    def test_pin_all_same_digits(self):
        # Should still generate (avoid_repeats just retries)
        for _ in range(10):
            pin = generate_pin(length=4, avoid_repeats=False)
            assert len(pin) == 4

    def test_generator_reproducibility_not_guaranteed(self):
        # Two calls should produce different passwords
        pwd1 = generate(length=16)
        pwd2 = generate(length=16)
        assert pwd1 != pwd2

    def test_analyze_common_passwords_list(self):
        # Test a few known common passwords
        for pwd in ["password", "123456", "qwerty", "12345678"]:
            report = analyze(pwd)
            assert report.score == 0

    def test_policy_with_exclude_complex_regex(self):
        policy = PasswordPolicy(exclude_patterns=[r"(.)\1{2,}"])  # No 3+ repeated chars
        result = policy.test("aabb1122")
        assert result.is_valid is True
        result = policy.test("aaab1122")
        assert result.is_valid is False

    def test_export_special_chars_json(self):
        entry = PasswordEntry("Test", "user", 'p@ss"w!rd')
        result = export_json([entry])
        data = json.loads(result)
        assert data[0]["password"] == 'p@ss"w!rd'

    def test_export_unicode_json(self):
        entry = PasswordEntry("测试", "user@邮箱.中国", "密码123")
        result = export_json([entry])
        data = json.loads(result)
        assert data[0]["title"] == "测试"
