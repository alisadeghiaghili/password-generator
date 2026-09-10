"""Tests for optional zxcvbn backend wiring (works without zxcvbn installed)."""

from __future__ import annotations

import pytest
from password_generator import analyze, zxcvbn_available
from password_generator.zxcvbn_backend import analyze_with_zxcvbn


class TestBackendSelection:
    def test_default_backend_is_heuristic(self) -> None:
        report = analyze("password")
        assert report.score == 0
        assert "common_password" in report.patterns

    def test_unknown_backend_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown backend"):
            analyze("password", backend="nope")

    def test_auto_falls_back_when_zxcvbn_missing(self) -> None:
        if zxcvbn_available():
            pytest.skip("zxcvbn installed; fallback path not exercised")
        report = analyze("password", backend="auto")
        assert report.score == 0

    def test_explicit_zxcvbn_without_package_raises(self) -> None:
        if zxcvbn_available():
            pytest.skip("zxcvbn installed")
        with pytest.raises(RuntimeError, match="zxcvbn"):
            analyze("password", backend="zxcvbn")

    def test_zxcvbn_available_is_bool(self) -> None:
        assert isinstance(zxcvbn_available(), bool)


class TestZxcvbnHelper:
    def test_empty_password_raises_when_available(self) -> None:
        if not zxcvbn_available():
            with pytest.raises(RuntimeError):
                analyze_with_zxcvbn("x")
            return
        with pytest.raises(ValueError):
            analyze_with_zxcvbn("")

    def test_when_installed_reports_score(self) -> None:
        if not zxcvbn_available():
            pytest.skip("optional dependency not installed")
        result = analyze_with_zxcvbn("password")
        assert result["score"] == 0
        assert result["backend"] == "zxcvbn"
        report = analyze("password", backend="zxcvbn")
        assert report.score == 0
