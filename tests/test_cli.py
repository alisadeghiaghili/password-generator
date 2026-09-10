"""Unit tests for CLI helpers and parser (no interactive TTY required)."""

from __future__ import annotations

import json

import pytest
from password_generator.cli import _safe_int, build_parser, main


class TestSafeInt:
    def test_default_on_empty(self) -> None:
        assert _safe_int("", 16, 4, 256) == 16
        assert _safe_int("   ", 4, 1, 10) == 4

    def test_valid_value(self) -> None:
        assert _safe_int("20", 16, 4, 256) == 20

    def test_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError):
            _safe_int("3", 16, 4, 256)
        with pytest.raises(ValueError):
            _safe_int("999", 16, 4, 256)

    def test_non_int_raises(self) -> None:
        with pytest.raises(ValueError):
            _safe_int("abc", 16, 4, 256)


class TestParser:
    def test_defaults(self) -> None:
        args = build_parser().parse_args([])
        assert args.length == 16
        assert args.count == 1
        assert args.analyze is False

    def test_analyze_is_flag_not_password(self) -> None:
        args = build_parser().parse_args(["--analyze"])
        assert args.analyze is True

    def test_no_symbols_flag(self) -> None:
        args = build_parser().parse_args(["--no-symbols"])
        assert args.no_symbols is True


class TestMainCliMode:
    def test_json_password_generation(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["--length", "12", "--count", "1", "--json"])
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["type"] == "password"
        assert len(payload["passwords"][0]) == 12

    def test_json_passphrase(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["--passphrase", "--words", "3", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["type"] == "passphrase"
        assert len(payload["passwords"][0].split("-")) == 3

    def test_json_pin(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["--pin", "--pin-length", "5", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["type"] == "pin"
        assert len(payload["passwords"][0]) == 5

    def test_analyze_from_stdin(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _FakeStdin:
            def isatty(self) -> bool:
                return False

            def read(self) -> str:
                return "password\n"

        monkeypatch.setattr("password_generator.cli.sys.stdin", _FakeStdin())
        main(["--analyze", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["score"] == 0
        assert "common_password" in payload["patterns"]

    def test_invalid_count_exits(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--count", "0"])
        assert exc.value.code == 2
