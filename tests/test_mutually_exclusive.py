"""--passphrase and --pin select different generators.

Passing both at once is a user error: the CLI must reject the combination
with exit code 2 instead of silently generating a passphrase and ignoring
--pin (and its --pin-length/--avoid-* options).
"""

from __future__ import annotations

import pytest

from password_generator.cli import main


def test_passphrase_and_pin_together_exit_2() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--passphrase", "--pin", "--json"])
    assert exc.value.code == 2


def test_passphrase_alone_still_works(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--passphrase", "--words", "3", "--json"])
    assert "passphrase" in capsys.readouterr().out


def test_pin_alone_still_works(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--pin", "--pin-length", "5", "--json"])
    assert "pin" in capsys.readouterr().out
