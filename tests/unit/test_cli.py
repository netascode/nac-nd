"""The entry point: the exit-code contract with CI, and `.env` resolution.

Exit 2 means a job failed and exit 4 means bad input. Typer's
`exists`/`dir_okay`/`readable` checks exit 2, so `prechange` validates its
input file itself.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from dotenv import find_dotenv
from typer.testing import CliRunner

import nac_nd
from nac_nd.cli import _apply_legacy_env_aliases, app, main
from nac_nd.exceptions import InputError, JobError

runner = CliRunner()

# Enough configuration to reach the file checks. No request is made: the
# input is rejected before any client is constructed.
ENV = {
    "ND_HOST": "nd.example.com",
    "ND_USER": "admin",
    "ND_PASSWORD": "s3cr3t",
    "ND_FABRIC": "FABRIC-A",
}


def test_exit_codes_for_bad_input_and_failed_jobs_do_not_collide() -> None:
    assert InputError.exit_code != JobError.exit_code


def test_a_missing_config_file_exits_4_not_click_s_usage_code(tmp_path: Path) -> None:
    result = runner.invoke(app, ["prechange", str(tmp_path / "absent.json")], env=ENV)

    assert result.exit_code == InputError.exit_code
    assert "does not exist" in result.output


def test_a_directory_in_place_of_a_config_file_exits_4(tmp_path: Path) -> None:
    result = runner.invoke(app, ["prechange", str(tmp_path)], env=ENV)

    assert result.exit_code == InputError.exit_code
    assert "is not a file" in result.output


def test_an_empty_config_file_exits_4(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("   \n")

    result = runner.invoke(app, ["prechange", str(empty)], env=ENV)

    assert result.exit_code == InputError.exit_code
    assert "is empty" in result.output


# -- .env resolution -------------------------------------------------------


@pytest.fixture
def restore_environ() -> Iterator[None]:
    """Undo the changes `load_dotenv` makes directly to `os.environ`."""
    saved = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(saved)


def run_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the entry point. Typer prints help and exits when given no args."""
    monkeypatch.setattr(sys, "argv", ["nac-nd"])
    with pytest.raises(SystemExit):
        main()


def test_a_dotenv_in_the_working_directory_is_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_environ: None
) -> None:
    (tmp_path / ".env").write_text("ND_HOST=cwd.example.com\n")
    monkeypatch.chdir(tmp_path)
    os.environ.pop("ND_HOST", None)

    run_main(monkeypatch)

    assert os.environ["ND_HOST"] == "cwd.example.com"


def test_the_dotenv_is_resolved_from_the_working_directory_not_the_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_environ: None
) -> None:
    """The path handed to `load_dotenv` is the one below the working directory."""
    package_tree = Path(nac_nd.__file__).resolve().parent.parent
    (tmp_path / ".env").write_text("ND_HOST=cwd.example.com\n")
    monkeypatch.chdir(tmp_path)
    loaded: list[str] = []

    def spy(path: str = "") -> bool:
        loaded.append(path)
        return True

    monkeypatch.setattr("nac_nd.cli.load_dotenv", spy)

    run_main(monkeypatch)

    assert loaded == [str(tmp_path / ".env")]
    assert package_tree not in Path(loaded[0]).resolve().parents


def test_find_dotenv_reports_nothing_when_no_file_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty path is what `load_dotenv` receives when there is no file."""
    monkeypatch.chdir(tmp_path)

    assert find_dotenv(usecwd=True) == ""


def test_a_real_environment_variable_beats_the_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_environ: None
) -> None:
    (tmp_path / ".env").write_text("ND_HOST=cwd.example.com\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ND_HOST", "real.example.com")

    run_main(monkeypatch)

    assert os.environ["ND_HOST"] == "real.example.com"


def test_running_without_a_dotenv_does_not_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_environ: None
) -> None:
    monkeypatch.chdir(tmp_path)
    os.environ.pop("ND_HOST", None)

    run_main(monkeypatch)

    assert "ND_HOST" not in os.environ


def test_root_help_explains_configuration() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Configuration:" in result.output
    assert "config.example.yaml" in result.output
    assert "nac-nd.yaml" in result.output
    assert "compliance --all" in result.output
    assert "ND_VERIFY_TLS" in result.output


def test_nd_verify_tls_is_mapped_when_nd_verify_ssl_is_unset(
    restore_environ: None,
) -> None:
    os.environ.pop("ND_VERIFY_SSL", None)
    os.environ["ND_VERIFY_TLS"] = "false"

    _apply_legacy_env_aliases()

    assert os.environ["ND_VERIFY_SSL"] == "false"


def test_nd_verify_ssl_wins_over_the_legacy_tls_alias(
    restore_environ: None,
) -> None:
    os.environ["ND_VERIFY_SSL"] = "true"
    os.environ["ND_VERIFY_TLS"] = "false"

    _apply_legacy_env_aliases()

    assert os.environ["ND_VERIFY_SSL"] == "true"


def test_a_dotenv_with_only_nd_verify_tls_is_honoured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_environ: None
) -> None:
    (tmp_path / ".env").write_text("ND_VERIFY_TLS=false\n")
    monkeypatch.chdir(tmp_path)
    os.environ.pop("ND_VERIFY_SSL", None)
    os.environ.pop("ND_VERIFY_TLS", None)

    run_main(monkeypatch)

    assert os.environ["ND_VERIFY_SSL"] == "false"


def test_compliance_all_and_fabric_together_exit_4() -> None:
    result = runner.invoke(
        app,
        ["compliance", "--all", "--fabric", "FABRIC-A"],
        env=ENV,
    )

    assert result.exit_code == InputError.exit_code
    assert "cannot be combined" in result.output
