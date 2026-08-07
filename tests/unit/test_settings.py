"""YAML settings file loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nac_nd.exceptions import InputError
from nac_nd.settings import (
    apply_settings,
    bootstrap_settings,
    configured_fabrics,
    load_settings,
    resolve_config_path,
)


@pytest.fixture
def restore_environ() -> None:
    saved = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(saved)


def test_yaml_values_apply_to_unset_environment_variables(
    restore_environ: None,
) -> None:
    os.environ.pop("ND_HOST", None)

    apply_settings({"host": "yaml.example.com"}, path=Path("nac-nd.yaml"))

    assert os.environ["ND_HOST"] == "yaml.example.com"


def test_a_real_environment_variable_beats_yaml(restore_environ: None) -> None:
    os.environ["ND_HOST"] = "real.example.com"

    apply_settings({"host": "yaml.example.com"}, path=Path("nac-nd.yaml"))

    assert os.environ["ND_HOST"] == "real.example.com"


def test_fabrics_default_from_fabric_when_the_list_is_omitted(
    restore_environ: None,
) -> None:
    apply_settings({"fabric": "FABRIC-A"}, path=Path("nac-nd.yaml"))

    assert configured_fabrics() == ["FABRIC-A"]


def test_bootstrap_loads_nac_nd_yaml_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_environ: None
) -> None:
    (tmp_path / "nac-nd.yaml").write_text("host: cwd.example.com\n")
    monkeypatch.chdir(tmp_path)
    os.environ.pop("ND_HOST", None)

    bootstrap_settings(["doctor"])

    assert os.environ["ND_HOST"] == "cwd.example.com"


def test_bootstrap_strips_a_root_level_config_option(
    tmp_path: Path,
    restore_environ: None,
) -> None:
    config = tmp_path / "lab.yaml"
    config.write_text("host: from-flag.example.com\n")
    os.environ.pop("ND_HOST", None)

    remaining = bootstrap_settings(["--config", str(config), "doctor"])

    assert remaining == ["doctor"]
    assert os.environ["ND_HOST"] == "from-flag.example.com"


def test_unknown_yaml_keys_are_ignored_without_failing(
    restore_environ: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    apply_settings({"host": "nd.example.com", "extra": "nope"}, path=Path("x.yaml"))

    assert os.environ["ND_HOST"] == "nd.example.com"
    assert any("extra" in record.message for record in caplog.records)


def test_resolve_config_path_prefers_an_explicit_file(tmp_path: Path) -> None:
    explicit = tmp_path / "custom.yaml"
    explicit.write_text("host: x\n")

    assert resolve_config_path(explicit=explicit, cwd=tmp_path / "empty") == explicit


def test_load_settings_rejects_invalid_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{not valid\n")

    with pytest.raises(InputError, match="valid YAML"):
        load_settings(bad)
