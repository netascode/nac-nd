"""YAML configuration file loading and discovery."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from nac_nd.exceptions import InputError

logger = logging.getLogger(__name__)

CONFIG_OPTION = "--config"
DEFAULT_CONFIG_NAME = "nac-nd.yaml"
XDG_CONFIG_RELATIVE = Path(".config") / "nac-nd" / "config.yaml"

KNOWN_KEYS = frozenset(
    {
        "host",
        "username",
        "user",
        "password",
        "domain",
        "fabric",
        "fabrics",
        "verify_ssl",
        "verify_tls",
        "ca_bundle",
        "job_timeout_minutes",
        "poll_interval",
        "delta_detail",
    }
)

ENV_MAP: dict[str, str] = {
    "host": "ND_HOST",
    "username": "ND_USER",
    "user": "ND_USER",
    "password": "ND_PASSWORD",  # nosec B105 — maps YAML key to env var name, not a secret
    "domain": "ND_DOMAIN",
    "fabric": "ND_FABRIC",
    "verify_ssl": "ND_VERIFY_SSL",
    "verify_tls": "ND_VERIFY_SSL",
    "ca_bundle": "ND_CA_BUNDLE",
    "job_timeout_minutes": "ND_JOB_TIMEOUT_MINUTES",
    "poll_interval": "ND_POLL_INTERVAL",
    "delta_detail": "ND_DELTA_DETAIL",
}

_configured_fabrics: list[str] = []
_loaded_config_path: Path | None = None


def configured_fabrics() -> list[str]:
    """Return the fabric list from the loaded config file, if any."""
    if _configured_fabrics:
        return list(_configured_fabrics)
    fabric = os.environ.get("ND_FABRIC", "").strip()
    return [fabric] if fabric else []


def loaded_config_path() -> Path | None:
    return _loaded_config_path


def strip_config_option(argv: list[str]) -> tuple[Path | None, list[str]]:
    """Remove a root-level ``--config`` option from ``argv`` before Typer runs."""
    remaining: list[str] = []
    config_path: Path | None = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == CONFIG_OPTION and index + 1 < len(argv):
            config_path = Path(argv[index + 1])
            index += 2
            continue
        if arg.startswith(f"{CONFIG_OPTION}="):
            config_path = Path(arg.split("=", 1)[1])
            index += 1
            continue
        remaining.append(arg)
        index += 1
    return config_path, remaining


def resolve_config_path(
    *, explicit: Path | None = None, cwd: Path | None = None
) -> Path | None:
    """Return the first config file path that exists."""
    if explicit is not None:
        return explicit
    env_path = os.environ.get("ND_CONFIG", "").strip()
    if env_path:
        return Path(env_path)
    base = cwd or Path.cwd()
    candidates = (
        base / DEFAULT_CONFIG_NAME,
        Path.home() / XDG_CONFIG_RELATIVE,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _coerce_env_value(key: str, value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if key in {"job_timeout_minutes", "poll_interval"}:
        return str(int(value))
    return str(value)


def _normalise_fabrics(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        raise InputError("Config key 'fabrics' must be a list of fabric names.")
    fabrics = [str(item).strip() for item in raw if str(item).strip()]
    if not fabrics:
        raise InputError("Config key 'fabrics' must not be empty.")
    return fabrics


def load_settings(path: Path) -> dict[str, Any]:
    """Parse and validate a YAML settings file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"Config file {path} cannot be read: {exc.strerror}.") from exc
    if not text.strip():
        raise InputError(f"Config file {path} is empty.")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InputError(f"Config file {path} is not valid YAML: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise InputError(
            f"Config file {path} must contain a YAML mapping at the top level."
        )
    return data


def apply_settings(data: dict[str, Any], *, path: Path | None = None) -> None:
    """Apply YAML settings to ``os.environ`` for keys not already set."""
    global _configured_fabrics, _loaded_config_path

    for key in data:
        if key not in KNOWN_KEYS:
            logger.warning("Ignoring unknown config key %r", key)

    fabrics_raw = data.get("fabrics")
    if fabrics_raw is not None:
        _configured_fabrics = _normalise_fabrics(fabrics_raw)
    elif data.get("fabric"):
        _configured_fabrics = [str(data["fabric"]).strip()]
    else:
        _configured_fabrics = []

    for key, env_name in ENV_MAP.items():
        if key not in data or data[key] is None:
            continue
        if env_name in os.environ:
            continue
        os.environ[env_name] = _coerce_env_value(key, data[key])

    _loaded_config_path = path


def bootstrap_settings(argv: list[str] | None = None) -> list[str]:
    """Load YAML config (if any) and return ``argv`` with ``--config`` removed."""
    args = list(argv if argv is not None else sys.argv[1:])
    explicit, remaining = strip_config_option(args)
    path = resolve_config_path(explicit=explicit)
    if path is not None:
        if not path.is_file():
            raise InputError(f"Config file {path} does not exist.")
        apply_settings(load_settings(path), path=path)
    return remaining
