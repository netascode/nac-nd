"""Configuration validation and host normalisation."""

from __future__ import annotations

import pytest

from nac_nd.config import Config, normalise_host
from nac_nd.exceptions import InputError


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("nd.example.com", "nd.example.com"),
        ("https://nd.example.com", "nd.example.com"),
        ("http://nd.example.com/", "nd.example.com"),
        ("HTTPS://ND.example.com//", "ND.example.com"),
        ("  10.0.0.1  ", "10.0.0.1"),
        ("nd.example.com:443", "nd.example.com:443"),
    ],
)
def test_a_scheme_in_the_host_is_stripped(given: str, expected: str) -> None:
    """A host carrying its own scheme would produce `https://https://...`."""
    assert normalise_host(given) == expected


def test_the_base_url_is_built_from_the_normalised_host() -> None:
    config = Config(host="https://nd.example.com/", username="u", password="p")

    assert config.base_url == "https://nd.example.com"


def test_prechange_ui_url_points_at_the_nd_prechange_page() -> None:
    config = Config(host="nd.example.com", username="u", password="p")

    assert config.prechange_ui_url == (
        "https://nd.example.com/appcenter/cisco/nexus-insights/ui/"
        "#/changeManagement/preChangeAnalysis"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [("host", ""), ("username", ""), ("password", ""), ("domain", "")],
)
def test_missing_credentials_are_reported_as_bad_input(field: str, value: str) -> None:
    fields = {"host": "nd", "username": "u", "password": "p", "domain": "DefaultAuth"}
    fields[field] = value

    with pytest.raises(InputError) as caught:
        Config(**fields)  # type: ignore[arg-type]

    assert caught.value.exit_code == 4


def test_an_empty_domain_is_caught_before_the_api_returns_a_500() -> None:
    """An empty domain returns HTTP 500, so it is rejected before the call."""
    with pytest.raises(InputError, match="DefaultAuth"):
        Config(host="nd", username="u", password="p", domain="")


def test_the_password_is_kept_out_of_the_repr() -> None:
    """A dataclass repr reaches debuggers, log lines and exception output."""
    config = Config(host="nd", username="u", password="s3cr3t")

    assert "s3cr3t" not in repr(config)


def test_nonsensical_polling_settings_are_rejected() -> None:
    with pytest.raises(InputError):
        Config(host="nd", username="u", password="p", poll_interval_seconds=0)
    with pytest.raises(InputError):
        Config(host="nd", username="u", password="p", job_timeout_minutes=0)
