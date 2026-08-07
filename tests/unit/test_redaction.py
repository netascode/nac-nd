"""Credential redaction."""

from __future__ import annotations

import logging

import pytest

from nac_nd.config import Config
from nac_nd.redaction import REDACTED, install_redaction_filter, redact

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"


@pytest.mark.parametrize(
    "text",
    [
        '{"userPasswd": "s3cr3t"}',
        "password='s3cr3t'",
        "AuthCookie=s3cr3t",
        "jwttoken: s3cr3t",
        "Authorization: Bearer s3cr3t",
    ],
)
def test_credentials_are_masked(text: str) -> None:
    scrubbed = redact(text)

    assert "s3cr3t" not in scrubbed
    assert REDACTED in scrubbed


def test_a_bare_jwt_is_matched_on_its_shape() -> None:
    """A JWT is matched on its shape, with no surrounding field name."""
    assert redact(f"token is {JWT}") == "token is ***REDACTED***"


def test_the_scheme_survives_so_the_line_stays_readable() -> None:
    assert redact("Authorization: Bearer abc123") == (
        f"Authorization: Bearer {REDACTED}"
    )


def test_newlines_are_escaped_not_dropped() -> None:
    """A forged CRLF must not be able to write a second log entry."""
    assert "\n" not in redact("first\nINFO fabricated second line")
    assert "\\n" in redact("first\nsecond")


def test_the_filter_masks_message_arguments(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("nac_nd.test")
    install_redaction_filter(logger)

    with caplog.at_level(logging.INFO):
        logger.info("login body=%s", {"userPasswd": "s3cr3t"})

    assert "s3cr3t" not in caplog.text


def test_the_filter_masks_a_config_rendered_into_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("nac_nd.test_config")
    install_redaction_filter(logger)
    config = Config(host="nd", username="u", password="s3cr3t")

    with caplog.at_level(logging.DEBUG):
        logger.debug("config=%s", config)

    assert "s3cr3t" not in caplog.text


def test_installing_twice_does_not_stack_filters() -> None:
    logger = logging.getLogger("nac_nd.test_idempotent")

    first = install_redaction_filter(logger)
    second = install_redaction_filter(logger)

    assert first is second
    assert len(logger.filters) == 1
