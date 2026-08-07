"""Logging defaults."""

from __future__ import annotations

import logging

from nac_nd.log import configure_logging


def test_httpx_is_quiet_by_default() -> None:
    configure_logging(verbose=False)

    assert logging.getLogger().level == logging.WARNING
    assert logging.getLogger("httpx").level == logging.WARNING


def test_verbose_enables_http_logging() -> None:
    configure_logging(verbose=True)

    assert logging.getLogger().level == logging.DEBUG
    assert logging.getLogger("httpx").level == logging.DEBUG
