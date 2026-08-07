"""Logging configuration shared by the CLI and client."""

from __future__ import annotations

import logging
import sys

from nac_nd.redaction import install_redaction_filter

_verbose = False


def is_verbose() -> bool:
    return _verbose


def configure_logging(verbose: bool) -> None:
    """Configure process logging.

    Default mode keeps stderr quiet except for explicit progress lines and
    errors. Verbose mode logs each HTTP request and API call.
    """
    global _verbose
    _verbose = verbose
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        root.addHandler(handler)
    if verbose:
        root.setLevel(logging.DEBUG)
        logging.getLogger("httpx").setLevel(logging.DEBUG)
        logging.getLogger("httpcore").setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
    install_redaction_filter(root)
