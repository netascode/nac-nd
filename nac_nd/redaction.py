"""Credential redaction for everything this tool logs.

A `logging.Filter` on the root logger and its handlers covers every call site
without any of them knowing it exists.
"""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED = "***REDACTED***"

# Field, header and cookie names used by this codebase and the Nexus Dashboard
# API. Longest first, so an alternation match cannot stop short at a shorter
# name.
SENSITIVE_KEYS: tuple[str, ...] = (
    "userpasswd",
    "authcookie",
    "jwttoken",
    "password",
    "passwd",
    "secret",
    "token",
)

_KEYS = "|".join(re.escape(key) for key in SENSITIVE_KEYS)

# `Authorization: Bearer <token>`. Matched by scheme so the scheme word
# survives and only the credential is replaced. Listing a bare `token ` here
# would redact the word after "returned no token".
_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9\-._~+/]+=*)")

# A JWT, matched on its shape because the session token can be logged with no
# surrounding field name for the key patterns to key on.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

# `"password": "s3cr3t"` -- a quoted value, kept quoted so the surrounding
# JSON or repr stays readable.
_QUOTED_RE = re.compile(
    rf"""(?i)(["']?(?:{_KEYS})["']?\s*[:=]\s*)(["'])(?:\\.|(?!\2).)*\2"""
)

# `AuthCookie=s3cr3t` -- an unquoted value, ending at the first character that
# cannot be part of one.
_BARE_RE = re.compile(rf"""(?i)((?:{_KEYS})["']?\s*[:=]\s*)([^\s,;&"'}}\)\]]+)""")


def _quoted_replacement(match: re.Match[str]) -> str:
    quote = match.group(2)
    return f"{match.group(1)}{quote}{REDACTED}{quote}"


def redact(text: str) -> str:
    r"""Mask credentials in `text` and flatten it to a single line.

    Newlines are escaped rather than dropped, so a forged `\r\n` cannot write
    a second log entry. Flattening runs first so a newline inside a quoted
    value cannot walk a pattern off the end of that value.
    """
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    text = _JWT_RE.sub(REDACTED, text)
    text = _SCHEME_RE.sub(rf"\1\2{REDACTED}", text)
    text = _QUOTED_RE.sub(_quoted_replacement, text)
    return _BARE_RE.sub(rf"\1{REDACTED}", text)


class RedactingFilter(logging.Filter):
    """Scrubs credentials from a log record's message, arguments and traceback.

    The record is interpolated here because a credential can arrive in
    `record.args` as well as in a preformatted message.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # Unnamed arguments cannot be recognised as credentials, so they
            # are withheld. The format string identifies the call site.
            message = f"{record.msg} [arguments withheld: interpolation failed]"
        record.msg = redact(message)
        # The message is already interpolated, so the arguments are cleared to
        # stop the handler applying them again.
        record.args = None
        if record.exc_info is not None and not record.exc_text:
            # Rendered here so the traceback is redacted too; the formatter
            # reuses `exc_text`. Line structure is preserved.
            exc_text = logging.Formatter().formatException(record.exc_info)
            record.exc_text = "\n".join(redact(line) for line in exc_text.splitlines())
        return True


def install_redaction_filter(logger: logging.Logger | None = None) -> RedactingFilter:
    """Install the filter on `logger` (the root logger by default) and its handlers.

    Both are needed: a logger's filters apply only to records logged through
    that logger, so a root filter alone misses records from child loggers.
    Idempotent, so repeated calls cannot stack duplicate filters.
    """
    target = logger if logger is not None else logging.getLogger()
    existing = _find_filter(target)
    if existing is None:
        existing = RedactingFilter()
        target.addFilter(existing)
    for handler in target.handlers:
        if _find_filter(handler) is None:
            handler.addFilter(existing)
    return existing


def _find_filter(target: Any) -> RedactingFilter | None:
    for candidate in target.filters:
        if isinstance(candidate, RedactingFilter):
            return candidate
    return None
