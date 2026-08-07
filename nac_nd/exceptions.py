"""Typed errors, each carrying the process exit code it should produce.

Exit codes are a contract with CI, so they live on the exception rather than
being chosen at the call site.
"""

from __future__ import annotations


class NacNdError(Exception):
    """Base error. Anything unclassified exits 1."""

    exit_code: int = 1


class JobError(NacNdError):
    """An analysis job failed, stopped, vanished or timed out."""

    exit_code = 2


class AnomalyThresholdError(NacNdError):
    """New anomalies were found at a severity the caller chose to fail on."""

    exit_code = 3


class InputError(NacNdError):
    """Bad arguments, bad configuration or an unusable input file."""

    exit_code = 4


class AuthError(NacNdError):
    """Authentication or authorisation against Nexus Dashboard failed."""

    exit_code = 5


class ApiError(NacNdError):
    """Nexus Dashboard answered a request with an unexpected status."""

    exit_code = 1
