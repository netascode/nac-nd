"""Connection settings, sourced from CLI options with `.env` behind them."""

from __future__ import annotations

from dataclasses import dataclass, field

from nac_nd.exceptions import InputError

# The login endpoint rejects a missing or empty `domain` with HTTP 500, so
# there is always a value here.
DEFAULT_DOMAIN = "DefaultAuth"


def normalise_host(host: str) -> str:
    """Strip any URL scheme and trailing slashes from a host.

    A host carrying its own scheme would produce `https://https://...`.
    """
    value = host.strip()
    lowered = value.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            value = value[len(scheme) :]
            break
    return value.rstrip("/")


@dataclass
class Config:
    """Everything needed to reach one Nexus Dashboard."""

    host: str
    username: str
    # Kept out of the generated __repr__, which reaches debuggers, log lines
    # and exception renderings.
    password: str = field(repr=False)
    domain: str = DEFAULT_DOMAIN
    fabric: str = ""
    verify_ssl: bool = True
    ca_bundle: str | None = None
    request_timeout_seconds: float = 60.0
    poll_interval_seconds: int = 15
    job_timeout_minutes: int = 30

    def __post_init__(self) -> None:
        self.host = normalise_host(self.host)
        if not self.host:
            raise InputError("Nexus Dashboard host is required (--host or ND_HOST).")
        if not self.username:
            raise InputError("Username is required (--username or ND_USER).")
        if not self.password:
            raise InputError("Password is required (ND_PASSWORD).")
        if not self.domain:
            # The API answers an empty domain with HTTP 500, so it is caught
            # here instead.
            raise InputError(
                "Login domain is required and cannot be empty "
                f"(--domain or ND_DOMAIN; try '{DEFAULT_DOMAIN}')."
            )
        if self.poll_interval_seconds < 1:
            raise InputError("--poll-interval must be at least 1 second.")
        if self.job_timeout_minutes < 1:
            raise InputError("--timeout must be at least 1 minute.")

    @property
    def base_url(self) -> str:
        return f"https://{self.host}"

    @property
    def prechange_ui_url(self) -> str:
        """Nexus Dashboard Pre-Change Analysis page (same as nexus-pcv --output-url)."""
        return (
            f"{self.base_url}/appcenter/cisco/nexus-insights/ui/"
            "#/changeManagement/preChangeAnalysis"
        )
