"""Models for the AdGuard Home server status."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from awesomeversion import AwesomeVersion, AwesomeVersionStrategy
from mashumaro import field_options

from ._model import (
    AdGuardHomeModel,
    OptionalMillisecondsStrategy,
    UnixMillisecondsStrategy,
)

# The release that introduced the newest API this library relies on: the
# `client` and `qtype` options of checking a host. Client search arrived just
# before it, in v0.107.56.
MINIMUM_VERSION = AwesomeVersion("v0.107.58")


@dataclass(frozen=True, kw_only=True)
class Status(AdGuardHomeModel):
    """Status of the AdGuard Home server."""

    version: AwesomeVersion
    running: bool
    language: str
    dns_addresses: tuple[str, ...]
    dns_port: int
    http_port: int
    dhcp_available: bool = False

    protection_enabled: bool
    protection_resumes_in: timedelta | None = field(
        default=None,
        metadata=field_options(
            alias="protection_disabled_duration",
            serialization_strategy=OptionalMillisecondsStrategy(),
        ),
    )

    started_at: datetime | None = field(
        default=None,
        metadata=field_options(
            alias="start_time",
            serialization_strategy=UnixMillisecondsStrategy(),
        ),
    )

    @property
    def supported(self) -> bool:
        """Return if this library supports the AdGuard Home version.

        Development builds do not carry a release version. We cannot tell
        what they support, so we give them the benefit of the doubt.
        """
        if self.version.strategy == AwesomeVersionStrategy.UNKNOWN:
            return True

        return self.version >= MINIMUM_VERSION
