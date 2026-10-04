"""Asynchronous Python client for the AdGuard Home API."""

from .adguardhome import AdGuardHome
from .clients import (
    Client,
    Clients,
    ClientSearchResult,
    DayRange,
    RuntimeClient,
    Schedule,
)
from .exceptions import (
    AdGuardHomeAuthenticationError,
    AdGuardHomeConnectionError,
    AdGuardHomeConnectionTimeoutError,
    AdGuardHomeError,
    AdGuardHomeResponseError,
    AdGuardHomeUnsupportedError,
)
from .filtering import (
    AppliedRule,
    FilteringConfig,
    FilteringReason,
    FilteringStatus,
    FilterList,
    HostCheck,
)
from .querylog import QueryLogConfig
from .rewrite import RewriteRule
from .safesearch import SafeSearchConfig
from .stats import Stats, StatsConfig, TimeUnit
from .status import MINIMUM_VERSION, Status
from .update import AvailableUpdate

__all__ = [
    "MINIMUM_VERSION",
    "AdGuardHome",
    "AdGuardHomeAuthenticationError",
    "AdGuardHomeConnectionError",
    "AdGuardHomeConnectionTimeoutError",
    "AdGuardHomeError",
    "AdGuardHomeResponseError",
    "AdGuardHomeUnsupportedError",
    "AppliedRule",
    "AvailableUpdate",
    "Client",
    "ClientSearchResult",
    "Clients",
    "DayRange",
    "FilterList",
    "FilteringConfig",
    "FilteringReason",
    "FilteringStatus",
    "HostCheck",
    "QueryLogConfig",
    "RewriteRule",
    "RuntimeClient",
    "SafeSearchConfig",
    "Schedule",
    "Stats",
    "StatsConfig",
    "Status",
    "TimeUnit",
]
