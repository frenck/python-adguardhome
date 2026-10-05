"""Asynchronous Python client for the AdGuard Home API."""

from .access import AccessConfig
from .adguardhome import AdGuardHome
from .blocked_services import (
    AvailableServices,
    BlockedServicesConfig,
    DayRange,
    Schedule,
    Service,
    ServiceGroup,
)
from .clients import Client, Clients, ClientSearchResult, RuntimeClient
from .dhcp import (
    DhcpCheck,
    DhcpConfig,
    DhcpStatus,
    DhcpV4Check,
    DhcpV4Config,
    DhcpV6Check,
    DhcpV6Config,
    Lease,
    NetworkInterface,
    OtherDhcpServer,
    StaticIpCheck,
    StaticLease,
)
from .dns import BlockingMode, DnsConfig, UpstreamMode
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
from .querylog import (
    DnsAnswer,
    DnsQuestion,
    QueryLog,
    QueryLogClient,
    QueryLogConfig,
    QueryLogEntry,
)
from .rewrite import RewriteConfig, RewriteRule
from .safesearch import SafeSearchConfig
from .stats import Stats, StatsConfig, TimeUnit
from .status import MINIMUM_VERSION, Status
from .tls import TlsConfig, TlsStatus
from .update import AvailableUpdate

__all__ = [
    "MINIMUM_VERSION",
    "AccessConfig",
    "AdGuardHome",
    "AdGuardHomeAuthenticationError",
    "AdGuardHomeConnectionError",
    "AdGuardHomeConnectionTimeoutError",
    "AdGuardHomeError",
    "AdGuardHomeResponseError",
    "AdGuardHomeUnsupportedError",
    "AppliedRule",
    "AvailableServices",
    "AvailableUpdate",
    "BlockedServicesConfig",
    "BlockingMode",
    "Client",
    "ClientSearchResult",
    "Clients",
    "DayRange",
    "DhcpCheck",
    "DhcpConfig",
    "DhcpStatus",
    "DhcpV4Check",
    "DhcpV4Config",
    "DhcpV6Check",
    "DhcpV6Config",
    "DnsAnswer",
    "DnsConfig",
    "DnsQuestion",
    "FilterList",
    "FilteringConfig",
    "FilteringReason",
    "FilteringStatus",
    "HostCheck",
    "Lease",
    "NetworkInterface",
    "OtherDhcpServer",
    "QueryLog",
    "QueryLogClient",
    "QueryLogConfig",
    "QueryLogEntry",
    "RewriteConfig",
    "RewriteRule",
    "RuntimeClient",
    "SafeSearchConfig",
    "Schedule",
    "Service",
    "ServiceGroup",
    "StaticIpCheck",
    "StaticLease",
    "Stats",
    "StatsConfig",
    "Status",
    "TimeUnit",
    "TlsConfig",
    "TlsStatus",
    "UpstreamMode",
]
