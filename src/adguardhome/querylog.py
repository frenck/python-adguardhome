"""Query log of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from mashumaro import field_options
from mashumaro.types import SerializationStrategy

from ._area import Area
from ._model import AdGuardHomeModel, MillisecondsStrategy, SecondsStrategy
from .filtering import AppliedRule, FilteringReason


class MillisecondsStringStrategy(SerializationStrategy):
    """Convert a duration in milliseconds, sent as a string, to a timedelta."""

    def serialize(self, value: timedelta) -> str:
        """Serialize to milliseconds, as a string."""
        return str(value.total_seconds() * 1000)

    def deserialize(self, value: str) -> timedelta:
        """Deserialize from milliseconds, sent as a string."""
        return timedelta(milliseconds=float(value))


@dataclass(frozen=True, kw_only=True)
class DnsQuestion(AdGuardHomeModel):
    """The question of a DNS query."""

    name: str
    type: str
    dns_class: str = field(metadata=field_options(alias="class"))

    # The name in Unicode, only when it differs from `name`, like for an
    # internationalized domain name.
    unicode_name: str | None = None


@dataclass(frozen=True, kw_only=True)
class DnsAnswer(AdGuardHomeModel):
    """A record in the answer to a DNS query."""

    type: str
    value: str
    ttl: timedelta = field(
        metadata=field_options(serialization_strategy=SecondsStrategy())
    )


@dataclass(frozen=True, kw_only=True)
class QueryLogClient(AdGuardHomeModel):
    """What AdGuard Home knows about the client that sent a DNS query."""

    name: str = ""
    whois: dict[str, str] = field(default_factory=dict)
    disallowed: bool = False

    # The access rule that disallows the client. Empty while disallowed
    # means the client is missing from the list of allowed clients.
    disallowed_rule: str = ""


@dataclass(frozen=True, kw_only=True)
class QueryLogEntry(AdGuardHomeModel):
    """A DNS query in the query log, and how AdGuard Home handled it."""

    time: datetime
    question: DnsQuestion

    # The IP address of the client, which AdGuard Home may have anonymized.
    client_ip: str = field(metadata=field_options(alias="client"))
    client_id: str | None = None
    client_info: QueryLogClient | None = None

    # The encrypted protocol the query came in over, like `doh` or `dot`.
    # None means plain DNS.
    client_proto: str | None = None

    # The EDNS Client Subnet of the query, if it had one.
    ecs: str | None = None

    reason: FilteringReason
    rules: tuple[AppliedRule, ...] = ()
    service_name: str | None = None

    # The DNS response code, like `NOERROR` or `NXDOMAIN`.
    status: str | None = None
    answer: tuple[DnsAnswer, ...] = ()

    # The answer of the upstream, when AdGuard Home changed it.
    original_answer: tuple[DnsAnswer, ...] = ()
    answer_dnssec: bool = False
    upstream: str | None = None
    cached: bool = False
    elapsed: timedelta = field(
        metadata=field_options(
            alias="elapsedMs", serialization_strategy=MillisecondsStringStrategy()
        )
    )

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop empty strings, which AdGuard Home sends for "not set"."""
        d = super().__pre_deserialize__(d)
        return {key: value for key, value in d.items() if value != ""}

    @property
    def filtered(self) -> bool:
        """Return if AdGuard Home filtered the query."""
        return self.reason.startswith("Filtered")


@dataclass(frozen=True, kw_only=True)
class QueryLog(AdGuardHomeModel):
    """A page of the query log, newest entry first."""

    entries: tuple[QueryLogEntry, ...] = field(
        default=(), metadata=field_options(alias="data")
    )

    # The time of the oldest entry on this page. Pass it as `older_than` to
    # get the next page. None when the page is empty.
    oldest: datetime | None = None

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop an empty `oldest`, which AdGuard Home sends for no entries."""
        d = super().__pre_deserialize__(d)
        return {key: value for key, value in d.items() if value != ""}


@dataclass(frozen=True, kw_only=True)
class QueryLogConfig(AdGuardHomeModel):
    """Configuration of the AdGuard Home query log."""

    enabled: bool
    retention: timedelta = field(
        metadata=field_options(
            alias="interval", serialization_strategy=MillisecondsStrategy()
        )
    )
    anonymize_client_ip: bool
    ignored: tuple[str, ...] = ()

    # Added in AdGuard Home v0.107.72. Older versions leave it out, and
    # AdGuard Home treats it as enabled when the ignored list is not empty.
    ignored_enabled: bool | None = None


class AdGuardHomeQueryLog(Area):
    """Query log of AdGuard Home."""

    __slots__ = ()

    async def get(
        self,
        *,
        search: str | None = None,
        limit: int | None = None,
        older_than: datetime | None = None,
    ) -> QueryLog:
        """Return a page of the query log, newest entry first.

        Args:
        ----
            search: Only return queries for this domain name or client.
            limit: The maximum number of entries to return. AdGuard Home
                picks a default when left out.
            older_than: Only return entries older than this. Pass the
                `oldest` of a page to get the next page.

        Returns:
        -------
            The entries, and the time of the oldest one to continue from.

        """
        params: dict[str, str] = {}
        if search is not None:
            params["search"] = search
        if limit is not None:
            params["limit"] = str(limit)
        if older_than is not None:
            params["older_than"] = older_than.isoformat()

        return QueryLog.from_api(await self._request("querylog", params=params))

    async def config(self) -> QueryLogConfig:
        """Return the configuration of the query log.

        Returns
        -------
            The current configuration of the query log.

        """
        return QueryLogConfig.from_api(await self._request("querylog/config"))

    async def set_config(self, config: QueryLogConfig) -> None:
        """Replace the configuration of the query log.

        Use `dataclasses.replace` on the result of `config()` to change
        only part of it.

        Args:
        ----
            config: The new configuration of the query log.

        """
        await self._request(
            "querylog/config/update", method="PUT", json=config.to_dict()
        )

    async def enable(self) -> None:
        """Enable the query log."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Disable the query log."""
        await self.set_config(replace(await self.config(), enabled=False))

    async def clear(self) -> None:
        """Remove all entries from the query log."""
        await self._request("querylog_clear", method="POST")
