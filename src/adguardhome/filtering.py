"""Filtering of AdGuard Home: filter lists, user rules, and host checks."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from mashumaro import field_options

from ._area import Area, Requester
from ._model import AdGuardHomeModel, HoursStrategy
from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True, kw_only=True)
class FilterList(AdGuardHomeModel):
    """A filter list subscription, either a blocklist or an allowlist."""

    id: int
    name: str
    url: str
    enabled: bool
    rules_count: int
    last_updated: datetime | None = None


@dataclass(frozen=True, kw_only=True)
class FilteringConfig(AdGuardHomeModel):
    """Configuration of AdGuard Home filtering."""

    enabled: bool

    # How often AdGuard Home updates the filter lists. AdGuard Home only
    # accepts 0 (never), 1, 12, 24, 72, or 168 hours.
    update_interval: timedelta = field(
        metadata=field_options(alias="interval", serialization_strategy=HoursStrategy())
    )


@dataclass(frozen=True, kw_only=True)
class FilteringStatus(FilteringConfig):
    """Configuration and filter lists of AdGuard Home filtering."""

    blocklists: tuple[FilterList, ...] = field(
        default=(), metadata=field_options(alias="filters")
    )
    allowlists: tuple[FilterList, ...] = field(
        default=(), metadata=field_options(alias="whitelist_filters")
    )
    user_rules: tuple[str, ...] = ()


class FilteringReason(StrEnum):
    """Reason AdGuard Home filtered, or did not filter, a host."""

    NOT_FILTERED_NOT_FOUND = "NotFilteredNotFound"
    NOT_FILTERED_ALLOWLIST = "NotFilteredWhiteList"
    NOT_FILTERED_ERROR = "NotFilteredError"
    FILTERED_BLOCKLIST = "FilteredBlackList"
    FILTERED_SAFEBROWSING = "FilteredSafeBrowsing"
    FILTERED_PARENTAL = "FilteredParental"
    FILTERED_INVALID = "FilteredInvalid"
    FILTERED_SAFESEARCH = "FilteredSafeSearch"
    FILTERED_BLOCKED_SERVICE = "FilteredBlockedService"
    REWRITE = "Rewrite"
    REWRITE_ETC_HOSTS = "RewriteEtcHosts"
    REWRITE_RULE = "RewriteRule"


@dataclass(frozen=True, kw_only=True)
class AppliedRule(AdGuardHomeModel):
    """A filtering rule AdGuard Home applied to a host."""

    text: str
    filter_list_id: int


@dataclass(frozen=True, kw_only=True)
class HostCheck(AdGuardHomeModel):
    """Result of checking how AdGuard Home filters a host."""

    reason: FilteringReason
    rules: tuple[AppliedRule, ...] = ()
    service_name: str | None = None
    cname: str | None = None
    ip_addresses: tuple[str, ...] = field(
        default=(), metadata=field_options(alias="ip_addrs")
    )

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop empty strings, which AdGuard Home sends for "not set"."""
        d = super().__pre_deserialize__(d)
        return {key: value for key, value in d.items() if value != ""}

    @property
    def filtered(self) -> bool:
        """Return if AdGuard Home filters the host."""
        return self.reason.startswith("Filtered")


class FilterLists(Area):
    """The blocklists or the allowlists of AdGuard Home.

    Both kinds of filter list work the same; the API tells them apart with
    a `whitelist` flag on every request. A filter list is identified by its
    URL, which AdGuard Home matches exactly.
    """

    __slots__ = ("_allowlist",)

    def __init__(self, request: Requester, *, allowlist: bool) -> None:
        """Initialize the filter lists.

        Args:
        ----
            request: The request method of the AdGuard Home client.
            allowlist: True for the allowlists, False for the blocklists.

        """
        super().__init__(request)
        self._allowlist = allowlist

    async def list(self) -> tuple[FilterList, ...]:
        """Return all filter lists of this kind.

        Returns
        -------
            The filter lists, in the order AdGuard Home has them.

        """
        status = FilteringStatus.from_api(await self._request("filtering/status"))
        return status.allowlists if self._allowlist else status.blocklists

    async def get(self, url: str) -> FilterList | None:
        """Return the filter list with the given URL.

        Args:
        ----
            url: The URL of the filter list.

        Returns:
        -------
            The filter list, or None if there is no filter list with this URL.

        """
        return next(
            (
                filter_list
                for filter_list in await self.list()
                if filter_list.url == url
            ),
            None,
        )

    async def add(self, url: str, *, name: str) -> None:
        """Add a filter list.

        Args:
        ----
            url: The URL of the filter list, or an absolute path to a file
                on the AdGuard Home server.
            name: The name to show for the filter list.

        """
        await self._request(
            "filtering/add_url",
            method="POST",
            json={"name": name, "url": url, "whitelist": self._allowlist},
        )

    async def remove(self, url: str) -> None:
        """Remove a filter list.

        Args:
        ----
            url: The URL of the filter list to remove.

        """
        await self._request(
            "filtering/remove_url",
            method="POST",
            json={"url": url, "whitelist": self._allowlist},
        )

    async def update(
        self,
        url: str,
        *,
        name: str | None = None,
        new_url: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        """Change a filter list. Leave out what should stay the same.

        Args:
        ----
            url: The current URL of the filter list.
            name: The new name of the filter list.
            new_url: The new URL of the filter list.
            enabled: True to enable the filter list, False to disable it.

        Raises:
        ------
            AdGuardHomeError: There is no filter list with this URL.

        """
        # AdGuard Home replaces the name, URL, and enabled state all at once,
        # so we need the current filter list to keep what does not change.
        current = await self.get(url)
        if current is None:
            kind = "allowlist" if self._allowlist else "blocklist"
            msg = f"AdGuard Home has no {kind} with URL {url}"
            raise AdGuardHomeError(msg)

        await self._request(
            "filtering/set_url",
            method="POST",
            json={
                "url": url,
                "whitelist": self._allowlist,
                "data": {
                    "name": current.name if name is None else name,
                    "url": current.url if new_url is None else new_url,
                    "enabled": current.enabled if enabled is None else enabled,
                },
            },
        )

    async def enable(self, url: str) -> None:
        """Enable a filter list.

        Args:
        ----
            url: The URL of the filter list to enable.

        """
        await self.update(url, enabled=True)

    async def disable(self, url: str) -> None:
        """Disable a filter list.

        Args:
        ----
            url: The URL of the filter list to disable.

        """
        await self.update(url, enabled=False)

    async def refresh(self) -> int:
        """Download the latest version of all filter lists of this kind.

        Returns
        -------
            The number of filter lists that changed.

        """
        response = await self._request(
            "filtering/refresh",
            method="POST",
            json={"whitelist": self._allowlist},
        )

        try:
            return int(response["updated"])
        except (KeyError, TypeError, ValueError) as exception:
            msg = "Unexpected refresh response from AdGuard Home"
            raise AdGuardHomeError(msg) from exception


class AdGuardHomeFiltering(Area):
    """Filtering of AdGuard Home: filter lists, user rules, and host checks."""

    __slots__ = ("allowlists", "blocklists")

    def __init__(self, request: Requester) -> None:
        """Initialize filtering.

        Args:
        ----
            request: The request method of the AdGuard Home client.

        """
        super().__init__(request)
        self.blocklists = FilterLists(request, allowlist=False)
        self.allowlists = FilterLists(request, allowlist=True)

    async def get(self) -> FilteringStatus:
        """Return the configuration and filter lists of filtering.

        Returns
        -------
            The filtering configuration, filter lists, and user rules.

        """
        return FilteringStatus.from_api(await self._request("filtering/status"))

    async def config(self) -> FilteringConfig:
        """Return the configuration of filtering.

        Returns
        -------
            The current configuration of filtering.

        """
        return FilteringConfig.from_api(await self._request("filtering/status"))

    async def set_config(self, config: FilteringConfig) -> None:
        """Replace the configuration of filtering.

        Args:
        ----
            config: The new configuration of filtering.

        """
        # Only send the configuration, also when given a full FilteringStatus.
        payload = FilteringConfig(
            enabled=config.enabled, update_interval=config.update_interval
        )
        await self._request("filtering/config", method="POST", json=payload.to_dict())

    async def enable(self) -> None:
        """Enable filtering."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Disable filtering."""
        await self.set_config(replace(await self.config(), enabled=False))

    async def user_rules(self) -> tuple[str, ...]:
        """Return the custom filtering rules.

        Returns
        -------
            The custom filtering rules, including comments.

        """
        return (await self.get()).user_rules

    async def set_user_rules(self, rules: Iterable[str]) -> None:
        """Replace the custom filtering rules.

        Args:
        ----
            rules: The new custom filtering rules, one rule per item.

        """
        await self._request(
            "filtering/set_rules", method="POST", json={"rules": list(rules)}
        )

    async def check_host(
        self,
        name: str,
        *,
        client: str | None = None,
        qtype: str | None = None,
    ) -> HostCheck:
        """Check how AdGuard Home filters a host.

        Args:
        ----
            name: The host name to check, like `example.com`.
            client: Check for this client (IP address or name), which
                matters when a client has its own settings.
            qtype: Check for this DNS record type, like `AAAA`.

        Returns:
        -------
            Whether, how, and by which rules the host is filtered.

        """
        params = {"name": name}
        if client is not None:
            params["client"] = client
        if qtype is not None:
            params["qtype"] = qtype

        return HostCheck.from_api(
            await self._request("filtering/check_host", params=params)
        )
