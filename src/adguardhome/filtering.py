"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeFiltering:
    """Controls AdGuard Home filtering. Blocks domains."""

    adguard: AdGuardHome

    async def _config(
        self, *, enabled: bool | None = None, interval: int | None = None
    ) -> None:
        """Configure filtering on AdGuard Home.

        Args:
        ----
            enabled: Enable/Disable AdGuard Home filtering.
            interval: Number of days to keep data in the logs.

        """
        if enabled is None:
            enabled = await self.enabled()
        if interval is None:
            interval = await self.interval()

        await self.adguard.request(
            "filtering/config",
            method="POST",
            json_data={"enabled": enabled, "interval": interval},
        )

    async def enabled(self) -> bool:
        """Return if AdGuard Home filtering is enabled or not.

        Returns
        -------
            The current state of the AdGuard Home filtering.

        """
        response = await self.adguard.request("filtering/status")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home filtering.

        Raises
        ------
            AdGuardHomeError: If enabling the filtering didn't succeed.

        """
        try:
            await self._config(enabled=True)
        except AdGuardHomeError as exception:
            msg = "Enabling AdGuard Home filtering failed"
            raise AdGuardHomeError(msg) from exception

    async def disable(self) -> None:
        """Disable AdGuard Home filtering.

        Raises
        ------
            AdGuardHomeError: If disabling the filtering didn't succeed.

        """
        try:
            await self._config(enabled=False)
        except AdGuardHomeError as exception:
            msg = "Disabling AdGuard Home filtering failed"
            raise AdGuardHomeError(msg) from exception

    async def interval(self, *, interval: int | None = None) -> int:
        """Return or set the time period to keep query log data.

        Args:
        ----
            interval: Set the time period (in days) to keep query log data.

        Returns:
        -------
            The current set time period to keep query log data.

        """
        if interval:
            await self._config(interval=interval)
            return interval

        response = await self.adguard.request("filtering/status")
        return response["interval"]

    async def rules_count(self, *, allowlist: bool) -> int:
        """Return the number of rules loaded.

        Args:
        ----
            allowlist: True to get the allowlists count, False for the blocklists.

        Returns:
        -------
            The number of filtering rules currently loaded in the AdGuard
            Home instance.

        """
        response = await self.adguard.request("filtering/status")

        count = "whitelist_filters" if allowlist else "filters"
        if not response.get(count):
            return 0

        return sum(fil["rules_count"] for fil in response[count])

    async def add_url(self, *, allowlist: bool, name: str, url: str) -> None:
        """Add a new filter subscription to AdGuard Home.

        Args:
        ----
            allowlist: True to add an allowlist, False for a blocklists.
            name: The name of the filter subscription.
            url: The URL of the filter list.

        Raises:
        ------
            AdGuardHomeError: Failed adding the filter subscription.

        """
        try:
            await self.adguard.request(
                "filtering/add_url",
                method="POST",
                json_data={"whitelist": allowlist, "name": name, "url": url},
            )
        except AdGuardHomeError as exception:
            msg = "Failed adding URL to AdGuard Home filter"
            raise AdGuardHomeError(msg) from exception

    async def remove_url(self, *, allowlist: bool, url: str) -> None:
        """Remove a new filter subscription from AdGuard Home.

        Args:
        ----
            allowlist: True to remove an allowlist, False for a blocklists.
            url: Filter subscription URL to remove from AdGuard Home.

        Raises:
        ------
            AdGuardHomeError: Failed removing the filter subscription.

        """
        try:
            await self.adguard.request(
                "filtering/remove_url",
                method="POST",
                json_data={"whitelist": allowlist, "url": url},
            )
        except AdGuardHomeError as exception:
            msg = "Failed removing URL from AdGuard Home filter"
            raise AdGuardHomeError(msg) from exception

    async def enable_url(self, *, allowlist: bool, url: str) -> None:
        """Enable a filter subscription in AdGuard Home.

        Args:
        ----
            allowlist: True to enable an allowlist, False for a blocklists.
            url: Filter subscription URL to enable on AdGuard Home.

        Raises:
        ------
            AdGuardHomeError: Failed enabling filter subscription.

        """
        response = await self.adguard.request("filtering/status")
        filter_type = "whitelist_filters" if allowlist else "filters"

        # Excluded from coverage:
        # https://github.com/nedbat/coveragepy/issues/515
        name = next(  # pragma: no cover
            (
                fil["name"]
                for fil in response[filter_type]
                if fil["url"].lower() == url.lower()
            ),
            "Unknown",
        )

        try:
            await self.adguard.request(
                "filtering/set_url",
                method="POST",
                json_data={
                    "url": url,
                    "whitelist": allowlist,
                    "data": {"enabled": True, "name": name, "url": url},
                },
            )
        except AdGuardHomeError as exception:
            msg = "Failed enabling URL on AdGuard Home filter"
            raise AdGuardHomeError(msg) from exception

    async def disable_url(self, *, allowlist: bool, url: str) -> None:
        """Disable a filter subscription in AdGuard Home.

        Args:
        ----
            url: Filter subscription URL to disable on AdGuard Home.
            allowlist: True to update the allowlists, False for the blocklists.

        Raises:
        ------
            AdGuardHomeError: Failed disabling filter subscription.

        """
        response = await self.adguard.request("filtering/status")
        filter_type = "whitelist_filters" if allowlist else "filters"

        # Excluded from coverage:
        # https://github.com/nedbat/coveragepy/issues/515
        name = next(  # pragma: no cover
            (
                fil["name"]
                for fil in response[filter_type]
                if fil["url"].lower() == url.lower()
            ),
            "Unknown",
        )

        try:
            await self.adguard.request(
                "filtering/set_url",
                method="POST",
                json_data={
                    "url": url,
                    "whitelist": allowlist,
                    "data": {"enabled": False, "name": name, "url": url},
                },
            )
        except AdGuardHomeError as exception:
            msg = "Failed disabling URL on AdGuard Home filter"
            raise AdGuardHomeError(msg) from exception

    async def url_enabled(self, *, allowlist: bool, url: str) -> bool:
        """Check if a filter subscription is enabled in AdGuard Home.

        Args:
        ----
            allowlist: True to check an allowlist, False for a blocklists.
            url: Filter subscription URL to check on AdGuard Home.

        Returns:
        -------
            True if the filter subscription is enabled, False otherwise.

        """
        response = await self.adguard.request("filtering/status")
        filter_type = "whitelist_filters" if allowlist else "filters"
        filters = response.get(filter_type) or []

        return next(
            (fil["enabled"] for fil in filters if fil["url"].lower() == url.lower()),
            False,
        )

    async def refresh(self, *, allowlist: bool, force: bool = False) -> None:
        """Reload filtering subscriptions from URLs specified in AdGuard Home.

        Args:
        ----
            force: Force the reload of all filter subscriptions.
            allowlist: True to update the allowlists, False for the blocklists.

        Raises:
        ------
            AdGuardHomeError: Failed to refresh filter subscriptions.

        """
        force_value = "true" if force else "false"

        try:
            await self.adguard.request(
                "filtering/refresh",
                method="POST",
                json_data={"whitelist": allowlist},
                params={"force": force_value},
            )
        except AdGuardHomeError as exception:
            msg = "Failed refreshing filter URLs in AdGuard Home"
            raise AdGuardHomeError(msg) from exception
