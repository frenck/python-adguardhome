"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeStats:
    """Provides stats of AdGuard Home."""

    adguard: AdGuardHome

    async def dns_queries(self) -> int:
        """Return number of DNS queries.

        Returns
        -------
            The number of DNS queries performed by the AdGuard Home instance.

        """
        response = await self.adguard.request("stats")
        return response["num_dns_queries"]

    async def blocked_filtering(self) -> int:
        """Return number of blocked DNS queries.

        Returns
        -------
            The number of DNS queries blocked by the AdGuard Home instance.

        """
        response = await self.adguard.request("stats")
        return response["num_blocked_filtering"]

    async def blocked_percentage(self) -> float:
        """Return the blocked percentage ratio of DNS queries.

        Returns
        -------
            The percentage ratio of blocked DNS queries by the AdGuard Home
            instance.

        """
        response = await self.adguard.request("stats")
        if not response["num_dns_queries"]:
            return 0.0
        return (response["num_blocked_filtering"] / response["num_dns_queries"]) * 100.0

    async def replaced_safebrowsing(self) -> int:
        """Return number of blocked pages by safe browsing.

        Returns
        -------
            The number of times a page was blocked by the safe
            browsing feature of the AdGuard Home instance.

        """
        response = await self.adguard.request("stats")
        return response["num_replaced_safebrowsing"]

    async def replaced_parental(self) -> int:
        """Return number of blocked pages by parental control.

        Returns
        -------
            The number of times a page was blocked by the parental control
            feature of the AdGuard Home instance.

        """
        response = await self.adguard.request("stats")
        return response["num_replaced_parental"]

    async def replaced_safesearch(self) -> int:
        """Return number of enforced safe searches.

        Returns
        -------
            The number of times a safe search was enforced by the
            AdGuard Home instance.

        """
        response = await self.adguard.request("stats")
        return response["num_replaced_safesearch"]

    async def avg_processing_time(self) -> float:
        """Return average processing time of DNS queries (in ms).

        Returns
        -------
            The averages processing time (in milliseconds) of DNS queries
            as performed by the AdGuard Home instance.

        """
        response = await self.adguard.request("stats")
        return round(response["avg_processing_time"] * 1000, 2)

    async def period(self) -> int:
        """Return the time period to keep data (in days).

        Returns
        -------
            The time period of data this AdGuard Home instance keeps.

        """
        response = await self.adguard.request("stats_info")
        return response["interval"]

    async def reset(self) -> None:
        """Reset all stats.

        Raises
        ------
            AdGuardHomeError: Restting the AdGuard Home stats did not succeed.

        """
        try:
            await self.adguard.request("stats_reset", method="POST")
        except AdGuardHomeError as exception:
            msg = "Resetting AdGuard Home stats failed"
            raise AdGuardHomeError(msg) from exception
