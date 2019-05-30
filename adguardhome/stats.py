# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeStats:
    """Provides stats of AdGuard Home."""

    def __init__(self, adguard):
        """Initialize object."""
        self._adguard = adguard

    async def dns_queries(self) -> int:
        """Return number of DNS queries."""
        response = await self._adguard._request("stats")
        return response["dns_queries"]

    async def blocked_filtering(self) -> int:
        """Return number of blocked DNS queries."""
        response = await self._adguard._request("stats")
        return response["blocked_filtering"]

    async def blocked_percentage(self) -> float:
        """Return the blocked percentage ratio of DNS queries."""
        response = await self._adguard._request("stats")
        return (response["blocked_filtering"] / response["dns_queries"]) * 100.0

    async def replaced_safebrowsing(self) -> int:
        """Return number of blocked pages by safe browsing."""
        response = await self._adguard._request("stats")
        return response["replaced_safebrowsing"]

    async def replaced_parental(self) -> int:
        """Return number of blocked pages by parental control."""
        response = await self._adguard._request("stats")
        return response["replaced_parental"]

    async def replaced_safesearch(self) -> int:
        """Return number of enforced safe searches."""
        response = await self._adguard._request("stats")
        return response["replaced_safesearch"]

    async def avg_processing_time(self) -> float:
        """Return avarage processing time of DNS queries (in ms)."""
        response = await self._adguard._request("stats")
        return response["avg_processing_time"]

    async def period(self) -> str:
        """Return the period the stats currently represent."""
        response = await self._adguard._request("stats")
        return response["stats_period"]

    async def reset(self) -> bool:
        """Reset all stats."""
        response = await self._adguard._request("stats_reset", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Resetting AdGuard Home stats failed", {"response": response}
            )
        return True
