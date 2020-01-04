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
        return response["num_dns_queries"]

    async def blocked_filtering(self) -> int:
        """Return number of blocked DNS queries."""
        response = await self._adguard._request("stats")
        return response["num_blocked_filtering"]

    async def blocked_percentage(self) -> float:
        """Return the blocked percentage ratio of DNS queries."""
        response = await self._adguard._request("stats")
        if not response["num_dns_queries"]:
            return 0.0
        return (response["num_blocked_filtering"] / response["num_dns_queries"]) * 100.0

    async def replaced_safebrowsing(self) -> int:
        """Return number of blocked pages by safe browsing."""
        response = await self._adguard._request("stats")
        return response["num_replaced_safebrowsing"]

    async def replaced_parental(self) -> int:
        """Return number of blocked pages by parental control."""
        response = await self._adguard._request("stats")
        return response["num_replaced_parental"]

    async def replaced_safesearch(self) -> int:
        """Return number of enforced safe searches."""
        response = await self._adguard._request("stats")
        return response["num_replaced_safesearch"]

    async def avg_processing_time(self) -> float:
        """Return avarage processing time of DNS queries (in ms)."""
        response = await self._adguard._request("stats")
        return round(response["avg_processing_time"] * 100, 2)

    async def period(self) -> int:
        """Return the time period to keep data (in days)."""
        response = await self._adguard._request("stats_info")
        return response["interval"]

    async def reset(self) -> None:
        """Reset all stats."""
        response = await self._adguard._request("stats_reset", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Resetting AdGuard Home stats failed", {"response": response}
            )
