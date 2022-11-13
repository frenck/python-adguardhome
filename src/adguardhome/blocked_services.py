"""Asynchronous Python client for the AdGuard Home API."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import AdGuardHome


class AdGuardHomeBlockedServices:
    """Controls AdGuard Home blocked services.

    Blocks services like Spotify, Disney+, Netflix.
    """

    def __init__(self, adguard: AdGuardHome) -> None:
        """Initialize object.

        Args:
            adguard: The AdGuard Home instance.
        """
        self._adguard = adguard

    async def all_services(self) -> list:
        """Return a list of all possible services which can be blocked.

        Returns:
            A list of dictionaries of all the services
        """
        response = await self._adguard.request("blocked_services/all")
        return response["blocked_services"]

    async def set_blocked_services(self, services: list) -> None:
        """Block zero or more services in AdGuard Home.

        Args:
            services: A list of id that needs to be blocked. eg:
                ["spotify"] or [] if nothing needs to be blocked
        """

        await self._adguard.request(
            "blocked_services/set",
            method="POST",
            json_data=services,
        )

    async def list_currently_blocked(self) -> list:
        """Return a list of all currently blocked services.

        Returns:
            A list of dictionaries of all currently blocked services.
        """
        response = await self._adguard.request("blocked_services/list")
        return response
