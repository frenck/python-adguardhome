"""Asynchronous Python client for the AdGuard Home API."""
from __future__ import annotations
from http import client

from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


class AdGuardHomeClients:
    """AdGuard Home client level controls."""

    def __init__(self, adguard: AdGuardHome) -> None:
        """Initialize object.

        Args:
            adguard: The AdGuard Home instance.
        """
        self._adguard = adguard

    async def getClients(self) -> list[dict]:
        """Return a list of configured clients.

        Returns:
            The list of configured clients from AdGuard Home.
        """
        response = await self._adguard.request("clients")
        return response["clients"]

    async def getClient(self, clientName: str) -> dict:
        """Return the requested client configuration or None.

        Returns:
            The requested client configuration from AdGuard Home.
        """
        clients = await self.getClients()
        client_settings = next((client for client in clients if client['name'] == clientName), None)
        return client_settings

    async def updateClient(self, clientName: str, **kwargs) -> None:
        """Update client settings by overwriting the current settings with arguments provided.

        Raises:
            AdGuardHomeError: If updating client settings failed.
        """
        try:
            client_settings = await self.getClient(clientName)
            for k, v in kwargs.items():
                client_settings[k] = v

            data = {
                "name": clientName,
                "data": client_settings
            }

            await self._adguard.request(
                "clients/update", method="POST", json_data=data
            )
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Enabling AdGuard Home parental control failed"
            ) from exception

    async def setClientFiltering(self, clientName: str, filtering_enabled: bool) -> None:
        """Update client filtering settings.

        Raises:
            AdGuardHomeError: If updating client settings failed.
        """
        try:
            await self.updateClient(clientName, filtering_enabled=filtering_enabled)
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Enabling AdGuard Home parental control failed"
            ) from exception

    async def setClientParental(self, clientName: str, parental_enabled: bool) -> None:
        """Update client parental settings.

        Raises:
            AdGuardHomeError: If updating client settings failed.
        """
        try:
            await self.updateClient(clientName, parental_enabled=parental_enabled)
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Enabling AdGuard Home parental control failed"
            ) from exception
