"""Asynchronous Python client for the AdGuard Home API."""
from __future__ import annotations
from http import client

from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome

class AdGuardHomeClient:
    """AdGuard Home client object."""
    
    def __init__(self, adguardClients: AdGuardHomeClients, name: str):
        self._adguardClients = adguardClients
        self._name = name

    async def getConfig(self) -> dict:
        return await self._adguardClients.getClientConfig(self._name)

    async def updateConfig(self, **kwargs) -> None:
        await self._adguardClients.updateClientConfig(self._name, **kwargs)


    async def getFiltering(self) -> bool:
        response = await self.getConfig()
        return response["filtering_enabled"]

    async def setFiltering(self, filtering_enabled: bool) -> None:
        await self.updateConfig(filtering_enabled=filtering_enabled)


    async def getParental(self) -> bool:
        response = await self.getConfig()
        return response["parental_enabled"]

    async def setParental(self, parental_enabled: bool) -> None:
        await self.updateConfig(parental_enabled=parental_enabled)


    async def getSafeBrowsing(self) -> bool:
        response = await self.getConfig()
        return response["safebrowsing_enabled"]

    async def setSafeBrowsing(self, safebrowsing_enabled: bool) -> None:
        await self.updateConfig(safebrowsing_enabled=safebrowsing_enabled)


    async def getSafeSearch(self) -> bool:
        response = await self.getConfig()
        return response["safesearch_enabled"]

    async def setSafeSearch(self, safesearch_enabled: bool) -> None:
        await self.updateConfig(self._name, safesearch_enabled=safesearch_enabled)


class AdGuardHomeClients:
    """AdGuard Home client level controls."""

    def __init__(self, adguard: AdGuardHome) -> None:
        """Initialize object.

        Args:
            adguard: The AdGuard Home instance.
        """
        self._adguard = adguard

    def getClient(self, clientName: str) -> AdGuardHomeClient:
        """Returns an interactable AdGuardHome client object

        Args:
            clientName: Name of the client
        """
        return AdGuardHomeClient(self, clientName)

    async def getValidClient(self, clientName: str) -> AdGuardHomeClient:
        """Returns an interactable AdGuardHome client object

        Args:
            clientName: Name of the client
        """
        if await self.getClientConfig(clientName) != None:
            return AdGuardHomeClient(self, clientName)
        else:
            return None

    async def getClientConfigs(self) -> list[dict]:
        """Return a list of configured clients.

        Returns:
            The list of configured clients from AdGuard Home.
        """
        response = await self._adguard.request("clients")
        return response["clients"]

    async def getClientNames(self) -> list[str]:
        """Return a list of client names.

        Returns:
            The list of configured client names from AdGuard Home.
        """
        response = await self._adguard.request("clients")
        names = [client["name"] for client in response["clients"]]
        return names

    async def getClientConfig(self, clientName: str) -> dict:
        """Return the requested client configuration or None.

        Args:
            clientName: Name of the client
        Returns:
            The requested client configuration from AdGuard Home.
        """
        clients = await self.getClientConfigs()
        client_config = next((client for client in clients if client['name'] == clientName), None)
        return client_config

    async def updateClientConfig(self, clientName: str, **kwargs) -> None:
        """Update client settings by overwriting the current settings with arguments provided.

        Raises:
            AdGuardHomeError: If updating client settings failed.
        """
        try:
            client_config = await self.getClientConfig(clientName)
            for k, v in kwargs.items():
                client_config[k] = v

            data = {
                "name": clientName,
                "data": client_config
            }

            await self._adguard.request(
                "clients/update", method="POST", json_data=data
            )
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                f"Updating AdGuard Home client settings ({kwargs.keys()}) failed"
            ) from exception
