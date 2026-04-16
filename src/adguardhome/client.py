"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AutoClient:
    """Automatically discovered AdGuard Home client."""

    ip_address: str
    name: str
    source: str
    whois_info: dict[str, str] | None = None


@dataclass
class Client:
    """Administratively managed AdGuard Home client."""

    name: str
    ids: list[str]
    use_global_settings: bool = True
    filtering_enabled: bool = False
    parental_enabled: bool = False
    safebrowsing_enabled: bool = False
    safesearch_enabled: bool = False
    use_global_blocked_services: bool = True
    blocked_services: list[str] | None = None
    upstreams: list[str] | None = None
    tags: list[str] | None = None
    ignore_querylog: bool = False
    ignore_statistics: bool = False
    upstreams_cache_enabled: bool = False
    upstreams_cache_size: int = 0


@dataclass
class AdGuardHomeClients:
    """Controls AdGuard Home client management."""

    adguard: AdGuardHome

    async def get_auto_clients(self) -> list[AutoClient]:
        """Return all automatically discovered clients.

        Returns
        -------
            A list of automatically discovered clients on the
            AdGuard Home instance.

        """
        response = await self.adguard.request("clients")
        return [
            AutoClient(
                ip_address=entry["ip"],
                name=entry["name"],
                source=entry["source"],
                whois_info=entry.get("whois_info"),
            )
            for entry in response.get("auto_clients", [])
        ]

    async def get_clients(self) -> list[Client]:
        """Return all administratively configured clients.

        Returns
        -------
            A list of configured clients on the AdGuard Home instance.

        """
        response = await self.adguard.request("clients")
        known = {f.name for f in fields(Client)}
        return [
            Client(**{k: v for k, v in entry.items() if k in known})
            for entry in response.get("clients", [])
        ]

    async def get_supported_tags(self) -> list[str]:
        """Return the list of supported client tags.

        Returns
        -------
            The supported tags for clients on the AdGuard Home instance.

        """
        response = await self.adguard.request("clients")
        return response.get("supported_tags", [])
