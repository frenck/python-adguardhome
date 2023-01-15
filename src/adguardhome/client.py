"""Interacting with AdGuardHome clients"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Mapping

if TYPE_CHECKING:
    from adguardhome.adguardhome import AdGuardHome


@dataclass
class WhoisInfo:
    """Not described in the OpenAPI docs."""

    type: str


@dataclass
class AutoClient:
    """Automatically discovered AdGuardHome client."""

    ip: str
    name: str
    source: str
    whois_info: WhoisInfo | None


@dataclass
class Client:
    """Administratively managed AdGuardHome client."""

    name: str
    ids: list[str]
    use_global_settings: bool
    filtering_enabled: bool
    parental_enabled: bool
    safebrowsing_enabled: bool
    safesearch_enabled: bool
    use_global_blocked_services: bool
    blocked_services: list[str] | None
    upstreams: list[str]
    tags: list[str]


class Clients:
    """A resource facade for the /clients API on AdGuardHome"""

    def __init__(self, adguard: AdGuardHome):
        self.adguard = adguard

    async def request(
        self,
        uri: str,
        method: str = "GET",
        data: Any | None = None,
        json_data: dict | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return await self.adguard.request(
            f"clients{uri}",
            method=method,
            data=data,
            json_data=json_data,
            params=params,
        )

    async def get_auto_clients(self) -> list[Any]:
        """List the AutoClients detected by the AdGuardHome instance.

        Returns:
            A List of `AutoClient` objects corresponding to the /clients['auto_clients']
            API response.
        """

        def _make_auto_client(raw: dict[str, Any]) -> AutoClient:
            wi = (
                WhoisInfo(type=raw["whois_info"]["type"])
                if "whois_info" in raw and raw["whois_info"]
                else None
            )
            return AutoClient(
                ip=raw["ip"], name=raw["name"], source=raw["source"], whois_info=wi
            )

        raw_auto_clients = (await self.request("", method="GET"))["auto_clients"]
        return [_make_auto_client(a) for a in raw_auto_clients]

    async def get_clients(self) -> list[Any]:
        """List the Clients configured on the AdGuardHome instance.

        These clients are mutable and can be updated by this API.

        Returns:
            A List of `Client` objects corresponding to the /clients['clients']
            API response.
        """

        def _make_client(raw: dict[str, Any]) -> Client:
            return Client(
                name=raw["name"],
                ids=raw["ids"],
                use_global_settings=raw["use_global_settings"],
                filtering_enabled=raw["filtering_enabled"],
                parental_enabled=raw["parental_enabled"],
                safebrowsing_enabled=raw["safebrowsing_enabled"],
                safesearch_enabled=raw["safesearch_enabled"],
                use_global_blocked_services=raw["use_global_blocked_services"],
                blocked_services=raw["blocked_services"],
                upstreams=raw["upstreams"],
                tags=raw["tags"],
            )

        return [
            _make_client(c) for c in (await self.request("", method="GET"))["clients"]
        ]

    async def get_supported_tags(self) -> list[Any]:
        """List supported tags for Clients"""
        return (await self.request("", method="GET"))["supported_tags"]
