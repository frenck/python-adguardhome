"""Clients of AdGuard Home: the configured ones, and the ones it found itself."""

from __future__ import annotations

from dataclasses import dataclass, field

from mashumaro import field_options

from ._area import Area
from ._model import AdGuardHomeModel
from .blocked_services import Schedule
from .exceptions import AdGuardHomeError
from .safesearch import SafeSearchConfig


@dataclass(frozen=True, kw_only=True)
class Client(AdGuardHomeModel):
    """A client configured in AdGuard Home, with its own settings."""

    name: str

    # IP addresses, CIDR ranges, MAC addresses, or ClientIDs of the client.
    ids: tuple[str, ...]
    tags: tuple[str, ...] = ()

    # When True, the client follows the global settings below instead.
    use_global_settings: bool = True
    filtering_enabled: bool = False
    parental_enabled: bool = False
    safebrowsing_enabled: bool = False
    safe_search: SafeSearchConfig = field(
        default_factory=lambda: SafeSearchConfig(enabled=False)
    )

    # When True, the client follows the globally blocked services instead.
    use_global_blocked_services: bool = True
    blocked_services: tuple[str, ...] = ()
    blocked_services_schedule: Schedule | None = None

    # Upstream DNS servers for this client. Empty uses the global ones.
    upstreams: tuple[str, ...] = ()
    upstreams_cache_enabled: bool = False
    upstreams_cache_size: int = 0

    ignore_querylog: bool = False
    ignore_statistics: bool = False


@dataclass(frozen=True, kw_only=True)
class ClientSearchResult(Client):
    """The settings AdGuard Home applies to a client, and if it may connect."""

    whois_info: dict[str, str] = field(default_factory=dict)
    disallowed: bool = False

    # The access rule that disallows the client. Empty while disallowed
    # means the client is missing from the list of allowed clients.
    disallowed_rule: str | None = None


@dataclass(frozen=True, kw_only=True)
class RuntimeClient(AdGuardHomeModel):
    """A client AdGuard Home found by itself, like through DHCP or rDNS."""

    ip_address: str = field(metadata=field_options(alias="ip"))
    name: str
    source: str
    whois_info: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Clients(AdGuardHomeModel):
    """All clients AdGuard Home knows about."""

    configured: tuple[Client, ...] = field(
        default=(), metadata=field_options(alias="clients")
    )
    runtime: tuple[RuntimeClient, ...] = field(
        default=(), metadata=field_options(alias="auto_clients")
    )
    supported_tags: tuple[str, ...] = ()


class AdGuardHomeClients(Area):
    """Clients of AdGuard Home: the configured ones, and the ones it found."""

    __slots__ = ()

    async def get(self) -> Clients:
        """Return all clients AdGuard Home knows about.

        Returns
        -------
            The configured clients, the runtime clients, and the tags a
            configured client can have.

        """
        return Clients.from_api(await self._request("clients"))

    async def add(self, client: Client) -> None:
        """Add a configured client.

        Args:
        ----
            client: The client to add. Its name must be unique.

        """
        await self._request("clients/add", method="POST", json=client.to_dict())

    async def update(self, name: str, client: Client) -> None:
        """Replace a configured client.

        Use `dataclasses.replace` on a client from `get()` to change only
        part of it.

        Args:
        ----
            name: The current name of the client to replace.
            client: The new client, which may have a new name.

        """
        await self._request(
            "clients/update",
            method="POST",
            json={"name": name, "data": client.to_dict()},
        )

    async def remove(self, name: str) -> None:
        """Remove a configured client.

        Args:
        ----
            name: The name of the client to remove.

        """
        await self._request("clients/delete", method="POST", json={"name": name})

    async def search(self, *ids: str) -> dict[str, ClientSearchResult]:
        """Return the settings AdGuard Home applies to the given clients.

        This works for any client, also those that are not configured.

        Args:
        ----
            ids: IP addresses, MAC addresses, or ClientIDs to look up.

        Returns:
        -------
            The result for each ID that AdGuard Home found.

        """
        response = await self._request(
            "clients/search",
            method="POST",
            json={"clients": [{"id": client_id} for client_id in ids]},
        )

        # AdGuard Home answers with a list of single-key objects, keyed by ID.
        try:
            return {
                client_id: ClientSearchResult.from_api(result)
                for entry in response or []
                for client_id, result in entry.items()
            }
        except (AttributeError, TypeError) as exception:
            msg = "Unexpected client search response from AdGuard Home"
            raise AdGuardHomeError(msg) from exception
