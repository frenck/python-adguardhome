"""DHCP server of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from mashumaro import field_options
from mashumaro.types import SerializationStrategy

from ._area import Area
from ._model import AdGuardHomeModel, WholeSecondsStrategy, require_whole
from .exceptions import AdGuardHomeError


class _NotSetModel(AdGuardHomeModel):
    """Base for DHCP models, where AdGuard Home sends "not set" as empty."""

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop empty strings, which AdGuard Home sends for "not set"."""
        d = super().__pre_deserialize__(d)
        return {key: value for key, value in d.items() if value != ""}


@dataclass(frozen=True, kw_only=True)
class DhcpV4Config(_NotSetModel):
    """Settings of the DHCPv4 server."""

    gateway_ip: str | None = None
    subnet_mask: str | None = None
    range_start: str | None = None
    range_end: str | None = None
    lease_duration: timedelta = field(
        default=timedelta(0),
        metadata=field_options(serialization_strategy=WholeSecondsStrategy()),
    )

    def __post_init__(self) -> None:
        """Reject a lease duration that is not a whole number of seconds."""
        require_whole(
            self.lease_duration, timedelta(seconds=1), "seconds", "lease duration"
        )


@dataclass(frozen=True, kw_only=True)
class DhcpV6Config(_NotSetModel):
    """Settings of the DHCPv6 server."""

    range_start: str | None = None
    lease_duration: timedelta = field(
        default=timedelta(0),
        metadata=field_options(serialization_strategy=WholeSecondsStrategy()),
    )

    def __post_init__(self) -> None:
        """Reject a lease duration that is not a whole number of seconds."""
        require_whole(
            self.lease_duration, timedelta(seconds=1), "seconds", "lease duration"
        )


@dataclass(frozen=True, kw_only=True)
class DhcpConfig(_NotSetModel):
    """Settings of the DHCP server."""

    enabled: bool

    # The network interface to serve DHCP on, like `eth0`.
    interface_name: str | None = None
    v4: DhcpV4Config = field(default_factory=DhcpV4Config)
    v6: DhcpV6Config = field(default_factory=DhcpV6Config)


@dataclass(frozen=True, kw_only=True)
class StaticLease(AdGuardHomeModel):
    """A DHCP lease that always gives a device the same address."""

    mac: str
    ip: str
    hostname: str = ""


@dataclass(frozen=True, kw_only=True)
class Lease(AdGuardHomeModel):
    """A DHCP lease the DHCP server handed out."""

    mac: str
    ip: str
    hostname: str = ""
    expires: datetime


@dataclass(frozen=True, kw_only=True)
class DhcpStatus(DhcpConfig):
    """Settings and leases of the DHCP server."""

    leases: tuple[Lease, ...] = ()
    static_leases: tuple[StaticLease, ...] = ()


@dataclass(frozen=True, kw_only=True)
class NetworkInterface(_NotSetModel):
    """A network interface the DHCP server can serve on."""

    name: str
    hardware_address: str
    flags: str
    gateway_ip: str | None = None
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()


class YesNoErrorStrategy(SerializationStrategy):
    """Convert the `yes`, `no`, or `error` of a DHCP check to a boolean.

    An `error` means AdGuard Home could not tell, which becomes None.
    """

    # The signature is the one of SerializationStrategy, so it stays positional.
    def serialize(self, value: bool) -> str:  # noqa: FBT001
        """Serialize to `yes` or `no`.

        Mashumaro never passes None to a strategy, so an `error` is left out
        instead of serialized.
        """
        return "yes" if value else "no"

    def deserialize(self, value: str) -> bool | None:
        """Deserialize from `yes`, `no`, or `error`.

        Raises
        ------
            ValueError: The value is something else.

        """
        if value == "error":
            return None
        if value not in ("yes", "no"):
            msg = f"Expected yes, no, or error, got {value!r}"
            raise ValueError(msg)
        return value == "yes"


def _yes_no_error() -> dict[str, Any]:
    """Return the metadata of a field holding a `yes`, `no`, or `error`."""
    return field_options(serialization_strategy=YesNoErrorStrategy())


@dataclass(frozen=True, kw_only=True)
class OtherDhcpServer(AdGuardHomeModel):
    """Whether another DHCP server is active on a network interface."""

    # None when AdGuard Home could not tell, see `error` for why.
    found: bool | None = field(default=False, metadata=_yes_no_error())
    error: str | None = None


@dataclass(frozen=True, kw_only=True)
class StaticIpCheck(AdGuardHomeModel):
    """Whether the server has a static IP address on a network interface."""

    # None when AdGuard Home could not tell, see `error` for why.
    static: bool | None = field(metadata=_yes_no_error())

    # The current address of the server, when it is not static.
    ip: str | None = None
    error: str | None = None


@dataclass(frozen=True, kw_only=True)
class DhcpV4Check(AdGuardHomeModel):
    """Whether a network interface is ready for the DHCPv4 server."""

    other_server: OtherDhcpServer
    static_ip: StaticIpCheck


@dataclass(frozen=True, kw_only=True)
class DhcpV6Check(AdGuardHomeModel):
    """Whether a network interface is ready for the DHCPv6 server."""

    other_server: OtherDhcpServer


@dataclass(frozen=True, kw_only=True)
class DhcpCheck(AdGuardHomeModel):
    """Whether a network interface is ready for the DHCP server."""

    v4: DhcpV4Check
    v6: DhcpV6Check


class AdGuardHomeDhcp(Area):
    """DHCP server of AdGuard Home.

    AdGuard Home only has a DHCP server on Linux, macOS, FreeBSD, and
    OpenBSD. On other systems, every call raises an
    `AdGuardHomeResponseError`. Check `Status.dhcp_available` first.
    """

    __slots__ = ()

    async def get(self) -> DhcpStatus:
        """Return the settings and leases of the DHCP server.

        Returns
        -------
            The settings, the handed out leases, and the static leases.

        """
        return DhcpStatus.from_api(await self._request("dhcp/status"))

    async def config(self) -> DhcpConfig:
        """Return the settings of the DHCP server.

        Returns
        -------
            The current settings of the DHCP server.

        """
        return DhcpConfig.from_api(await self._request("dhcp/status"))

    async def set_config(self, config: DhcpConfig) -> None:
        """Replace the settings of the DHCP server.

        Args:
        ----
            config: The new settings of the DHCP server.

        """
        # Only send the settings, also when given a full DhcpStatus.
        payload = DhcpConfig(
            enabled=config.enabled,
            interface_name=config.interface_name,
            v4=config.v4,
            v6=config.v6,
        )
        await self._request("dhcp/set_config", method="POST", json=payload.to_dict())

    async def enable(self) -> None:
        """Enable the DHCP server, with its current settings."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Disable the DHCP server, keeping its settings."""
        await self.set_config(replace(await self.config(), enabled=False))

    async def interfaces(self) -> dict[str, NetworkInterface]:
        """Return the network interfaces the DHCP server can serve on.

        Returns
        -------
            The network interfaces, by name.

        """
        response = await self._request("dhcp/interfaces")

        try:
            return {
                name: NetworkInterface.from_api(interface)
                for name, interface in (response or {}).items()
            }
        except AttributeError as exception:
            msg = "Unexpected network interfaces response from AdGuard Home"
            raise AdGuardHomeError(msg) from exception

    async def check(self, interface_name: str) -> DhcpCheck:
        """Check if a network interface is ready for the DHCP server.

        This looks for other DHCP servers on the network, and for a static
        IP address of AdGuard Home. It takes a few seconds.

        Args:
        ----
            interface_name: The network interface to check, like `eth0`.

        Returns:
        -------
            Whether there are other DHCP servers, and if the address is static.

        """
        response = await self._request(
            "dhcp/find_active_dhcp",
            method="POST",
            json={"interface": interface_name},
        )
        return DhcpCheck.from_api(response)

    async def add_static_lease(self, lease: StaticLease) -> None:
        """Add a static lease.

        Args:
        ----
            lease: The static lease to add.

        """
        await self._request(
            "dhcp/add_static_lease", method="POST", json=lease.to_dict()
        )

    async def update_static_lease(self, lease: StaticLease) -> None:
        """Change the address or hostname of a static lease.

        Args:
        ----
            lease: The static lease, found by its MAC address, with its new
                address or hostname. The address must stay IPv4 or IPv6.

        """
        await self._request(
            "dhcp/update_static_lease", method="POST", json=lease.to_dict()
        )

    async def remove_static_lease(self, lease: StaticLease) -> None:
        """Remove a static lease.

        Args:
        ----
            lease: The static lease to remove. Its MAC address, address, and
                hostname must all match, like a lease from `get()`.

        """
        await self._request(
            "dhcp/remove_static_lease", method="POST", json=lease.to_dict()
        )

    async def reset(self) -> None:
        """Reset the DHCP server to its defaults, removing all leases."""
        await self._request("dhcp/reset", method="POST")

    async def reset_leases(self) -> None:
        """Remove all leases, keeping the settings of the DHCP server."""
        await self._request("dhcp/reset_leases", method="POST")
