"""DNS server settings of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from mashumaro import field_options

from ._area import Area
from ._model import AdGuardHomeModel, WholeSecondsStrategy, require_whole
from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from collections.abc import Iterable


class BlockingMode(StrEnum):
    """How AdGuard Home answers a DNS query it blocks."""

    # Like NULL_IP for adblock-style rules, but answers with the address in
    # the rule for hosts-style rules.
    DEFAULT = "default"
    REFUSED = "refused"
    NXDOMAIN = "nxdomain"

    # 0.0.0.0 for A queries and :: for AAAA queries.
    NULL_IP = "null_ip"

    # The addresses in `blocking_ipv4` and `blocking_ipv6`.
    CUSTOM_IP = "custom_ip"


class UpstreamMode(StrEnum):
    """How AdGuard Home picks which upstream DNS server to ask."""

    LOAD_BALANCE = "load_balance"
    PARALLEL = "parallel"
    FASTEST_ADDR = "fastest_addr"


def _seconds(alias: str | None = None) -> dict[str, Any]:
    """Return the metadata of a field holding a duration in whole seconds."""
    return field_options(alias=alias, serialization_strategy=WholeSecondsStrategy())


@dataclass(frozen=True, kw_only=True)
class DnsConfig(AdGuardHomeModel):
    """Settings of the AdGuard Home DNS server.

    Protection is not part of this, use `AdGuardHome.status()` and
    `AdGuardHome.enable_protection()` for that. AdGuard Home leaves it alone
    when it is left out, so changing these settings never undoes a pause.
    """

    upstream_dns: tuple[str, ...]
    upstream_dns_file: str | None = None
    upstream_mode: UpstreamMode = UpstreamMode.LOAD_BALANCE
    upstream_timeout: timedelta = field(metadata=_seconds())
    bootstrap_dns: tuple[str, ...]
    fallback_dns: tuple[str, ...] = ()

    # Resolving the names of clients through reverse DNS, and which servers
    # to ask for private addresses.
    resolve_clients: bool
    use_private_ptr_resolvers: bool
    local_ptr_upstreams: tuple[str, ...] = ()

    # Requests per second per client subnet, 0 means no limit.
    ratelimit: int
    ratelimit_subnet_len_ipv4: int
    ratelimit_subnet_len_ipv6: int
    ratelimit_allowlist: tuple[str, ...] = field(
        default=(), metadata=field_options(alias="ratelimit_whitelist")
    )

    blocking_mode: BlockingMode
    blocking_ipv4: str | None = None
    blocking_ipv6: str | None = None
    blocked_response_ttl: timedelta = field(metadata=_seconds())

    edns_cs_enabled: bool
    edns_cs_use_custom: bool
    edns_cs_custom_ip: str | None = None
    dnssec_enabled: bool
    disable_ipv6: bool

    # The cache size in bytes. A TTL of 0 means AdGuard Home does not override
    # the TTL the upstream answered with.
    cache_enabled: bool
    cache_size: int
    cache_ttl_min: timedelta = field(metadata=_seconds())
    cache_ttl_max: timedelta = field(metadata=_seconds())
    cache_optimistic: bool

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop empty strings, which AdGuard Home sends for "not set".

        That includes an empty upstream mode, which is how AdGuard Home
        reports load balancing, so it falls back to the default.
        """
        d = super().__pre_deserialize__(d)
        return {key: value for key, value in d.items() if value != ""}

    def __post_init__(self) -> None:
        """Reject durations that are not a whole number of seconds."""
        second = timedelta(seconds=1)
        require_whole(self.upstream_timeout, second, "seconds", "upstream timeout")
        require_whole(
            self.blocked_response_ttl, second, "seconds", "blocked response TTL"
        )
        require_whole(self.cache_ttl_min, second, "seconds", "minimum cache TTL")
        require_whole(self.cache_ttl_max, second, "seconds", "maximum cache TTL")


class AdGuardHomeDns(Area):
    """DNS server settings of AdGuard Home."""

    __slots__ = ()

    async def config(self) -> DnsConfig:
        """Return the settings of the DNS server.

        Returns
        -------
            The current settings of the DNS server.

        """
        return DnsConfig.from_api(await self._request("dns_info"))

    async def set_config(self, config: DnsConfig) -> None:
        """Replace the settings of the DNS server.

        Use `dataclasses.replace` on the result of `config()` to change
        only part of it.

        Args:
        ----
            config: The new settings of the DNS server.

        """
        await self._request("dns_config", method="POST", json=config.to_dict())

    async def clear_cache(self) -> None:
        """Clear the DNS cache, including the caches of clients."""
        await self._request("cache_clear", method="POST")

    async def test_upstreams(
        self,
        upstream_dns: Iterable[str],
        *,
        bootstrap_dns: Iterable[str] = (),
        fallback_dns: Iterable[str] = (),
        local_ptr_upstreams: Iterable[str] = (),
    ) -> dict[str, str | None]:
        """Test if AdGuard Home can reach DNS servers, before using them.

        Args:
        ----
            upstream_dns: The upstream DNS servers to test.
            bootstrap_dns: The bootstrap DNS servers to resolve the upstreams
                with. Empty uses the ones AdGuard Home has.
            fallback_dns: The fallback DNS servers to test.
            local_ptr_upstreams: The private reverse DNS servers to test.

        Returns:
        -------
            For every server, None when it works, or the error otherwise.

        """
        response = await self._request(
            "test_upstream_dns",
            method="POST",
            json={
                "upstream_dns": list(upstream_dns),
                "bootstrap_dns": list(bootstrap_dns),
                "fallback_dns": list(fallback_dns),
                "private_upstream": list(local_ptr_upstreams),
            },
        )

        try:
            return {
                server: None if result == "OK" else result
                for server, result in response.items()
            }
        except AttributeError as exception:
            msg = "Unexpected upstream test response from AdGuard Home"
            raise AdGuardHomeError(msg) from exception
