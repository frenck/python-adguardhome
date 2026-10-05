"""Encryption settings of AdGuard Home: HTTPS, DNS-over-TLS, and friends."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any

from mashumaro import field_options
from mashumaro.types import SerializationStrategy

from ._area import Area
from ._model import AdGuardHomeModel
from .exceptions import AdGuardHomeError

# How Go encodes a time that is not set, like the expiry of a missing
# certificate.
GO_ZERO_TIME = "0001-01-01T00:00:00Z"


class Base64Strategy(SerializationStrategy):
    """Convert PEM text, which travels base64-encoded, to a plain string."""

    def serialize(self, value: str) -> str:
        """Serialize to base64."""
        return base64.b64encode(value.encode()).decode()

    def deserialize(self, value: str) -> str:
        """Deserialize from base64."""
        return base64.b64decode(value).decode()


@dataclass(frozen=True, kw_only=True)
class TlsConfig(AdGuardHomeModel):
    """Encryption settings of AdGuard Home.

    A certificate and private key are either given as PEM text, or as a path
    to a file on the AdGuard Home server, not both. A port of 0 turns that
    protocol off.
    """

    enabled: bool
    server_name: str | None = None
    force_https: bool = False

    # Also answer plain, unencrypted DNS.
    serve_plain_dns: bool = True

    port_https: int = 0
    port_dns_over_tls: int = 0
    port_dns_over_quic: int = 0
    port_dnscrypt: int = 0
    dnscrypt_config_file: str | None = None

    certificate_chain: str | None = field(
        default=None,
        metadata=field_options(serialization_strategy=Base64Strategy()),
    )
    certificate_path: str | None = None

    # AdGuard Home never sends a saved private key back, so this is None after
    # reading the settings, and `private_key_saved` says if there is one.
    private_key: str | None = field(
        default=None,
        repr=False,
        metadata=field_options(serialization_strategy=Base64Strategy()),
    )
    private_key_path: str | None = None
    private_key_saved: bool = False

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop values AdGuard Home sends for "not set"."""
        d = super().__pre_deserialize__(d)
        return {
            key: value for key, value in d.items() if value not in ("", GO_ZERO_TIME)
        }

    def __post_serialize__(self, d: dict[Any, Any]) -> dict[Any, Any]:
        """Make AdGuard Home use a new private key, instead of the saved one.

        While `private_key_saved` is true, AdGuard Home ignores the private key
        in the request and puts the saved one back. With a key file, that
        leaves it with both a key and a key file, which it rejects.
        """
        if "private_key" in d or "private_key_path" in d:
            d["private_key_saved"] = False
        return d


@dataclass(frozen=True, kw_only=True)
class TlsStatus(TlsConfig):
    """Encryption settings of AdGuard Home, and the state of its certificate."""

    subject: str | None = None
    issuer: str | None = None
    key_type: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    dns_names: tuple[str, ...] = ()

    valid_cert: bool = False
    valid_chain: bool = False
    valid_key: bool = False
    valid_pair: bool = False

    # Why the certificate or key is not valid, if it is not.
    warning_validation: str | None = None

    @property
    def rejected(self) -> bool:
        """Return if AdGuard Home rejects these settings.

        AdGuard Home also warns about problems it does not mind, like an
        incomplete certificate chain. It only rejects the settings when the
        certificate, the key, or the pair of them is not valid.
        """
        if not self.warning_validation:
            return False

        return not (self.valid_cert and self.valid_key and self.valid_pair)


class AdGuardHomeTls(Area):
    """Encryption settings of AdGuard Home: HTTPS, DNS-over-TLS, and friends."""

    __slots__ = ()

    async def get(self) -> TlsStatus:
        """Return the encryption settings, and the state of the certificate.

        Returns
        -------
            The encryption settings, and what AdGuard Home found in the
            certificate and private key.

        """
        return TlsStatus.from_api(await self._request("tls/status"))

    async def config(self) -> TlsConfig:
        """Return the encryption settings.

        Returns
        -------
            The current encryption settings.

        """
        return TlsConfig.from_api(await self._request("tls/status"))

    async def validate(self, config: TlsConfig) -> TlsStatus:
        """Check encryption settings, without applying them.

        Args:
        ----
            config: The encryption settings to check.

        Returns:
        -------
            What AdGuard Home found in the certificate and private key.

        """
        response = await self._request(
            "tls/validate", method="POST", json=_settings(config)
        )
        return TlsStatus.from_api(response)

    async def set_config(self, config: TlsConfig) -> TlsStatus:
        """Replace the encryption settings.

        Changing the HTTPS settings restarts the web interface of AdGuard
        Home, so expect it to be unreachable for a moment afterwards.

        Args:
        ----
            config: The new encryption settings.

        Returns:
        -------
            What AdGuard Home found in the certificate and private key,
            including warnings it applied the settings despite.

        Raises:
        ------
            AdGuardHomeError: AdGuard Home rejected the settings, and kept
                the ones it had.

        """
        response = await self._request(
            "tls/configure", method="POST", json=_settings(config)
        )
        result = TlsStatus.from_api(response)

        # AdGuard Home answers a rejection like a success, with the reason.
        if result.rejected:
            msg = (
                "AdGuard Home rejected the encryption settings: "
                f"{result.warning_validation}"
            )
            raise AdGuardHomeError(msg)

        return result


def _settings(config: TlsConfig) -> dict[str, Any]:
    """Return only the settings, also when given a full TlsStatus."""
    settings = TlsConfig(
        **{setting.name: getattr(config, setting.name) for setting in fields(TlsConfig)}
    )
    return settings.to_dict()
