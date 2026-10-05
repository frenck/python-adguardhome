"""Tests for `adguardhome.tls`."""

import base64
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import AdGuardHome, AdGuardHomeError, TlsConfig, TlsStatus

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control/tls"

PEM_CERTIFICATE = (
    "-----BEGIN CERTIFICATE-----\nMIIBfakecertificatedata\n-----END CERTIFICATE-----\n"
)
# The library treats the key as opaque text, so it does not need to look
# like a real key, which would also trip the private key detection hook.
PEM_KEY = "fake private key for testing\n"


def b64(text: str) -> str:
    """Return text base64-encoded, the way AdGuard Home sends PEM data."""
    return base64.b64encode(text.encode()).decode()


async def test_get(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the settings and certificate state are parsed into a model."""
    responses.get(f"{URL_BASE}/status", status=200, payload=load_fixture("tls_status"))

    tls = await adguard.tls.get()

    assert tls == snapshot
    assert tls.certificate_chain == PEM_CERTIFICATE
    assert tls.private_key is None
    assert tls.private_key_saved
    assert tls.not_after == datetime(2025, 11, 30, tzinfo=UTC)
    assert tls.dns_names == ("dns.example.com", "*.dns.example.com")
    assert tls.valid_pair


async def test_get_off(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test encryption that is off, with Go zero times and empty strings."""
    responses.get(
        f"{URL_BASE}/status", status=200, payload=load_fixture("tls_status_off")
    )

    tls = await adguard.tls.get()

    assert not tls.enabled
    assert tls.server_name is None
    assert tls.certificate_chain is None
    assert tls.not_before is None
    assert tls.not_after is None
    assert tls.dns_names == ()
    assert tls.port_https == 0


def test_private_key_not_in_repr() -> None:
    """Test the private key does not end up in logs through repr()."""
    config = TlsConfig(enabled=True, private_key=PEM_KEY)

    assert "fake private key" not in repr(config)


async def test_set_config_keeps_saved_key(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test sending settings back keeps the private key AdGuard Home has."""
    responses.get(f"{URL_BASE}/status", status=200, payload=load_fixture("tls_status"))

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        sent = kwargs["json"]
        assert sent["private_key_saved"] is True
        assert "private_key" not in sent
        assert "subject" not in sent
        assert "valid_pair" not in sent
        assert sent["certificate_chain"] == b64(PEM_CERTIFICATE)
        assert sent["port_https"] == 8443
        return CallbackResult(status=200, payload=load_fixture("tls_status"))

    responses.post(f"{URL_BASE}/configure", callback=callback)

    tls = await adguard.tls.get()
    await adguard.tls.set_config(replace(tls, port_https=8443))


async def test_set_config_new_key(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a new private key is sent base64-encoded, replacing the saved one."""
    responses.get(f"{URL_BASE}/status", status=200, payload=load_fixture("tls_status"))

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        sent = kwargs["json"]
        assert sent["private_key"] == b64(PEM_KEY)
        assert sent["private_key_saved"] is False
        return CallbackResult(status=200, payload=load_fixture("tls_status"))

    responses.post(f"{URL_BASE}/configure", callback=callback)

    config = await adguard.tls.config()
    await adguard.tls.set_config(replace(config, private_key=PEM_KEY))


async def test_validate(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test validating settings returns what AdGuard Home found."""
    invalid = load_fixture("tls_status") | {
        "valid_pair": False,
        "warning_validation": "certificate does not match the private key",
    }

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"]["certificate_path"] == "/etc/ssl/dns.pem"
        return CallbackResult(status=200, payload=invalid)

    responses.post(f"{URL_BASE}/validate", callback=callback)

    result = await adguard.tls.validate(
        TlsConfig(
            enabled=True,
            certificate_path="/etc/ssl/dns.pem",
            private_key_path="/etc/ssl/dns.key",
        )
    )

    assert isinstance(result, TlsStatus)
    assert not result.valid_pair
    assert result.warning_validation == "certificate does not match the private key"


async def test_get_invalid_base64(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a certificate that is not valid base64 raises an error."""
    data = load_fixture("tls_status") | {"certificate_chain": "not base64!"}
    responses.get(f"{URL_BASE}/status", status=200, payload=data)

    with pytest.raises(AdGuardHomeError, match="Unexpected TlsStatus data"):
        await adguard.tls.get()
