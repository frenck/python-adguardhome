"""Tests for `adguardhome.update`."""

import pytest
from aioresponses import aioresponses
from syrupy.assertion import SnapshotAssertion

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError

from .conftest import FixtureLoader

URL_VERSION = "http://example.com:3000/control/version.json"
URL_UPDATE = "http://example.com:3000/control/update"


async def test_update_available(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting the latest available update."""
    responses.post(URL_VERSION, status=200, payload=load_fixture("update_available"))

    available_update = await adguard.update.update_available()

    assert available_update
    assert available_update.announcement == "AdGuard Home v0.107.59 is now available!"
    assert (
        available_update.announcement_url
        == "https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.59"
    )
    assert available_update.can_autoupdate
    assert available_update.disabled is False
    assert available_update.new_version == "v0.107.59"


async def test_update_available_snapshot(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test update_available dataclass parsing matches snapshot."""
    responses.post(URL_VERSION, status=200, payload=load_fixture("update_available"))
    assert await adguard.update.update_available() == snapshot


async def test_update_disabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting the latest update when auto-update is disabled."""
    responses.post(URL_VERSION, status=200, payload=load_fixture("update_disabled"))

    available_update = await adguard.update.update_available()

    assert available_update
    assert available_update.disabled is True
    assert available_update.announcement is None
    assert available_update.announcement_url is None
    assert available_update.can_autoupdate is None
    assert available_update.new_version is None


async def test_begin_update(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test beginning the AdGuard Home auto-upgrade."""
    responses.post(URL_UPDATE, status=200, body="OK", content_type="text/plain")
    await adguard.update.begin_update()


@pytest.mark.parametrize("status", [400, 500])
async def test_begin_update_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test beginning the auto-upgrade fails on HTTP error."""
    responses.post(URL_UPDATE, status=status, body="NOT OK", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.update.begin_update()
