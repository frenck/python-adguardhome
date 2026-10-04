"""Tests for `adguardhome.update`."""

from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from awesomeversion import AwesomeVersion
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import AdGuardHome, AvailableUpdate

from .conftest import FixtureLoader

URL_VERSION = "http://example.com:3000/control/version.json"
URL_UPDATE = "http://example.com:3000/control/update"


@pytest.mark.parametrize("recheck", [False, True])
async def test_get(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
    recheck: bool,
) -> None:
    """Test the available update is parsed, rechecking only when asked."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {"recheck_now": recheck}
        return CallbackResult(status=200, payload=load_fixture("update_available"))

    responses.post(URL_VERSION, callback=callback)

    update = await adguard.update.get(recheck=recheck)

    assert update == snapshot
    assert not update.disabled
    assert update.new_version == AwesomeVersion("v0.107.59")
    assert update.can_autoupdate


async def test_get_disabled(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test AdGuard Home with update checks disabled only reports that."""
    responses.post(URL_VERSION, status=200, payload=load_fixture("update_disabled"))

    assert await adguard.update.get() == AvailableUpdate(disabled=True)


async def test_install(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test starting the update of AdGuard Home."""
    responses.post(URL_UPDATE, status=200, body="OK\n", content_type="text/plain")

    await adguard.update.install()

    assert responses.requests is not None
    assert ("POST", URL(URL_UPDATE)) in responses.requests
