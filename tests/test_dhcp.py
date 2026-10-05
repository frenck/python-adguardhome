"""Tests for `adguardhome.dhcp`."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import (
    AdGuardHome,
    AdGuardHomeError,
    AdGuardHomeResponseError,
    DhcpCheck,
    DhcpStatus,
    DhcpV4Config,
    DhcpV6Config,
    StaticLease,
)

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control/dhcp"


def expect_json(expected: Any, payload: Any = None) -> Any:
    """Return a callback asserting the JSON body of the request."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == expected
        if payload is not None:
            return CallbackResult(status=200, payload=payload)
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    return callback


@pytest.fixture
def status(responses: aiointercept, load_fixture: FixtureLoader) -> None:
    """Mock the DHCP status, which reading the settings also uses."""
    responses.get(
        f"{URL_BASE}/status",
        status=200,
        payload=load_fixture("dhcp_status"),
        repeat=True,
    )


@pytest.mark.usefixtures("status")
async def test_get(adguard: AdGuardHome, snapshot: SnapshotAssertion) -> None:
    """Test the settings and leases are parsed into models."""
    dhcp = await adguard.dhcp.get()

    assert dhcp == snapshot
    assert dhcp.enabled
    assert dhcp.interface_name == "eth0"
    assert dhcp.v4.range_start == "192.168.1.100"
    assert dhcp.v4.lease_duration == timedelta(days=1)
    assert dhcp.v6 == DhcpV6Config()
    assert dhcp.leases[0].hostname == "phone"
    assert dhcp.leases[0].expires == datetime(2025, 10, 4, 14, 0, tzinfo=UTC)
    assert dhcp.static_leases == (
        StaticLease(mac="aa:bb:cc:dd:ee:02", ip="192.168.1.5", hostname="nas"),
    )


@pytest.mark.usefixtures("status")
async def test_config(adguard: AdGuardHome) -> None:
    """Test the settings only hold the settings."""
    config = await adguard.dhcp.config()

    assert not isinstance(config, DhcpStatus)
    assert config.v4.gateway_ip == "192.168.1.1"


@pytest.mark.usefixtures("status")
async def test_set_config_from_status(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a full status only sends its settings, leaving out what is not set."""
    responses.post(
        f"{URL_BASE}/set_config",
        callback=expect_json(
            {
                "enabled": True,
                "interface_name": "eth0",
                "v4": {
                    "gateway_ip": "192.168.1.1",
                    "subnet_mask": "255.255.255.0",
                    "range_start": "192.168.1.100",
                    "range_end": "192.168.1.200",
                    "lease_duration": 86400,
                },
                "v6": {"lease_duration": 0},
            }
        ),
    )

    await adguard.dhcp.set_config(await adguard.dhcp.get())


@pytest.mark.usefixtures("status")
@pytest.mark.parametrize(("method", "enabled"), [("enable", True), ("disable", False)])
async def test_enable_disable(
    responses: aiointercept, adguard: AdGuardHome, method: str, enabled: bool
) -> None:
    """Test toggling the DHCP server keeps its settings."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"]["enabled"] is enabled
        assert kwargs["json"]["v4"]["range_end"] == "192.168.1.200"
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(f"{URL_BASE}/set_config", callback=callback)

    await getattr(adguard.dhcp, method)()


@pytest.mark.parametrize("model", [DhcpV4Config, DhcpV6Config])
def test_config_rejects_partial_seconds(
    model: type[DhcpV4Config | DhcpV6Config],
) -> None:
    """Test a lease duration with a partial second is rejected, not rounded."""
    with pytest.raises(ValueError, match="whole number of seconds"):
        model(lease_duration=timedelta(seconds=1.5))


async def test_interfaces(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test the network interfaces are parsed, by name."""
    responses.get(
        f"{URL_BASE}/interfaces", status=200, payload=load_fixture("dhcp_interfaces")
    )

    interfaces = await adguard.dhcp.interfaces()

    assert list(interfaces) == ["eth0", "wlan0"]
    assert interfaces["eth0"].ipv4_addresses == ("192.168.1.2",)
    assert interfaces["wlan0"].gateway_ip is None
    assert interfaces["wlan0"].ipv4_addresses == ()


async def test_interfaces_unexpected_response(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test an interfaces response that is not an object raises an error."""
    responses.get(f"{URL_BASE}/interfaces", status=200, payload=["eth0"])

    with pytest.raises(AdGuardHomeError, match="Unexpected network interfaces"):
        await adguard.dhcp.interfaces()


async def test_check(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test checking an interface turns `yes`, `no`, and `error` into booleans."""
    response = {
        "v4": {
            "other_server": {"found": "yes"},
            "static_ip": {"static": "no", "ip": "192.168.1.2/24"},
        },
        "v6": {"other_server": {"found": "error", "error": "no IPv6 address"}},
    }
    responses.post(
        f"{URL_BASE}/find_active_dhcp",
        callback=expect_json({"interface": "eth0"}, payload=response),
    )

    check = await adguard.dhcp.check("eth0")

    assert check.v4.other_server.found is True
    assert check.v4.static_ip.static is False
    assert check.v4.static_ip.ip == "192.168.1.2/24"
    assert check.v6.other_server.found is None
    assert check.v6.other_server.error == "no IPv6 address"
    assert check.to_dict()["v4"] == response["v4"]


def test_check_serializes_no() -> None:
    """Test a check without another server serializes back to `no`."""
    check = DhcpCheck.from_api(
        {
            "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "yes"}},
            "v6": {"other_server": {"found": "no"}},
        }
    )

    assert check.v4.other_server.found is False
    assert check.to_dict()["v6"] == {"other_server": {"found": "no"}}


@pytest.mark.parametrize("action", ["add", "update", "remove"])
async def test_static_lease(
    responses: aiointercept, adguard: AdGuardHome, action: str
) -> None:
    """Test static lease changes send the whole lease."""
    lease = StaticLease(mac="aa:bb:cc:dd:ee:02", ip="192.168.1.5", hostname="nas")
    responses.post(
        f"{URL_BASE}/{action}_static_lease",
        callback=expect_json(
            {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.5", "hostname": "nas"}
        ),
    )

    await getattr(adguard.dhcp, f"{action}_static_lease")(lease)


@pytest.mark.parametrize("action", ["reset", "reset_leases"])
async def test_reset(
    responses: aiointercept, adguard: AdGuardHome, action: str
) -> None:
    """Test resetting the DHCP server, or only its leases."""
    url = f"{URL_BASE}/{action}"
    responses.post(url, status=200, body="OK\n", content_type="text/plain")

    await getattr(adguard.dhcp, action)()

    assert responses.requests is not None
    assert ("POST", URL(url)) in responses.requests


async def test_not_available(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test AdGuard Home without a DHCP server, like on Windows."""
    responses.get(
        f"{URL_BASE}/status",
        status=501,
        payload={"message": "dhcp is unsupported on windows"},
    )

    with pytest.raises(AdGuardHomeResponseError) as excinfo:
        await adguard.dhcp.get()

    assert excinfo.value.status == 501


def test_check_unexpected_value() -> None:
    """Test a check answer other than yes, no, or error raises an error."""
    with pytest.raises(AdGuardHomeError, match="Unexpected DhcpCheck data"):
        DhcpCheck.from_api(
            {
                "v4": {
                    "other_server": {"found": "maybe"},
                    "static_ip": {"static": "yes"},
                },
                "v6": {"other_server": {"found": "no"}},
            }
        )
