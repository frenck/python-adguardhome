"""Tests for the AdGuard Home CLI."""

# pylint: disable=redefined-outer-name
from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import click
import pytest
from awesomeversion import AwesomeVersion
from typer.main import get_command
from typer.testing import CliRunner

from adguardhome import (
    AdGuardHomeAuthenticationError,
    AdGuardHomeConnectionError,
    AdGuardHomeError,
    AvailableUpdate,
    Clients,
    FilteringStatus,
    HostCheck,
    QueryLog,
    Stats,
    Status,
)
from adguardhome.cli import Feature, cli, parse_duration

if TYPE_CHECKING:
    from collections.abc import Generator

    from syrupy.assertion import SnapshotAssertion

    from tests.conftest import FixtureLoader


@pytest.fixture(autouse=True)
def stable_terminal(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Force deterministic Rich rendering and time zone for stable snapshots."""
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("ADGUARD_HOME_URL", "http://adguard.local:3000")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture
def runner() -> CliRunner:
    """Return a CLI runner for invoking the Typer app."""
    return CliRunner()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Replace the AdGuard Home client of the CLI with a mock, and return it."""
    adguard = AsyncMock()

    instance = AsyncMock()
    instance.__aenter__.return_value = adguard
    instance.__aexit__.return_value = None

    factory = MagicMock(return_value=instance)
    monkeypatch.setattr("adguardhome.cli.AdGuardHome", factory)
    adguard.factory = factory
    return adguard


def test_cli_structure(snapshot: SnapshotAssertion) -> None:
    """Test the commands and their parameters stay as they are."""
    command = get_command(cli)
    assert isinstance(command, click.Group)

    structure = {
        name: sorted(param.name for param in sub.params if param.name)
        for name, sub in command.commands.items()
    }

    assert structure == snapshot


def test_connection_options(runner: CliRunner, client: AsyncMock) -> None:
    """Test the global options are what the client connects with."""
    client.status.return_value = MagicMock()

    runner.invoke(
        cli,
        [
            "--url",
            "https://dns.example.com/adguard",
            "--username",
            "frenck",
            "--password",
            "zerocool",
            "update",
        ],
    )

    client.factory.assert_called_once_with(
        "https://dns.example.com/adguard",
        username="frenck",
        password="zerocool",  # noqa: S106
    )


def test_missing_url(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test a missing URL explains how to pass one."""
    monkeypatch.delenv("ADGUARD_HOME_URL")

    result = runner.invoke(cli, ["status"])

    assert result.exit_code == 2
    assert "ADGUARD_HOME_URL" in result.output


def test_invalid_url(runner: CliRunner) -> None:
    """Test an URL that is not HTTP or HTTPS is rejected as a usage error."""
    result = runner.invoke(cli, ["--url", "adguard.local", "status"])

    assert result.exit_code == 2
    assert "Invalid AdGuard Home URL" in result.output


def test_status(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the status is shown as a table."""
    client.status.return_value = Status.from_api(load_fixture("status"))

    result = runner.invoke(cli, ["status"])

    assert result.exit_code == 0
    assert result.output == snapshot


def test_status_paused(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test a protection pause shows when protection resumes."""
    client.status.return_value = Status.from_api(load_fixture("status_paused"))

    result = runner.invoke(cli, ["status"])

    assert "resumes in 0:00:29.500000" in result.output


def test_status_json(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the status as JSON, in the names and units of the library."""
    client.status.return_value = Status.from_api(load_fixture("status_paused"))

    result = runner.invoke(cli, ["status", "--json"])

    data = json.loads(result.output)
    assert data == snapshot
    assert data["protection_resumes_in"] == 29.5
    assert data["supported"] is True


@pytest.mark.parametrize("feature", [f for f in Feature if f is not Feature.PROTECTION])
def test_enable_disable_feature(
    runner: CliRunner, client: AsyncMock, feature: Feature
) -> None:
    """Test every feature turns on and off through its own area."""
    area = getattr(client, feature.value)

    assert runner.invoke(cli, ["enable", feature.value]).exit_code == 0
    assert runner.invoke(cli, ["disable", feature.value]).exit_code == 0

    area.enable.assert_awaited_once_with()
    area.disable.assert_awaited_once_with()


def test_enable_protection(runner: CliRunner, client: AsyncMock) -> None:
    """Test enabling protection."""
    result = runner.invoke(cli, ["enable", "protection"])

    assert result.exit_code == 0
    assert "Enabled protection" in result.output
    client.enable_protection.assert_awaited_once_with()


def test_disable_protection(runner: CliRunner, client: AsyncMock) -> None:
    """Test disabling protection until it is enabled again."""
    result = runner.invoke(cli, ["disable", "protection"])

    assert result.exit_code == 0
    assert "Disabled protection" in result.output
    client.disable_protection.assert_awaited_once_with(None)


def test_pause_protection(runner: CliRunner, client: AsyncMock) -> None:
    """Test pausing protection for a while."""
    result = runner.invoke(cli, ["disable", "protection", "--for", "1h30m"])

    assert result.exit_code == 0
    assert "Paused protection for 1:30:00" in result.output
    client.disable_protection.assert_awaited_once_with(timedelta(hours=1, minutes=30))


def test_pause_other_feature(runner: CliRunner, client: AsyncMock) -> None:
    """Test only protection can be paused for a while."""
    result = runner.invoke(cli, ["disable", "filtering", "--for", "10m"])

    assert result.exit_code == 2
    assert "Only protection can be paused" in result.output
    client.filtering.disable.assert_not_awaited()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("90", timedelta(seconds=90)),
        ("90s", timedelta(seconds=90)),
        ("10m", timedelta(minutes=10)),
        ("2h", timedelta(hours=2)),
        ("1h30m15s", timedelta(hours=1, minutes=30, seconds=15)),
    ],
)
def test_parse_duration(value: str, expected: timedelta) -> None:
    """Test durations in seconds, or with hours, minutes, and seconds."""
    assert parse_duration(value) == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("soon", "Not a duration"),
        ("10x", "Not a duration"),
        ("0", "longer than zero"),
        ("", "longer than zero"),
    ],
)
def test_parse_duration_invalid(value: str, message: str) -> None:
    """Test values that are not a positive duration are rejected."""
    with pytest.raises(click.BadParameter, match=message):
        parse_duration(value)


def test_stats(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the statistics are shown as a table, with the top lists."""
    client.stats.get.return_value = Stats.from_api(load_fixture("stats"))

    result = runner.invoke(cli, ["stats"])

    assert result.exit_code == 0
    assert result.output == snapshot


def test_stats_json(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test the statistics as JSON include the blocked percentage."""
    client.stats.get.return_value = Stats.from_api(load_fixture("stats"))

    data = json.loads(runner.invoke(cli, ["stats", "--json"]).output)

    assert data["dns_queries"] == 1440
    assert data["avg_processing_time"] == 0.018744
    assert data["blocked_percentage"] == pytest.approx(18.40277, abs=1e-5)
    assert data["top_clients"] == {"192.168.1.20": 1021, "192.168.1.33": 419}


def test_filters(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the filter lists are shown as a table."""
    client.filtering.get.return_value = FilteringStatus.from_api(
        load_fixture("filtering_status")
    )

    result = runner.invoke(cli, ["filters"])

    assert result.exit_code == 0
    assert result.output == snapshot


def test_filters_json(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test the filter lists as JSON, by kind."""
    client.filtering.get.return_value = FilteringStatus.from_api(
        load_fixture("filtering_status")
    )

    data = json.loads(runner.invoke(cli, ["filters", "--json"]).output)

    assert [f["name"] for f in data["blocklists"]] == [
        "AdGuard DNS filter",
        "Example ads",
    ]
    assert data["allowlists"] == []


def test_refresh(runner: CliRunner, client: AsyncMock) -> None:
    """Test refreshing reports how many lists of each kind changed."""
    client.filtering.blocklists.refresh.return_value = 2
    client.filtering.allowlists.refresh.return_value = 0

    result = runner.invoke(cli, ["refresh"])

    assert result.exit_code == 0
    assert "Updated 2 blocklists and 0 allowlists" in result.output


@pytest.mark.parametrize(
    "fixture", ["filtering_check_host_blocked", "filtering_check_host_rewrite"]
)
def test_check(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
    fixture: str,
) -> None:
    """Test checking a host shows why it is, or is not, filtered."""
    client.filtering.check_host.return_value = HostCheck.from_api(load_fixture(fixture))

    result = runner.invoke(cli, ["check", "example.com", "--client", "192.168.1.20"])

    assert result.exit_code == 0
    assert result.output == snapshot
    client.filtering.check_host.assert_awaited_once_with(
        "example.com", client="192.168.1.20"
    )


def test_check_blocked_service(runner: CliRunner, client: AsyncMock) -> None:
    """Test a host blocked as part of a service names that service."""
    client.filtering.check_host.return_value = HostCheck.from_api(
        {"reason": "FilteredBlockedService", "service_name": "tiktok"}
    )

    result = runner.invoke(cli, ["check", "tiktok.com"])

    assert "Blocked service" in result.output
    assert "tiktok" in result.output


def test_check_json(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test a host check as JSON includes whether it is filtered."""
    client.filtering.check_host.return_value = HostCheck.from_api(
        load_fixture("filtering_check_host_blocked")
    )

    data = json.loads(runner.invoke(cli, ["check", "ads.example.com", "--json"]).output)

    assert data["filtered"] is True
    assert data["reason"] == "FilteredBlackList"


def test_log(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the query log is shown as a table."""
    client.querylog.get.return_value = QueryLog.from_api(load_fixture("querylog"))

    result = runner.invoke(cli, ["log", "--search", "example", "--limit", "5"])

    assert result.exit_code == 0
    assert result.output == snapshot
    client.querylog.get.assert_awaited_once_with(search="example", limit=5)


def test_log_json(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test the query log as JSON is a list of entries."""
    client.querylog.get.return_value = QueryLog.from_api(load_fixture("querylog"))

    data = json.loads(runner.invoke(cli, ["log", "--json"]).output)

    assert len(data) == 2
    assert data[0]["time"] == "2025-10-03T16:00:01.123456+02:00"
    assert data[1]["question"]["unicode_name"] == "مثال.إختبار"


def test_log_without_client_info(runner: CliRunner, client: AsyncMock) -> None:
    """Test an entry without client details shows the client address."""
    client.querylog.get.return_value = QueryLog.from_api(
        {
            "data": [
                {
                    "time": "2025-10-03T16:00:00+02:00",
                    "client": "192.168.1.40",
                    "question": {"class": "IN", "name": "example.org", "type": "A"},
                    "reason": "NotFilteredNotFound",
                    "elapsedMs": "1",
                }
            ],
            "oldest": "2025-10-03T16:00:00+02:00",
        }
    )

    result = runner.invoke(cli, ["log"])

    assert "192.168.1.40" in result.output


def test_clients(
    runner: CliRunner,
    client: AsyncMock,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the clients are shown as a table."""
    client.clients.get.return_value = Clients.from_api(load_fixture("clients"))

    result = runner.invoke(cli, ["clients"])

    assert result.exit_code == 0
    assert result.output == snapshot


def test_clients_json(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test the clients as JSON, configured and runtime."""
    client.clients.get.return_value = Clients.from_api(load_fixture("clients"))

    data = json.loads(runner.invoke(cli, ["clients", "--json"]).output)

    assert data["configured"][0]["name"] == "Kids devices"
    assert data["runtime"][0]["ip_address"] == "192.168.1.10"


@pytest.mark.parametrize(
    ("available", "expected"),
    [
        (AvailableUpdate(disabled=True), "does not check for updates"),
        (AvailableUpdate(disabled=False), "up to date"),
        (
            AvailableUpdate(
                disabled=False,
                new_version=AwesomeVersion("v0.107.80"),
                announcement="AdGuard Home v0.107.80 is now available!",
                announcement_url="https://github.com/AdguardTeam/AdGuardHome/releases",
            ),
            "cannot update itself",
        ),
        (
            AvailableUpdate(
                disabled=False,
                new_version=AwesomeVersion("v0.107.80"),
                announcement="AdGuard Home v0.107.80 is now available!",
                can_autoupdate=True,
            ),
            "v0.107.80 is now available",
        ),
    ],
)
def test_update(
    runner: CliRunner,
    client: AsyncMock,
    available: AvailableUpdate,
    expected: str,
) -> None:
    """Test the update check, with update checks off, up to date, or behind."""
    client.update.get.return_value = available

    result = runner.invoke(cli, ["update", "--recheck"])

    assert result.exit_code == 0
    assert expected in result.output
    client.update.get.assert_awaited_once_with(recheck=True)


def test_update_json(
    runner: CliRunner, client: AsyncMock, load_fixture: FixtureLoader
) -> None:
    """Test the update check as JSON."""
    client.update.get.return_value = AvailableUpdate.from_api(
        load_fixture("update_available")
    )

    data = json.loads(runner.invoke(cli, ["update", "--json"]).output)

    assert data["new_version"] == "v0.107.59"
    assert data["can_autoupdate"] is True


def test_clear_cache(runner: CliRunner, client: AsyncMock) -> None:
    """Test clearing the DNS cache."""
    result = runner.invoke(cli, ["clear-cache"])

    assert result.exit_code == 0
    client.dns.clear_cache.assert_awaited_once_with()


@pytest.mark.parametrize(
    "error",
    [
        AdGuardHomeConnectionError("unreachable"),
        AdGuardHomeAuthenticationError("rejected"),
        AdGuardHomeError("something went wrong"),
    ],
)
def test_error_handlers(
    capsys: pytest.CaptureFixture[str],
    snapshot: SnapshotAssertion,
    error: AdGuardHomeError,
) -> None:
    """Test each error is shown in a panel, exiting with 1."""
    handler = cli.error_handlers[type(error)]

    with pytest.raises(SystemExit) as exc_info:
        handler(error)

    assert exc_info.value.code == 1
    assert capsys.readouterr().out == snapshot
