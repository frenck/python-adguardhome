"""Command-line interface for AdGuard Home."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Annotated, Any

import typer
from awesomeversion import AwesomeVersion
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from adguardhome.adguardhome import AdGuardHome
from adguardhome.exceptions import (
    AdGuardHomeAuthenticationError,
    AdGuardHomeConnectionError,
    AdGuardHomeError,
)

from .async_typer import AsyncTyper

if TYPE_CHECKING:
    from collections.abc import Callable

cli = AsyncTyper(
    help="Manage AdGuard Home from the command line.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

# Errors go to stderr, so they never end up in the output of --json.
error_console = Console(stderr=True)

JsonFlag = Annotated[
    bool,
    typer.Option("--json", help="Emit machine-readable JSON output"),
]


@dataclass(frozen=True)
class Connection:
    """How to reach AdGuard Home, from the global options."""

    url: str | None
    username: str | None

    def client(self) -> AdGuardHome:
        """Return an AdGuard Home client for these options.

        The password comes from ADGUARD_HOME_PASSWORD, or from a hidden prompt.
        It is not an option, as that would leave it in the shell history and
        the process list.

        Raises
        ------
            typer.BadParameter: The URL is missing or invalid.

        """
        if not self.url:
            msg = "Pass --url, or set ADGUARD_HOME_URL"
            raise typer.BadParameter(msg, param_hint="--url")

        password = None
        if self.username:
            password = os.environ.get("ADGUARD_HOME_PASSWORD")
            if password is None:
                password = typer.prompt("Password", hide_input=True)

        try:
            return AdGuardHome(self.url, username=self.username, password=password)
        except ValueError as exception:
            raise typer.BadParameter(str(exception), param_hint="--url") from exception


@cli.callback()
async def main(
    ctx: typer.Context,
    url: Annotated[
        str | None,
        typer.Option(
            help="URL of the AdGuard Home web interface",
            envvar="ADGUARD_HOME_URL",
            show_default=False,
        ),
    ] = None,
    username: Annotated[
        str | None,
        typer.Option(
            help="Username, if AdGuard Home requires one",
            envvar="ADGUARD_HOME_USERNAME",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Manage AdGuard Home from the command line."""
    ctx.obj = Connection(url=url, username=username)


def _error_panel(message: str, title: str) -> None:
    """Print an error in a red panel and exit."""
    error_console.print(
        Panel(message, expand=False, title=title, border_style="red bold")
    )
    sys.exit(1)


@cli.error_handler(AdGuardHomeConnectionError)
def connection_error_handler(_: AdGuardHomeConnectionError) -> None:
    """Handle connection errors."""
    _error_panel(
        "Could not connect to AdGuard Home. Check the URL, and that AdGuard "
        "Home is running and reachable on the network.",
        "Connection error",
    )


@cli.error_handler(AdGuardHomeAuthenticationError)
def authentication_error_handler(_: AdGuardHomeAuthenticationError) -> None:
    """Handle rejected credentials."""
    _error_panel(
        "AdGuard Home rejected the username or password.",
        "Authentication error",
    )


@cli.error_handler(AdGuardHomeError)
def adguardhome_error_handler(err: AdGuardHomeError) -> None:
    """Handle any other AdGuard Home error."""
    _error_panel(_safe(err), "AdGuard Home error")


# How to turn the values in models into something JSON can hold. Durations
# become seconds and timestamps ISO 8601, so the JSON uses the names and units
# of this library rather than those of the API.
_JSON_CONVERSIONS: tuple[tuple[type, Callable[[Any], Any]], ...] = (
    (timedelta, timedelta.total_seconds),
    (datetime, datetime.isoformat),
    (Enum, lambda value: value.value),
    (AwesomeVersion, str),
)


def _plain(value: Any) -> Any:
    """Return a value as something JSON can hold, models included."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]

    for kind, convert in _JSON_CONVERSIONS:
        if isinstance(value, kind):
            return convert(value)

    return value


def emit_json(data: Any) -> None:
    """Emit a model, or a collection of models, as indented JSON on stdout."""
    typer.echo(json.dumps(_plain(data), indent=2, ensure_ascii=False))


# Control characters, except tabs and newlines. Text from AdGuard Home, like a
# client name, could otherwise move the cursor, clear the screen, or worse, in
# the terminal of whoever runs the CLI.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(value: object) -> str:
    """Return text from AdGuard Home, made safe to show in a terminal.

    Rich reads square brackets as markup, so a filter rule or client name with
    brackets would lose them, or crash the output on a stray closing tag.
    Control characters are replaced, so they cannot control the terminal.
    """
    return escape(_CONTROL_CHARACTERS.sub("\N{REPLACEMENT CHARACTER}", str(value)))


def _yes_no(value: bool) -> str:  # noqa: FBT001
    """Return a value as a colored yes or no."""
    return "[green]yes[/green]" if value else "[red]no[/red]"


def _milliseconds(value: timedelta) -> str:
    """Return a duration in milliseconds, for short durations."""
    return f"{value / timedelta(milliseconds=1):.2f} ms"


def _top(counts: dict[str, int], limit: int = 5) -> str:
    """Return the first entries of a top list, one per line."""
    return "\n".join(
        f"{_safe(key)} ({count})" for key, count in list(counts.items())[:limit]
    )


def parse_duration(value: str) -> timedelta:
    """Parse a duration like `90s`, `10m`, `1h30m`, or plain seconds.

    Raises
    ------
        typer.BadParameter: The value is not a positive duration.

    """
    try:
        if value.isdigit():
            duration = timedelta(seconds=int(value))
        elif match := re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", value):
            hours, minutes, seconds = (int(part or 0) for part in match.groups())
            duration = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        else:
            msg = f"Not a duration: {value}. Use something like 90s, 10m, or 1h30m"
            raise typer.BadParameter(msg)
    except OverflowError as exception:
        msg = f"The duration is too long: {value}"
        raise typer.BadParameter(msg) from exception

    if not duration:
        msg = "The duration must be longer than zero"
        raise typer.BadParameter(msg)

    return duration


class Feature(StrEnum):
    """A feature of AdGuard Home that turns on and off."""

    PROTECTION = "protection"
    FILTERING = "filtering"
    PARENTAL = "parental"
    SAFEBROWSING = "safebrowsing"
    SAFESEARCH = "safesearch"
    QUERYLOG = "querylog"
    STATS = "stats"
    REWRITE = "rewrite"


@cli.command("status")
async def status(ctx: typer.Context, output_json: JsonFlag = False) -> None:
    """Show the status of AdGuard Home."""
    async with ctx.obj.client() as adguard:
        server = await adguard.status()

    if output_json:
        emit_json(dataclasses.asdict(server) | {"supported": server.supported})
        return

    protection = _yes_no(server.protection_enabled)
    if server.protection_resumes_in:
        protection += f" (resumes in {server.protection_resumes_in})"

    table = Table(title="AdGuard Home")
    table.add_column("Property", style="cyan bold")
    table.add_column("Value")
    table.add_row("Version", _safe(server.version))
    table.add_row("Supported", _yes_no(server.supported))
    table.add_row("Running", _yes_no(server.running))
    table.add_row("Protection", protection)
    table.add_row("DNS addresses", _safe("\n".join(server.dns_addresses)))
    table.add_row("DNS port", str(server.dns_port))
    table.add_row("HTTP port", str(server.http_port))
    table.add_row("DHCP available", _yes_no(server.dhcp_available))
    if server.started_at:
        table.add_row("Started at", server.started_at.astimezone().isoformat())
    console.print(table)


async def _toggle(
    adguard: AdGuardHome,
    feature: Feature,
    *,
    turn_on: bool,
    duration: timedelta | None,
) -> None:
    """Turn a feature on or off."""
    if feature is Feature.PROTECTION:
        if turn_on:
            await adguard.enable_protection()
        else:
            await adguard.disable_protection(duration)
        return

    area = getattr(adguard, feature.value)
    await (area.enable() if turn_on else area.disable())


@cli.command("enable")
async def enable(ctx: typer.Context, feature: Feature) -> None:
    """Turn on a feature of AdGuard Home."""
    async with ctx.obj.client() as adguard:
        await _toggle(adguard, feature, turn_on=True, duration=None)
    console.print(f"[green]Enabled {feature}.[/green]")


@cli.command("disable")
async def disable(
    ctx: typer.Context,
    feature: Feature,
    duration: Annotated[
        timedelta | None,
        typer.Option(
            "--for",
            help="Only pause protection, for a duration like 90s, 10m, or 1h30m",
            parser=parse_duration,
            metavar="DURATION",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Turn off a feature of AdGuard Home."""
    if duration and feature is not Feature.PROTECTION:
        msg = "Only protection can be paused for a while"
        raise typer.BadParameter(msg, param_hint="--for")

    async with ctx.obj.client() as adguard:
        await _toggle(adguard, feature, turn_on=False, duration=duration)

    if duration:
        console.print(f"[yellow]Paused {feature} for {duration}.[/yellow]")
    else:
        console.print(f"[yellow]Disabled {feature}.[/yellow]")


@cli.command("stats")
async def stats(ctx: typer.Context, output_json: JsonFlag = False) -> None:
    """Show the statistics of AdGuard Home."""
    async with ctx.obj.client() as adguard:
        totals = await adguard.stats.get()

    if output_json:
        emit_json(
            dataclasses.asdict(totals)
            | {"blocked_percentage": totals.blocked_percentage}
        )
        return

    table = Table(title="Statistics")
    table.add_column("Property", style="cyan bold")
    table.add_column("Value")
    table.add_row("DNS queries", str(totals.dns_queries))
    table.add_row(
        "Blocked by filters",
        f"{totals.blocked_filtering} ({totals.blocked_percentage:.1f}%)",
    )
    table.add_row("Blocked by safe browsing", str(totals.blocked_safebrowsing))
    table.add_row("Blocked by parental control", str(totals.blocked_parental))
    table.add_row("Enforced safe search", str(totals.enforced_safesearch))
    table.add_row("Average processing time", _milliseconds(totals.avg_processing_time))
    table.add_row("Top queried domains", _top(totals.top_queried_domains))
    table.add_row("Top blocked domains", _top(totals.top_blocked_domains))
    table.add_row("Top clients", _top(totals.top_clients))
    console.print(table)


@cli.command("filters")
async def filters(ctx: typer.Context, output_json: JsonFlag = False) -> None:
    """Show the blocklists and allowlists."""
    async with ctx.obj.client() as adguard:
        filtering = await adguard.filtering.get()

    if output_json:
        emit_json(
            {"blocklists": filtering.blocklists, "allowlists": filtering.allowlists}
        )
        return

    table = Table(title="Filter lists")
    table.add_column("Kind", style="cyan bold")
    table.add_column("Name")
    table.add_column("Enabled")
    table.add_column("Rules", justify="right")
    table.add_column("Updated")
    for kind, filter_lists in (
        ("blocklist", filtering.blocklists),
        ("allowlist", filtering.allowlists),
    ):
        for filter_list in filter_lists:
            updated = filter_list.last_updated
            table.add_row(
                kind,
                _safe(filter_list.name),
                _yes_no(filter_list.enabled),
                str(filter_list.rules_count),
                updated.astimezone().strftime("%Y-%m-%d %H:%M") if updated else "",
            )
    console.print(table)


@cli.command("refresh")
async def refresh(ctx: typer.Context) -> None:
    """Download the latest version of all filter lists."""
    async with ctx.obj.client() as adguard:
        blocklists = await adguard.filtering.blocklists.refresh()
        allowlists = await adguard.filtering.allowlists.refresh()
    console.print(
        f"[green]Updated {blocklists} blocklists and {allowlists} allowlists.[/green]"
    )


@cli.command("check")
async def check(
    ctx: typer.Context,
    host: Annotated[str, typer.Argument(help="The host name to check")],
    client: Annotated[
        str | None,
        typer.Option(help="Check for this client, by IP address or name"),
    ] = None,
    output_json: JsonFlag = False,
) -> None:
    """Check how AdGuard Home filters a host."""
    async with ctx.obj.client() as adguard:
        result = await adguard.filtering.check_host(host, client=client)

    if output_json:
        emit_json(dataclasses.asdict(result) | {"filtered": result.filtered})
        return

    table = Table(title=_safe(host))
    table.add_column("Property", style="cyan bold")
    table.add_column("Value")
    table.add_row("Filtered", _yes_no(result.filtered))
    table.add_row("Reason", result.reason.value)
    for rule in result.rules:
        table.add_row("Rule", _safe(rule.text))
    if result.service_name:
        table.add_row("Blocked service", _safe(result.service_name))
    if result.cname:
        table.add_row("Rewritten to", _safe(result.cname))
    if result.ip_addresses:
        table.add_row("Answer", _safe("\n".join(result.ip_addresses)))
    console.print(table)


@cli.command("log")
async def log(
    ctx: typer.Context,
    search: Annotated[
        str | None,
        typer.Option(help="Only show queries for this domain name or client"),
    ] = None,
    limit: Annotated[
        int, typer.Option(help="The number of entries to show", min=1)
    ] = 20,
    output_json: JsonFlag = False,
) -> None:
    """Show the most recent DNS queries."""
    async with ctx.obj.client() as adguard:
        query_log = await adguard.querylog.get(search=search, limit=limit)

    if output_json:
        emit_json(query_log.entries)
        return

    table = Table(title="Query log")
    table.add_column("Time", style="cyan")
    table.add_column("Client")
    table.add_column("Domain")
    table.add_column("Type")
    table.add_column("Result")
    for entry in query_log.entries:
        client_name = entry.client_info.name if entry.client_info else ""
        result = "[red]blocked[/red]" if entry.filtered else _safe(entry.status or "")
        table.add_row(
            entry.time.astimezone().strftime("%H:%M:%S"),
            _safe(client_name or entry.client_ip),
            _safe(entry.question.unicode_name or entry.question.name),
            _safe(entry.question.type),
            result,
        )
    console.print(table)


@cli.command("clients")
async def clients(ctx: typer.Context, output_json: JsonFlag = False) -> None:
    """Show the configured clients, and the ones AdGuard Home found itself."""
    async with ctx.obj.client() as adguard:
        known = await adguard.clients.get()

    if output_json:
        emit_json({"configured": known.configured, "runtime": known.runtime})
        return

    table = Table(title="Clients")
    table.add_column("Name", style="cyan bold")
    table.add_column("Addresses")
    table.add_column("Source")
    for configured in known.configured:
        table.add_row(
            _safe(configured.name), _safe("\n".join(configured.ids)), "configured"
        )
    for runtime in known.runtime:
        table.add_row(
            _safe(runtime.name), _safe(runtime.ip_address), _safe(runtime.source)
        )
    console.print(table)


@cli.command("update")
async def update(
    ctx: typer.Context,
    recheck: Annotated[
        bool, typer.Option(help="Check for a new version right now")
    ] = False,
    output_json: JsonFlag = False,
) -> None:
    """Show if a new version of AdGuard Home is available."""
    async with ctx.obj.client() as adguard:
        available = await adguard.update.get(recheck=recheck)

    if output_json:
        emit_json(available)
        return

    if available.disabled:
        console.print("[yellow]AdGuard Home does not check for updates.[/yellow]")
        return

    if not available.new_version:
        console.print("[green]AdGuard Home is up to date.[/green]")
        return

    console.print(f"[cyan bold]{_safe(available.announcement)}[/cyan bold]")
    if available.announcement_url:
        console.print(_safe(available.announcement_url))
    if not available.can_autoupdate:
        console.print("AdGuard Home cannot update itself on this system.")


@cli.command("clear-cache")
async def clear_cache(ctx: typer.Context) -> None:
    """Clear the DNS cache of AdGuard Home."""
    async with ctx.obj.client() as adguard:
        await adguard.dns.clear_cache()
    console.print("[green]Cleared the DNS cache.[/green]")
