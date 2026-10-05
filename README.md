# Python: AdGuard Home API Client

[![GitHub Release][releases-shield]][releases]
[![Python Versions][python-versions-shield]][pypi]
![Project Stage][project-stage-shield]
![Project Maintenance][maintenance-shield]
[![License][license-shield]](LICENSE.md)

[![Build Status][build-shield]][build]
[![Code Coverage][codecov-shield]][codecov]
[![OpenSSF Scorecard][scorecard-shield]][scorecard]
[![Open in Dev Containers][devcontainer-shield]][devcontainer]

[![Sponsor Frenck via GitHub Sponsors][github-sponsors-shield]][github-sponsors]

[![Support Frenck on Patreon][patreon-shield]][patreon]

Asynchronous Python client for the AdGuard Home API.

## About

This package allows you to control and monitor an AdGuard Home instance
programmatically. It is mainly created to allow third-party programs to automate
the behavior of AdGuard.

An excellent example of this might be Home Assistant, which allows you to write
automations that turn on parental controls when the kids get home.

## Installation

```bash
pip install adguardhome
```

For the command-line interface, install the `cli` extra:

```bash
pip install "adguardhome[cli]"
```

## CLI

The optional CLI manages AdGuard Home from the terminal. Pass the URL of the
web interface with `--url`, or set `ADGUARD_HOME_URL`, and the username with
`--username`, or `ADGUARD_HOME_USERNAME`. The password comes from
`ADGUARD_HOME_PASSWORD`, or the CLI asks for it. There is no option for it,
so it stays out of your shell history and the process list.

```bash
export ADGUARD_HOME_URL=http://192.168.1.2:3000

# Show the status of AdGuard Home
adguardhome status

# Pause protection for ten minutes, or turn a feature off and on
adguardhome disable protection --for 10m
adguardhome disable parental
adguardhome enable parental

# Show the statistics and the most recent DNS queries
adguardhome stats
adguardhome log --search example.com --limit 50

# Check how a host is filtered, and update the filter lists
adguardhome check ads.example.com --client 192.168.1.20
adguardhome refresh

# Show the filter lists and the clients
adguardhome filters
adguardhome clients

# See if a new AdGuard Home version is available
adguardhome update --recheck

# Clear the DNS cache
adguardhome clear-cache

# Emit machine-readable JSON
adguardhome stats --json
```

## Usage

The client is an async context manager; every API call is a coroutine. A
quick status check looks like this:

```python
import asyncio

from adguardhome import AdGuardHome


async def main() -> None:
    """Show example how to get status of your AdGuard Home instance."""
    async with AdGuardHome("http://192.168.1.2:3000") as adguard:
        status = await adguard.status()
        print("AdGuard version:", status.version)
        print("Protection enabled?", "Yes" if status.protection_enabled else "No")

        if not status.protection_enabled:
            print("AdGuard Home protection disabled. Enabling...")
            await adguard.enable_protection()


if __name__ == "__main__":
    asyncio.run(main())
```

### Feature areas

Each AdGuard Home feature lives under its own namespace on the client.
Short examples per namespace:

**Filtering**: blocklists and allowlists are separate collections with the
same methods. A filter list is identified by its URL:

```python
async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    await adguard.filtering.blocklists.add(
        "https://easylist.to/easylist/easylist.txt", name="EasyList"
    )
    await adguard.filtering.blocklists.disable(
        "https://easylist.to/easylist/easylist.txt"
    )
    print("Lists updated:", await adguard.filtering.blocklists.refresh())

    filtering = await adguard.filtering.get()
    print("Rules loaded:", sum(f.rules_count for f in filtering.blocklists))

    result = await adguard.filtering.check_host("ads.example.com")
    print("Filtered?", result.filtered, result.reason)
```

**Access lists**: which clients may use AdGuard Home, and which hosts it
refuses:

```python
from dataclasses import replace

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    access = await adguard.access.config()
    await adguard.access.set_config(
        replace(access, disallowed_clients=("203.0.113.0/24",))
    )
```

**Blocked services**: block whole services, like TikTok or Steam:

```python
async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    available = await adguard.blocked_services.get()
    print([service.name for service in available.services])

    await adguard.blocked_services.block("tiktok", "steam")
    await adguard.blocked_services.unblock("steam")
```

**Clients**: configured clients with their own settings, and the clients
AdGuard Home found by itself:

```python
from dataclasses import replace

from adguardhome import Client

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    clients = await adguard.clients.get()
    for runtime in clients.runtime:
        print(runtime.ip_address, runtime.name, runtime.source)

    await adguard.clients.add(Client(name="Printer", ids=("192.168.1.50",)))

    kids = next(c for c in clients.configured if c.name == "Kids")
    await adguard.clients.update(kids.name, replace(kids, parental_enabled=True))

    result = (await adguard.clients.search("192.168.1.30"))["192.168.1.30"]
    print("Allowed to connect?", not result.disallowed)
```

**Parental control and safe browsing**: these only turn on and off:

```python
async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    await adguard.parental.enable()
    await adguard.safebrowsing.disable()
    print("Parental control on?", await adguard.parental.enabled())
```

**Safe search**: on and off overall, plus a setting per search engine:

```python
from dataclasses import replace

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    config = await adguard.safesearch.config()
    await adguard.safesearch.set_config(replace(config, enabled=True, youtube=False))
```

**Query log**: read the logged DNS queries page by page, newest first:

```python
async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    log = await adguard.querylog.get(search="example.com", limit=50)
    for entry in log.entries:
        print(entry.time, entry.client_ip, entry.question.name, entry.reason)

    if log.cursor:
        next_page = await adguard.querylog.get(older_than=log.cursor)
```

And enable, disable, set retention, and clear it:

```python
from dataclasses import replace
from datetime import timedelta

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    await adguard.querylog.enable()
    config = await adguard.querylog.config()
    await adguard.querylog.set_config(replace(config, retention=timedelta(days=7)))
    await adguard.querylog.clear()
```

**DHCP server**: settings, leases, and static leases. Only on Linux, macOS,
FreeBSD, and OpenBSD, check `status.dhcp_available` first:

```python
from adguardhome import StaticLease

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    check = await adguard.dhcp.check("eth0")
    if check.v4.other_server.found is False:
        await adguard.dhcp.enable()

    dhcp = await adguard.dhcp.get()
    for lease in dhcp.leases:
        print(lease.hostname, lease.ip, "until", lease.expires)

    await adguard.dhcp.add_static_lease(
        StaticLease(mac="aa:bb:cc:dd:ee:02", ip="192.168.1.5", hostname="nas")
    )
```

**DNS server**: upstreams, caching, rate limiting, and how to block:

```python
from dataclasses import replace

from adguardhome import BlockingMode

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    results = await adguard.dns.test_upstreams(["tls://1.1.1.1"])
    if all(error is None for error in results.values()):
        config = await adguard.dns.config()
        await adguard.dns.set_config(
            replace(
                config,
                upstream_dns=("tls://1.1.1.1",),
                blocking_mode=BlockingMode.NXDOMAIN,
            )
        )
    await adguard.dns.clear_cache()
```

**DNS rewrites**: answer a domain with your own IP address or CNAME:

```python
async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    await adguard.rewrite.add("nas.lan", "192.168.1.5")
    await adguard.rewrite.update("nas.lan", "192.168.1.5", new_answer="192.168.1.6")
    await adguard.rewrite.update("nas.lan", "192.168.1.6", enabled=False)
    for rule in await adguard.rewrite.get():
        print(rule.domain, "->", rule.answer, "(on)" if rule.enabled else "(off)")
    await adguard.rewrite.remove("nas.lan", "192.168.1.6")

    await adguard.rewrite.disable()  # stop applying all rules, keep them
```

**Stats**: one request returns totals, top lists, and history:

```python
from dataclasses import replace
from datetime import timedelta

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    stats = await adguard.stats.get()
    print("Queries:", stats.dns_queries)
    print(f"Blocked: {stats.blocked_percentage:.1f}%")
    print("Avg processing time:", stats.avg_processing_time)
    print("Top client:", next(iter(stats.top_clients), None))

    config = await adguard.stats.config()
    await adguard.stats.set_config(replace(config, retention=timedelta(days=7)))
```

**Encryption**: HTTPS, DNS-over-TLS, DNS-over-QUIC, and the certificate.
Certificates and keys are plain PEM text; AdGuard Home never sends a saved
private key back:

```python
from dataclasses import replace

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    tls = await adguard.tls.get()
    print("Certificate valid until:", tls.not_after)

    new = replace(tls, certificate_chain=chain_pem, private_key=key_pem)
    result = await adguard.tls.validate(new)
    if result.valid_pair:
        await adguard.tls.set_config(new)
```

**Update check**: see if a new AdGuard Home release is available, and let
AdGuard Home update itself:

```python
async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    update = await adguard.update.get(recheck=True)
    if update.new_version and update.can_autoupdate:
        await adguard.update.install()
```

### Connection options

Point the client at the URL of the AdGuard Home web interface, the same one
you open in your browser. Everything else is keyword-only:

```python
AdGuardHome(
    "https://example.com/adguard",  # also works behind a reverse proxy
    username="admin",               # HTTP basic auth (optional)
    password="secret",              # noqa: S106
    verify_ssl=True,                # set to False to accept self-signed certs
    request_timeout=10,             # per-request timeout in seconds
)
```

### Supported versions

This library supports AdGuard Home v0.107.68 and newer. Check
`status.supported` to see if the server you connect to qualifies. An API the
server does not know raises `AdGuardHomeUnsupportedError`.

### Protection

Disable protection for good, or pause it for a while. AdGuard Home enables
it again by itself once the pause is over:

```python
from datetime import timedelta

async with AdGuardHome("http://192.168.1.2:3000") as adguard:
    await adguard.disable_protection(timedelta(minutes=10))
    status = await adguard.status()
    print("Protection resumes in:", status.protection_resumes_in)
```

You may also pass your own `aiohttp.ClientSession` via `session=...` to
share a connection pool across multiple clients.

## Changelog & Releases

This repository keeps a change log using [GitHub's releases][releases]
functionality. The format of the log is based on
[Keep a Changelog][keepchangelog].

Releases are based on [Semantic Versioning][semver], and use the format
of `MAJOR.MINOR.PATCH`. In a nutshell, the version will be incremented
based on the following:

- `MAJOR`: Incompatible or major changes.
- `MINOR`: Backwards-compatible new features and enhancements.
- `PATCH`: Backwards-compatible bugfixes and package updates.

## Contributing

This is an active open-source project. We are always open to people who want to
use the code or contribute to it.

We've set up a separate document for our
[contribution guidelines](CONTRIBUTING.md).

Thank you for being involved! :heart_eyes:

## Setting up development environment

This Python project is fully managed using the [Poetry][poetry] dependency
manager. But also relies on the use of NodeJS for certain checks during
development.

You need at least:

- Python 3.11+
- [Poetry][poetry-install]
- NodeJS 24+ (including NPM)

To install all packages, including all development requirements:

```bash
npm install
poetry install
```

As this repository uses the [prek][prek] framework, all changes
are linted and tested with each commit. You can run all checks and tests
manually, using the following command:

```bash
poetry run prek run --all-files
```

To run just the Python tests:

```bash
poetry run pytest
```

## Authors & contributors

The original setup of this repository is by [Franck Nijhof][frenck].

For a full list of all authors and contributors,
check [the contributor's page][contributors].

## License

MIT License

Copyright (c) 2019-2026 Franck Nijhof

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

[build-shield]: https://github.com/frenck/python-adguardhome/actions/workflows/tests.yaml/badge.svg
[build]: https://github.com/frenck/python-adguardhome/actions/workflows/tests.yaml
[codecov-shield]: https://codecov.io/gh/frenck/python-adguardhome/branch/main/graph/badge.svg
[codecov]: https://codecov.io/gh/frenck/python-adguardhome
[contributors]: https://github.com/frenck/python-adguardhome/graphs/contributors
[devcontainer-shield]: https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue&logo=visualstudiocode
[devcontainer]: https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/frenck/python-adguardhome
[frenck]: https://github.com/frenck
[github-sponsors-shield]: https://frenck.dev/wp-content/uploads/2019/12/github_sponsor.png
[github-sponsors]: https://github.com/sponsors/frenck
[keepchangelog]: http://keepachangelog.com/en/1.0.0/
[license-shield]: https://img.shields.io/github/license/frenck/python-adguardhome.svg
[maintenance-shield]: https://img.shields.io/maintenance/yes/2026.svg
[patreon-shield]: https://frenck.dev/wp-content/uploads/2019/12/patreon.png
[patreon]: https://www.patreon.com/frenck
[poetry-install]: https://python-poetry.org/docs/#installation
[poetry]: https://python-poetry.org
[prek]: https://github.com/j178/prek
[project-stage-shield]: https://img.shields.io/badge/project%20stage-production%20ready-brightgreen.svg
[pypi]: https://pypi.org/project/adguardhome/
[python-versions-shield]: https://img.shields.io/pypi/pyversions/adguardhome
[releases-shield]: https://img.shields.io/github/release/frenck/python-adguardhome.svg
[releases]: https://github.com/frenck/python-adguardhome/releases
[scorecard]: https://scorecard.dev/viewer/?uri=github.com/frenck/python-adguardhome
[scorecard-shield]: https://api.scorecard.dev/projects/github.com/frenck/python-adguardhome/badge
[semver]: http://semver.org/spec/v2.0.0.html
