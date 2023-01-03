# Python: AdGuard Home API Client

[![GitHub Release][releases-shield]][releases]
[![Python Versions][python-versions-shield]][pypi]
![Project Stage][project-stage-shield]
![Project Maintenance][maintenance-shield]
[![License][license-shield]](LICENSE.md)

[![Build Status][build-shield]][build]
[![Code Coverage][codecov-shield]][codecov]
[![Code Quality][code-quality-shield]][code-quality]
[![Deepcode.ai][deepcode-shield]][deepcode]

[![Sponsor Frenck via GitHub Sponsors][github-sponsors-shield]][github-sponsors]

[![Support Frenck on Patreon][patreon-shield]][patreon]

Asynchronous Python client for the AdGuard Home API.

## About

This package allows you to control and monitor an AdGuard Home instance
programmatically. It is mainly created to allow third-party programs to automate
the behavior of AdGuard.

An excellent example of this might be Home Assistant, which allows you to write
automations, to turn on parental controls when the kids get home.

## Installation

```bash
pip install adguardhome
```

## Usage

```python
from adguardhome import AdGuardHome

import asyncio


async def main():
    """Show example how to get status of your AdGuard Home instance."""
    async with AdGuardHome("192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        active = await adguard.protection_enabled()
        active = "Yes" if active else "No"
        print("Protection enabled?", active)

        if not active:
            print("AdGuard Home protection disabled. Enabling...")
            await adguard.enable_protection()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```

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

- Python 3.7+
- [Poetry][poetry-install]
- NodeJS 12+ (including NPM)

To install all packages, including all development requirements:

```bash
npm install
poetry install
```

As this repository uses the [pre-commit][pre-commit] framework, all changes
are linted and tested with each commit. You can run all checks and tests
manually, using the following command:

```bash
poetry run pre-commit run --all-files
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

Copyright (c) 2019-2023 Franck Nijhof

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
[code-quality-shield]: https://img.shields.io/lgtm/grade/python/g/frenck/python-adguardhome.svg?logo=lgtm&logoWidth=18
[code-quality]: https://lgtm.com/projects/g/frenck/python-adguardhome/context:python
[codecov-shield]: https://codecov.io/gh/frenck/python-adguardhome/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/frenck/python-adguardhome
[contributors]: https://github.com/frenck/python-adguardhome/graphs/contributors
[deepcode-shield]: https://www.deepcode.ai/api/gh/badge?key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbGF0Zm9ybTEiOiJnaCIsIm93bmVyMSI6ImZyZW5jayIsInJlcG8xIjoicHl0aG9uLWVsZ2F0byIsImluY2x1ZGVMaW50IjpmYWxzZSwiYXV0aG9ySWQiOjI4MDU1LCJpYXQiOjE2MTUxODgzODh9.hJsD6PTw8K8bnTmHUzroQi7XkXRi46bdt-oMqx2zXj0
[deepcode]: https://www.deepcode.ai/app/gh/frenck/python-adguardhome/_/dashboard?utm_content=gh%2Ffrenck%2Fpython-adguardhome
[frenck]: https://github.com/frenck
[github-sponsors-shield]: https://frenck.dev/wp-content/uploads/2019/12/github_sponsor.png
[github-sponsors]: https://github.com/sponsors/frenck
[keepchangelog]: http://keepachangelog.com/en/1.0.0/
[license-shield]: https://img.shields.io/github/license/frenck/python-adguardhome.svg
[maintenance-shield]: https://img.shields.io/maintenance/yes/2023.svg
[patreon-shield]: https://frenck.dev/wp-content/uploads/2019/12/patreon.png
[patreon]: https://www.patreon.com/frenck
[project-stage-shield]: https://img.shields.io/badge/project%20stage-experimental-yellow.svg
[releases-shield]: https://img.shields.io/github/release/frenck/python-adguardhome.svg
[releases]: https://github.com/frenck/python-adguardhome/releases
[semver]: http://semver.org/spec/v2.0.0.html
[poetry-install]: https://python-poetry.org/docs/#installation
[poetry]: https://python-poetry.org
[pre-commit]: https://pre-commit.com/
[pypi]: https://pypi.org/project/adguardhome/
[python-versions-shield]: https://img.shields.io/pypi/pyversions/adguardhome
