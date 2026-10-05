# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. This file
follows the [agents.md](https://agents.md) convention. `CLAUDE.md` is a symlink
to this file, so Claude-compatible tooling reads the same guidance.

## What this project is

python-adguardhome is an asynchronous Python client for the
[AdGuard Home][adguard-home] HTTP API, built on aiohttp. It is used by the
Home Assistant AdGuard Home integration.

The library mirrors the API: every feature area of AdGuard Home (filtering,
stats, query log, clients, and so on) is a namespace on the `AdGuardHome`
client, and every API document is a typed, immutable model. The minimum
supported AdGuard Home version is `MINIMUM_VERSION` in `status.py`.

## Project layout

| Path               | Purpose                                                    |
| ------------------ | ---------------------------------------------------------- |
| `src/adguardhome/` | The package                                                |
| `  adguardhome.py` | The `AdGuardHome` client: transport, status, protection    |
| `  _area.py`       | `Area`, the base of every feature area                     |
| `  _model.py`      | `AdGuardHomeModel` and the unit conversion strategies      |
| `  exceptions.py`  | The exception hierarchy                                    |
| `  <area>.py`      | One module per area, holding its models and its namespace  |
| `  toggle.py`      | Parental control and safe browsing, which only turn on/off |
| `tests/`           | pytest suite; each test has a one-line docstring           |
| `tests/fixtures/`  | API responses, in the exact shape AdGuard Home sends them  |
| `examples/`        | Runnable examples                                          |

## Commands

This is a [Poetry][poetry] project that also uses NodeJS for some checks, with
[prek][prek] running the hooks. Set up and run the gate with:

```bash
npm install
poetry install
poetry run prek run --all-files   # lint, format, type, and test hooks
poetry run pytest                 # just the tests
```

During iteration, running a single tool directly is fine and faster:
`poetry run pytest -k ...`, `poetry run ruff check .`, `poetry run ty check src`.

## Conventions

- An area is a subclass of `Area`. It only gets the request method of the
  client, never the client itself. Every area follows the same shape:
  `get()` returns data, `config()` and `set_config()` read and replace
  settings, and actions are verbs like `enable()`, `refresh()`, or `reset()`.
  `enable()` and `disable()` are a read and a write of the config, nothing more.
- Models are frozen, keyword-only dataclasses on `AdGuardHomeModel`. Field
  names say what a value means; the wire name goes in an alias. Durations are
  `timedelta` and timestamps are `datetime`, whatever unit the API uses, and
  versions are `AwesomeVersion`. Parse with `from_api()`, never `from_dict()`.
- The library never leaks a raw exception. `_request` is the only place that
  raises for transport and HTTP errors, and `from_api()` turns bad data into an
  `AdGuardHomeError`. Do not catch and re-raise an `AdGuardHomeError` with a
  new message: that throws away the status code and the message of AdGuard Home.
- A field that is newer than `MINIMUM_VERSION` is optional, defaults to what
  older versions do, and has a comment naming the version that added it. A new
  endpoint, or a new option on an endpoint, raises `MINIMUM_VERSION` instead of
  getting a fallback.
- Verify API behavior against the AdGuard Home source and its
  [API changelog][api-changelog] rather than assuming. The OpenAPI spec is
  useful, but it is not always accurate.
- Coverage is enforced at 100%. New code needs tests.
- Every test carries a one-line docstring describing what it verifies. Tests
  mock HTTP with aiointercept, which runs a real local server, so callbacks see
  the headers and body that actually went over the wire.
- Comments explain the why, not the what. Clarity over cleverness, clear names,
  and blank lines between logical steps.

## Writing and voice

English for all public artifacts (commits, PRs, issues). Held to a high bar:
clear, honest, no filler. Avoid:

- AI cheerleading and marketing speak (leverage, synergize, delight).
- Em-dashes and en-dashes anywhere. Use a period, colon, comma, or parentheses;
  hyphen only for compound words. Restructure a sentence rather than reach for one.
- "e.g.", "i.e.", "etc."; write "like", "for example", "such as".
- CAPS for emphasis (use italics); "click" as a verb (use "select").
- "HA"/"HASS"; write "Home Assistant" in full, and never frame it as fragile.
- "master/slave"; use "client/server", "leader/follower", "main/replica".

See [AI_POLICY.md](AI_POLICY.md) for the contribution policy around AI tooling.

## Gotchas

- AdGuard Home is written in Go, which sends an empty list as `null`.
  `AdGuardHomeModel` drops null values before parsing, so field defaults apply.
- Mashumaro never passes `None` to a serialization strategy, and models omit
  `None` when serializing. An optional field that is `None` is left out of the
  request, which makes AdGuard Home keep or default it.
- Models serialize with their aliases, so a settings model can go straight back
  to the API. A model holding more than the endpoint accepts (like
  `FilteringStatus`) must be narrowed before sending, see `set_config()`.
- Actions answer with a plain `OK` as `text/plain`, which `_request` returns as
  `None`. A request without a body must not carry a content type; aiohttp would
  otherwise send `application/octet-stream`.
- The API still says `whitelist` for allowlists. Keep that on the wire only.
- Filter lists are identified by their URL, which AdGuard Home matches exactly,
  including case. Rewrite rules are identified by their domain and answer.
- AdGuard Home only accepts whole units for durations, like hours for the
  filter update interval and seconds for DNS TTLs. Models reject partial units
  with `require_whole()` instead of rounding them.
- Go sends a time that is not set as `0001-01-01T00:00:00Z`, and an address
  that is not set as an empty string. Models turn both into `None`.
- Settings endpoints mostly keep what is left out of a request. To clear a
  setting, send its empty value; see `DnsConfig.__post_serialize__()`.
- AdGuard Home looks up a query log page by the exact nanosecond time of its
  cursor, which a `datetime` cannot hold. Pass the raw `QueryLog.cursor`.
- `_request` does not follow redirects, since they would resend the body (a
  TLS private key, for example) wherever they point, also to plain HTTP.
- TLS certificates and keys travel base64-encoded, and AdGuard Home never sends
  a saved private key back. `TlsConfig` hides both, and keeps the key out of
  `repr()`. Never log or snapshot a private key.

## Where to read next

- `README.md`: install, usage per area, and the development setup.
- `src/adguardhome/_model.py`: the base model and every unit conversion.
- `src/adguardhome/stats.py`: a complete area with data, config, and actions.

[adguard-home]: https://github.com/AdguardTeam/AdGuardHome
[api-changelog]: https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/CHANGELOG.md
[poetry]: https://python-poetry.org
[prek]: https://github.com/j178/prek
