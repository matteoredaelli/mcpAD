# AGENTS.md — notes for coding agents working on mcpAD

This file is for AI coding agents. It covers things that aren't in the
README (install/usage/tool list) but matter when *changing code* here.

## What this repo is

A single-file FastMCP server (`src/mcpad/server.py`, ~1200 lines) exposing
`msad` functions as MCP tools. There is **no test suite** in this repo
(lint + `pyrefly check` only) — verify changes with a manual smoke check,
e.g.:

```python
import asyncio
from mcpad import server
asyncio.run(server.mcp.list_tools())   # confirm the tool is registered
asyncio.run(server.mcp.call_tool("your_tool", {...}))
```

This is a sibling project to `restAD` and `graphqlAD`: all three wrap the
same `msad` functions through a different protocol. When `msad` gains a new
function, it is expected to show up here too (a new `@tool`), and in the
other two repos.

## Adding a new tool — required plumbing, not just the function

Every tool must use the `@tool` decorator (not the bare `@mcp.tool`) —
it's what wires in audit logging and the `MCPAD_MAX_LIMIT` clamp on any
`limit` argument. Read-only by default; pass `@tool(destructive=True)` only
for genuine write operations (currently just `add_member`,
`remove_member`, `unlock_user`) — this flips the MCP `readOnlyHint`/
`destructiveHint` annotations a client uses to gauge risk, so don't mark
something destructive just because it "could" be, and don't leave an actual
write tool without it.

Wrap list/dict results through `_present()` (decodes raw AD attributes when
`MCPAD_DECODE_ATTRS` is on, then JSON-serializes) — use `_jsonable()` alone
only for non-entry results (bools, summaries). Open a session with
`_Session(domain)` at the top of the tool body; don't call
`msad.load_domain_config`/`msad.connect` directly outside that helper.

## Write tools are guarded — don't bypass the guard-rails

Write tools are opt-in (`MCPAD_ALLOW_WRITE`) and, even then, refuse to touch
accounts/groups matching `_is_protected_account` / `_is_protected_group`
(built-in admin/service-account patterns plus
`MCPAD_PROTECTED_ACCOUNTS`/`MCPAD_PROTECTED_GROUPS`). If you add a new write
tool, call these checks the same way the existing three do — do not add a
write path that skips them, even for an operation that seems low-risk.

## Kerberos is an optional extra

`[project.optional-dependencies] kerberos = ["msad[kerberos]>=..."]` mirrors
msad's own extra. Don't add `gssapi` to the base `dependencies`.

## Versioning — do not hand-edit

Version comes from the Git tag via `hatch-vcs`, same setup as `msad` (see
`msad`'s AGENTS.md for the mechanics and the `fetch-depth: 0` CI gotcha).
`__version__` lives in `src/mcpad/__init__.py`; `server.py` keeps its own
`_MCPAD_VERSION` (duplicated, not imported from the package `__init__`, to
avoid a circular import since `__init__.py` imports `server`) and surfaces
it via the `health` tool alongside `msad.__version__`. Never hardcode a
version string anywhere else.

## Keeping `msad` in sync

When bumping the `msad>=` pin in `pyproject.toml`, run:

```bash
uv lock --upgrade-package msad --refresh-package msad
```

Plain `--upgrade-package` without `--refresh-package` can silently resolve
against a stale cached version of msad's metadata right after a new release.

Run `make lint` (ruff check + format check + pyrefly strict) before
considering a change done.
