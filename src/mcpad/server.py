# Copyright 2026 Matteo Redaelli
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""FastMCP server exposing the msad Active Directory / LDAP library as MCP tools.

Each tool opens a short-lived connection using the msad configuration
(``~/.msad.toml`` by default, or the ``MSAD_DOMAIN`` / ``MSAD_CONFIG_FILE``
environment variables) and calls the corresponding msad library function.

Run it with:

    uv run mcpad            # stdio transport (for MCP clients)
    fastmcp run src/mcpad/server.py
"""

from __future__ import annotations

import datetime
import os
from typing import Any

import msad
from fastmcp import FastMCP
from msad.exceptions import MsadError

mcp: FastMCP = FastMCP(
    name="mcpAD",
    instructions=(
        "Query Active Directory / LDAP via the msad library: search users and "
        "groups, inspect memberships, and check account status. All tools are "
        "read-only."
    ),
)

# Default domain / config file can be overridden per environment.
_DEFAULT_DOMAIN = os.environ.get("MSAD_DOMAIN") or None
_CONFIG_FILE = os.environ.get("MSAD_CONFIG_FILE") or None


def _jsonable(value: Any) -> Any:
    """Make LDAP values JSON-serializable (datetimes -> ISO strings)."""
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


class _Session:
    """Resolve config and open a bound connection, raising MsadError on failure."""

    def __init__(self, domain: str | None) -> None:
        self.config = msad.load_domain_config(domain or _DEFAULT_DOMAIN, _CONFIG_FILE)
        self.conn = msad.connect(self.config)

    @property
    def base(self) -> str:
        return self.config.search_base


@mcp.tool
def find_users(
    name: str | None = None,
    surname: str | None = None,
    mail: str | None = None,
    sam: str | None = None,
    department: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD users by field. Criteria are ANDed; values may contain * wildcards."""
    s = _Session(domain)
    result = msad.find_users(
        s.conn,
        s.base,
        name=name,
        surname=surname,
        mail=mail,
        sam=sam,
        department=department,
        limit=limit,
    )
    return _jsonable(result)


@mcp.tool
def get_user(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD user by sAMAccountName, UPN, mail or cn (exact match)."""
    s = _Session(domain)
    return _jsonable(msad.get_user(s.conn, s.base, identifier))


@mcp.tool
def find_groups(string: str, limit: int = 100, domain: str | None = None) -> list[dict[str, Any]]:
    """Find AD groups by cn/name/sAMAccountName/displayName (supports * wildcards)."""
    s = _Session(domain)
    return _jsonable(msad.find_groups(s.conn, s.base, string, limit=limit))


@mcp.tool
def get_group(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD group by sAMAccountName or cn (exact match)."""
    s = _Session(domain)
    return _jsonable(msad.get_group(s.conn, s.base, identifier))


@mcp.tool
def get_by_dn(dn: str, domain: str | None = None) -> dict[str, Any] | None:
    """Fetch any AD entry directly by its distinguished name (DN).

    Use this to resolve DN-valued attributes into full records, e.g. the
    `manager` of a user or the `managedBy` owner of a group. Returns None if
    the DN does not exist.
    """
    s = _Session(domain)
    return _jsonable(msad.get_by_dn(s.conn, dn))


@mcp.tool
def find_computers(
    name: str | None = None,
    dns: str | None = None,
    os: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD computers by cn (name), dNSHostName (dns) or operatingSystem (os).

    Criteria are ANDed; values may contain * wildcards.
    """
    s = _Session(domain)
    return _jsonable(
        msad.find_computers(s.conn, s.base, name=name, dns=dns, os=os, limit=limit)
    )


@mcp.tool
def get_computer(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD computer by sAMAccountName, cn or dNSHostName (exact match)."""
    s = _Session(domain)
    return _jsonable(msad.get_computer(s.conn, s.base, identifier))


@mcp.tool
def group_members(
    group: str, nested: bool = False, limit: int = 1000, domain: str | None = None
) -> list[dict[str, Any]]:
    """List members of a group. Set nested=True for recursive membership."""
    s = _Session(domain)
    return _jsonable(msad.group_members(s.conn, s.base, group, nested=nested, limit=limit))


@mcp.tool
def user_groups(
    user: str, nested: bool = True, limit: int = 1000, domain: str | None = None
) -> list[dict[str, Any]] | None:
    """List the groups a user belongs to (nested/recursive by default)."""
    s = _Session(domain)
    return _jsonable(msad.user_groups(s.conn, s.base, limit, user, nested=nested))


@mcp.tool
def is_member(group: str, user: str, domain: str | None = None) -> bool:
    """Return True if the user is a (nested) member of the group."""
    s = _Session(domain)
    return msad.is_member(s.conn, s.base, group, user)


@mcp.tool
def is_disabled(user: str, domain: str | None = None) -> bool | None:
    """Return True if the account is disabled, None if the user is not found."""
    s = _Session(domain)
    return msad.is_disabled(s.conn, s.base, user)


@mcp.tool
def is_locked(user: str, domain: str | None = None) -> bool | None:
    """Return True if the account is locked, None if the user is not found."""
    s = _Session(domain)
    return msad.is_locked(s.conn, s.base, user)


def main() -> None:
    """Entry point. Transport/host/port are read from the environment.

    - MCP_TRANSPORT: "stdio" (default), "http", "sse" or "streamable-http"
    - MCP_HOST:      bind host for HTTP transports (default 127.0.0.1)
    - MCP_PORT:      bind port for HTTP transports (default 8000)
    """
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        host = os.environ.get("MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("MCP_PORT", "8000"))
        mcp.run(transport=transport, host=host, port=port)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()


__all__ = ["mcp", "main", "MsadError"]
