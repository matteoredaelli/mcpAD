# Copyright 2026 Matteo Redaelli
# mcpAD - MCP server for Active Directory / LDAP (built on msad)
# Copyright (C) 2026 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
        return self.config.base


@mcp.tool
def test_connection(domain: str | None = None) -> dict[str, Any]:
    """Test connectivity and bind to the AD server without raising.

    Returns a status dict with `ok`, `target`, `auth` and `error`. Use this to
    verify the configuration and reachability before running other tools.
    """
    config = msad.load_domain_config(domain or _DEFAULT_DOMAIN, _CONFIG_FILE)
    return _jsonable(msad.check_connection(config))


@mcp.tool
def health(domain: str | None = None) -> dict[str, Any]:
    """Server health check: reports server name, msad version and AD connectivity."""
    result: dict[str, Any] = {
        "server": mcp.name,
        "msad_version": msad.__version__,
    }
    try:
        config = msad.load_domain_config(domain or _DEFAULT_DOMAIN, _CONFIG_FILE)
        result["connection"] = _jsonable(msad.check_connection(config))
    except MsadError as exc:
        # Config could not be loaded (missing file, unknown domain, ...).
        result["connection"] = {"ok": False, "error": str(exc)}
    result["ok"] = bool(result["connection"].get("ok"))
    return result


@mcp.tool
def find_users(
    name: str | None = None,
    surname: str | None = None,
    mail: str | None = None,
    sam: str | None = None,
    department: str | None = None,
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD users by field. Criteria are ANDed; values may contain * wildcards.

    Pass `base` (a DN, e.g. an OU) to restrict the search to a subtree.
    """
    s = _Session(domain)
    result = msad.find_users(
        s.conn,
        base or s.base,
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
def find_groups(
    string: str, base: str | None = None, limit: int = 100, domain: str | None = None
) -> list[dict[str, Any]]:
    """Find AD groups by cn/name/sAMAccountName/displayName (supports * wildcards).

    Pass `base` (a DN, e.g. an OU) to restrict the search to a subtree.
    """
    s = _Session(domain)
    return _jsonable(msad.find_groups(s.conn, base or s.base, string, limit=limit))


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
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD computers by cn (name), dNSHostName (dns) or operatingSystem (os).

    Criteria are ANDed; values may contain * wildcards. Pass `base` (a DN, e.g.
    an OU) to restrict the search to a subtree.
    """
    s = _Session(domain)
    return _jsonable(
        msad.find_computers(s.conn, base or s.base, name=name, dns=dns, os=os, limit=limit)
    )


@mcp.tool
def get_computer(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD computer by sAMAccountName, cn or dNSHostName (exact match)."""
    s = _Session(domain)
    return _jsonable(msad.get_computer(s.conn, s.base, identifier))


@mcp.tool
def find_ous(
    name: str | None = None,
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD organizational units (OUs) by name (matches `ou`; may contain *).

    Pass `base` (a DN) to search under a specific parent OU instead of the
    whole domain.
    """
    s = _Session(domain)
    return _jsonable(msad.find_ous(s.conn, base or s.base, name=name, limit=limit))


@mcp.tool
def get_ou(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD organizational unit by its `ou` name or full DN (exact)."""
    s = _Session(domain)
    return _jsonable(msad.get_ou(s.conn, s.base, identifier))


@mcp.tool
def get_ou_contents(
    ou_dn: str,
    object_class: str | None = None,
    limit: int = 1000,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List the objects contained under an OU (given its DN).

    Optionally restrict to a single `object_class` (e.g. user, group, computer,
    organizationalUnit). Returns an empty list if the OU DN does not exist.
    """
    s = _Session(domain)
    return _jsonable(msad.get_ou_contents(s.conn, ou_dn, object_class=object_class, limit=limit))


@mcp.tool
def find_inactive_users(
    days: int = 90,
    base: str | None = None,
    include_never: bool = False,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find users whose last logon is older than `days` (default 90).

    Matches `lastLogonTimestamp` at or before the cutoff. Set
    `include_never=True` to also return users that never logged on. Pass
    `base` (a DN) to scope to an OU.
    """
    s = _Session(domain)
    return _jsonable(
        msad.find_inactive_users(
            s.conn, base or s.base, days=days, include_never=include_never, limit=limit
        )
    )


@mcp.tool
def find_stale_computers(
    days: int = 90,
    base: str | None = None,
    include_never: bool = False,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find computers whose last logon is older than `days` (default 90).

    Matches `lastLogonTimestamp` at or before the cutoff. Set
    `include_never=True` to also return computers that never logged on. Pass
    `base` (a DN) to scope to an OU.
    """
    s = _Session(domain)
    return _jsonable(
        msad.find_stale_computers(
            s.conn, base or s.base, days=days, include_never=include_never, limit=limit
        )
    )


@mcp.tool
def get_domain_info(domain: str | None = None) -> dict[str, Any] | None:
    """Read the domain object: security-relevant settings and metadata (audit)."""
    s = _Session(domain)
    return _jsonable(msad.get_domain_info(s.conn, s.base))


@mcp.tool
def get_password_policy(domain: str | None = None) -> dict[str, Any] | None:
    """Read the default domain password policy (maxPwdAge, minPwdLength, ...)."""
    s = _Session(domain)
    return _jsonable(msad.get_password_policy(s.conn, s.base))


@mcp.tool
def get_password_policy_violations(
    include_never_set: bool = True,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find users whose password violates the domain policy (audit).

    Flags enabled users whose password has expired (older than the domain
    `maxPwdAge`) and, when `include_never_set` is True, users who must set a
    password at next logon (`pwdLastSet=0`). Accounts whose password never
    expires are excluded. Returns an empty list if the domain has no maximum
    password age.
    """
    s = _Session(domain)
    return _jsonable(
        msad.get_password_policy_violations(
            s.conn, s.base, include_never_set=include_never_set, limit=limit
        )
    )


@mcp.tool
def get_privileged_groups(
    with_members: bool = False,
    nested: bool = False,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Report on well-known privileged groups (Domain Admins, ...) with counts.

    Each entry includes the group's attributes plus `member_count`. Set
    `with_members=True` to include a `members` list (use `nested=True` to
    expand nested membership).
    """
    s = _Session(domain)
    return _jsonable(
        msad.get_privileged_groups(s.conn, s.base, with_members=with_members, nested=nested)
    )


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
