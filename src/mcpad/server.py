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
import functools
import json
import logging
import os
import re
import time
from collections.abc import Callable
from typing import Any

import msad
from fastmcp import FastMCP
from msad.exceptions import MsadError

mcp: FastMCP = FastMCP(
    name="mcpAD",
    instructions=(
        "Query Active Directory / LDAP via the msad library: search users and "
        "groups, inspect memberships, check account status and run read-only "
        "security audits. Write tools (group membership changes) are disabled "
        "by default and only registered when MCPAD_ALLOW_WRITE is enabled."
    ),
)

# Default domain / config file can be overridden per environment.
_DEFAULT_DOMAIN = os.environ.get("MSAD_DOMAIN") or None
_CONFIG_FILE = os.environ.get("MSAD_CONFIG_FILE") or None


def _env_flag(name: str) -> bool:
    """Return True if the environment variable `name` is set to a truthy value."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Return the environment variable `name` as a positive int, else `default`.

    A missing, empty, non-numeric or non-positive value falls back to the
    default, so a mistyped cap can never silently disable the protection.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


# Hard cap on the number of rows any single tool may request from AD, to keep
# responses bounded and avoid inadvertent load on a domain controller. A tool's
# own `limit` is clamped to this ceiling; callers can still ask for less.
# Override with MCPAD_MAX_LIMIT (positive integer; default 1000).
_MAX_LIMIT = _env_int("MCPAD_MAX_LIMIT", 1000)


# Decode raw AD attributes (userAccountControl -> flags, FILETIME -> ISO-8601,
# objectSid / objectGUID -> canonical strings, groupType -> scope) into
# human-/LLM-friendly companion keys on entry results. Non-destructive: the raw
# attributes are kept. On by default; set MCPAD_DECODE_ATTRS to a falsy value
# (0/false/no/off) to return raw attributes only.
_DECODE_ATTRS = os.environ.get("MCPAD_DECODE_ATTRS", "1").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


# Write tools (group membership changes) are opt-in: the server stays read-only
# unless the operator explicitly enables them.
_ALLOW_WRITE = _env_flag("MCPAD_ALLOW_WRITE")


def _env_list(name: str) -> list[str]:
    """Parse a comma-separated environment variable into a list of trimmed items."""
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


# --- Write safety guard-rails ----------------------------------------------
#
# Even when writes are enabled, membership changes that touch sensitive
# accounts or privileged groups are refused. The defaults below are matched
# case-insensitively against sAMAccountName / cn and can be extended via the
# MCPAD_PROTECTED_ACCOUNTS / MCPAD_PROTECTED_GROUPS environment variables
# (comma-separated). Set MCPAD_DISABLE_GUARDRAILS=1 to turn the checks off
# entirely (not recommended).

#: Accounts that must never be modified through this server.
_PROTECTED_ACCOUNTS = {
    name.lower()
    for name in (
        "administrator",
        "admin",
        "krbtgt",
        "guest",
        "system",
    )
    + tuple(_env_list("MCPAD_PROTECTED_ACCOUNTS"))
}

#: Regex patterns for account names that are treated as protected (service /
#: machine accounts). Matched case-insensitively against the identifier.
_SERVICE_ACCOUNT_PATTERNS = [
    r".*\$$",  # machine accounts (end with $)
    r"svc_.*",  # svc_*
    r"service_.*",  # service_*
    r"sa_.*",  # sa_*
    r"adm_.*",  # adm_*
    r"sys_.*",  # sys_*
]

#: Privileged / critical groups that membership changes must never touch.
_PROTECTED_GROUPS = {
    name.lower()
    for name in (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "group policy creator owners",
        "dnsadmins",
        "domain users",  # critical system group: removals would be destructive
    )
    + tuple(_env_list("MCPAD_PROTECTED_GROUPS"))
}

_GUARDRAILS_ENABLED = not _env_flag("MCPAD_DISABLE_GUARDRAILS")


def _rdn_value(identifier: str) -> str:
    """Return the leaf label of a DN (the first RDN value), else the string itself.

    ``CN=John Doe,OU=Staff,DC=x`` -> ``John Doe``; ``jdoe`` -> ``jdoe``. Used so
    the guard-rails match whether the caller passed a sAMAccountName or a DN.
    """
    head = identifier.split(",", 1)[0]
    return head.split("=", 1)[1] if "=" in head else head


def _is_protected_account(identifier: str) -> bool:
    """Return True if `identifier` names a protected or service/machine account."""
    value = _rdn_value(identifier).lower()
    if value in _PROTECTED_ACCOUNTS:
        return True
    return any(re.fullmatch(pattern, value) for pattern in _SERVICE_ACCOUNT_PATTERNS)


def _is_protected_group(identifier: str) -> bool:
    """Return True if `identifier` names a protected / critical group."""
    return _rdn_value(identifier).lower() in _PROTECTED_GROUPS


class _GuardRailError(Exception):
    """Raised when a write is refused by the safety guard-rails."""


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


def _present(value: Any) -> Any:
    """Decode raw AD entries (when MCPAD_DECODE_ATTRS is on) then JSON-serialize.

    Use for tool results that are LDAP entries (a dict) or a list of entries:
    the decoding (via ``msad.decode_entry`` / ``decode_entries``) runs on the
    *raw* values — before :func:`_jsonable` turns FILETIME ints and binary
    SID/GUID blobs into strings — and adds ``*_decoded`` / ``*_iso`` companion
    keys without touching the originals. With decoding off, it is exactly
    ``_jsonable``.
    """
    if _DECODE_ATTRS:
        if isinstance(value, list):
            value = msad.decode_entries(value)
        elif isinstance(value, dict):
            value = msad.decode_entry(value)
    return _jsonable(value)


class _Session:
    """Resolve config and open a bound connection, raising MsadError on failure."""

    def __init__(self, domain: str | None) -> None:
        self.config = msad.load_domain_config(domain or _DEFAULT_DOMAIN, _CONFIG_FILE)
        self.conn = msad.connect(self.config)

    @property
    def base(self) -> str:
        return self.config.base


# --- Audit logging ---------------------------------------------------------
#
# When MCPAD_AUDIT_LOG points to a file, every tool call is appended to it as
# one JSON object per line (JSON-lines): timestamp, tool name, (redacted)
# arguments, status, duration and any error. This is opt-in and off by default.

_AUDIT_LOG_PATH = os.environ.get("MCPAD_AUDIT_LOG") or None

#: Argument names whose values must never be written to the audit log.
_AUDIT_REDACT_KEYS = {
    "password",
    "new_password",
    "old_password",
    "pass",
    "pwd",
    "secret",
    "token",
}

_audit_logger: logging.Logger | None = None


def _get_audit_logger() -> logging.Logger | None:
    """Return a file logger for the audit trail, or None when disabled."""
    global _audit_logger
    if not _AUDIT_LOG_PATH:
        return None
    if _audit_logger is not None:
        return _audit_logger

    logger = logging.getLogger("mcpad.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        try:
            directory = os.path.dirname(_AUDIT_LOG_PATH)
            if directory:
                os.makedirs(directory, exist_ok=True)
            handler: logging.Handler = logging.FileHandler(_AUDIT_LOG_PATH, encoding="utf-8")
        except OSError as exc:
            # Never let an unwritable audit path break tool execution.
            logging.getLogger(__name__).warning(
                "mcpAD audit log disabled: cannot open %r (%s)", _AUDIT_LOG_PATH, exc
            )
            return None
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    _audit_logger = logger
    return logger


def _redact(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of kwargs with sensitive values masked."""
    redacted: dict[str, Any] = {}
    for key, value in kwargs.items():
        if key.lower() in _AUDIT_REDACT_KEYS:
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted


def _write_audit(entry: dict[str, Any]) -> None:
    """Append one audit entry as a JSON line, swallowing any logging error."""
    logger = _get_audit_logger()
    if logger is None:
        return
    try:
        logger.info(json.dumps(entry, default=str, ensure_ascii=False))
    except (TypeError, ValueError):
        logging.getLogger(__name__).debug("failed to serialize audit entry", exc_info=True)


def _classify_outcome(result: Any) -> str:
    """Map a tool's returned payload to a business-outcome label for the audit log.

    This complements ``status`` (which only records whether the Python call
    raised). The labels describe what actually happened:

    - ``preview``   — a two-phase write returned its confirmation preview and
      changed nothing (``status="confirmation_required"``).
    - ``blocked``   — a safety guard-rail refused the write (``status="error"``).
    - ``applied``   — a write was confirmed and executed (``status="success"``).
    - ``completed`` — a read-only tool returned normally (the common case).

    (The ``failed`` label is set directly by the wrapper when a call raises.)
    """
    if isinstance(result, dict):
        business = result.get("status")
        if business == "confirmation_required":
            return "preview"
        if business == "error":
            return "blocked"
        if business == "success":
            return "applied"
    return "completed"


def _audited(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a tool function so each call is recorded to the audit log (if enabled)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not _AUDIT_LOG_PATH:
            return fn(*args, **kwargs)
        start = time.monotonic()
        entry: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.UTC).isoformat(),
            "tool": fn.__name__,
            "params": _redact(kwargs),
        }
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            entry["status"] = "error"
            entry["outcome"] = "failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
            _write_audit(entry)
            raise
        entry["status"] = "ok"
        entry["outcome"] = _classify_outcome(result)
        entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
        _write_audit(entry)
        return result

    return wrapper


def _cap_limits(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Clamp a tool's ``limit`` keyword to ``_MAX_LIMIT`` before it runs.

    A tool invoked with ``limit`` above the ceiling (or ``limit=0``, which msad
    treats as "no limit") has it rewritten to ``_MAX_LIMIT``. Applied beneath
    the audit wrapper so the log records the effective, capped value.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        limit = kwargs.get("limit")
        if isinstance(limit, int) and not isinstance(limit, bool):
            if limit <= 0 or limit > _MAX_LIMIT:
                kwargs["limit"] = _MAX_LIMIT
        return fn(*args, **kwargs)

    return wrapper


def tool(fn: Callable[..., Any] | None = None, *, destructive: bool = False) -> Any:
    """Register `fn` as an MCP tool, wrapped with audit logging and annotations.

    Drop-in replacement for the bare ``@mcp.tool`` decorator used throughout
    this module, so every tool is covered by the audit trail automatically and
    advertises standard MCP behavior hints to the client:

    - default (``@tool``): a read-only tool — ``readOnlyHint: true``.
    - ``@tool(destructive=True)``: a write tool — ``readOnlyHint: false`` and
      ``destructiveHint: true`` so the client treats it as mutating.

    The hints let an MCP client reason about a tool's risk without parsing its
    name or docstring. Every tool's ``limit`` argument is also clamped to
    ``MCPAD_MAX_LIMIT`` (see :func:`_cap_limits`).
    """
    annotations = (
        {"readOnlyHint": False, "destructiveHint": True} if destructive else {"readOnlyHint": True}
    )

    def register(func: Callable[..., Any]) -> Any:
        # Order matters: cap runs before audit snapshots kwargs, so the logged
        # `limit` is the effective (capped) value the tool actually used.
        return mcp.tool(_cap_limits(_audited(func)), annotations=annotations)

    # Support both @tool and @tool(destructive=True).
    return register if fn is None else register(fn)


@tool
def test_connection(domain: str | None = None) -> dict[str, Any]:
    """Test connectivity and bind to the AD server without raising.

    Returns a status dict with `ok`, `target`, `auth` and `error`. Use this to
    verify the configuration and reachability before running other tools.
    """
    config = msad.load_domain_config(domain or _DEFAULT_DOMAIN, _CONFIG_FILE)
    return _jsonable(msad.check_connection(config))


@tool
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


@tool
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
    return _present(result)


@tool
def get_user(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD user by sAMAccountName, UPN, mail or cn (exact match)."""
    s = _Session(domain)
    return _present(msad.get_user(s.conn, s.base, identifier))


@tool
def find_groups(
    string: str, base: str | None = None, limit: int = 100, domain: str | None = None
) -> list[dict[str, Any]]:
    """Find AD groups by cn/name/sAMAccountName/displayName (supports * wildcards).

    Pass `base` (a DN, e.g. an OU) to restrict the search to a subtree.
    """
    s = _Session(domain)
    return _present(msad.find_groups(s.conn, base or s.base, string, limit=limit))


@tool
def get_group(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD group by sAMAccountName or cn (exact match)."""
    s = _Session(domain)
    return _present(msad.get_group(s.conn, s.base, identifier))


@tool
def get_by_dn(dn: str, domain: str | None = None) -> dict[str, Any] | None:
    """Fetch any AD entry directly by its distinguished name (DN).

    Use this to resolve DN-valued attributes into full records, e.g. the
    `manager` of a user or the `managedBy` owner of a group. Returns None if
    the DN does not exist.
    """
    s = _Session(domain)
    return _present(msad.get_by_dn(s.conn, dn))


@tool
def find_contacts(
    string: str | None = None,
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD contact objects by cn/mail/displayName (supports * wildcards).

    Passing no `string` matches every contact. Pass `base` (a DN, e.g. an OU)
    to restrict the search to a subtree.
    """
    s = _Session(domain)
    return _present(msad.find_contacts(s.conn, base or s.base, string, limit=limit))


@tool
def find_computers(
    name: str | None = None,
    dns: str | None = None,
    os: str | None = None,
    exclude_domain_controllers: bool = False,
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Find AD computers by cn (name), dNSHostName (dns) or operatingSystem (os).

    Criteria are ANDed; values may contain * wildcards. Set
    `exclude_domain_controllers=True` to drop domain controllers from the
    results. Pass `base` (a DN, e.g. an OU) to restrict the search to a
    subtree.
    """
    s = _Session(domain)
    return _present(
        msad.find_computers(
            s.conn,
            base or s.base,
            name=name,
            dns=dns,
            os=os,
            exclude_domain_controllers=exclude_domain_controllers,
            limit=limit,
        )
    )


@tool
def get_computer(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD computer by sAMAccountName, cn or dNSHostName (exact match)."""
    s = _Session(domain)
    return _present(msad.get_computer(s.conn, s.base, identifier))


@tool
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
    return _present(msad.find_ous(s.conn, base or s.base, name=name, limit=limit))


@tool
def get_ou(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single AD organizational unit by its `ou` name or full DN (exact)."""
    s = _Session(domain)
    return _present(msad.get_ou(s.conn, s.base, identifier))


@tool
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
    return _present(msad.get_ou_contents(s.conn, ou_dn, object_class=object_class, limit=limit))


@tool
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
    return _present(
        msad.find_inactive_users(
            s.conn, base or s.base, days=days, include_never=include_never, limit=limit
        )
    )


@tool
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
    return _present(
        msad.find_stale_computers(
            s.conn, base or s.base, days=days, include_never=include_never, limit=limit
        )
    )


@tool
def get_domain_info(domain: str | None = None) -> dict[str, Any] | None:
    """Read the domain object: security-relevant settings and metadata (audit)."""
    s = _Session(domain)
    return _present(msad.get_domain_info(s.conn, s.base))


@tool
def get_password_policy(domain: str | None = None) -> dict[str, Any] | None:
    """Read the default domain password policy (maxPwdAge, minPwdLength, ...)."""
    s = _Session(domain)
    return _present(msad.get_password_policy(s.conn, s.base))


@tool
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
    return _present(
        msad.get_password_policy_violations(
            s.conn, s.base, include_never_set=include_never_set, limit=limit
        )
    )


@tool
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
    return _present(
        msad.get_privileged_groups(s.conn, s.base, with_members=with_members, nested=nested)
    )


@tool
def group_members(
    group: str, nested: bool = False, limit: int = 1000, domain: str | None = None
) -> list[dict[str, Any]]:
    """List members of a group. Set nested=True for recursive membership."""
    s = _Session(domain)
    return _present(msad.group_members(s.conn, s.base, group, nested=nested, limit=limit))


@tool
def user_groups(
    user: str, nested: bool = True, limit: int = 1000, domain: str | None = None
) -> list[dict[str, Any]] | None:
    """List the groups a user belongs to (nested/recursive by default)."""
    s = _Session(domain)
    return _present(msad.user_groups(s.conn, s.base, limit, user, nested=nested))


@tool
def is_member(group: str, user: str, domain: str | None = None) -> bool:
    """Return True if the user is a (nested) member of the group."""
    s = _Session(domain)
    return msad.is_member(s.conn, s.base, group, user)


@tool
def is_disabled(user: str, domain: str | None = None) -> bool | None:
    """Return True if the account is disabled, None if the user is not found."""
    s = _Session(domain)
    return msad.is_disabled(s.conn, s.base, user)


@tool
def is_locked(user: str, domain: str | None = None) -> bool | None:
    """Return True if the account is locked, None if the user is not found."""
    s = _Session(domain)
    return msad.is_locked(s.conn, s.base, user)


@tool
def disabled_users(
    base: str | None = None,
    extra_filter: str = "",
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List disabled user accounts (userAccountControl flag 2).

    Audit counterpart of `is_disabled`: returns every disabled account instead
    of checking a single user. Pass `base` (a DN) to scope to an OU, or
    `extra_filter` to AND an extra raw LDAP clause (must be pre-escaped).
    """
    s = _Session(domain)
    return _present(
        msad.disabled_users(s.conn, base or s.base, extra_filter=extra_filter, limit=limit)
    )


@tool
def locked_users(
    base: str | None = None,
    extra_filter: str = "",
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List locked-out user accounts (lockoutTime >= 1).

    Audit counterpart of `is_locked`: returns every locked account instead of
    checking a single user. Pass `base` (a DN) to scope to an OU, or
    `extra_filter` to AND an extra raw LDAP clause (must be pre-escaped).
    """
    s = _Session(domain)
    return _present(
        msad.locked_users(s.conn, base or s.base, extra_filter=extra_filter, limit=limit)
    )


@tool
def never_expires_password(
    base: str | None = None,
    extra_filter: str = "",
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List users whose password never expires (userAccountControl flag 65536).

    A common security-audit check. Pass `base` (a DN) to scope to an OU, or
    `extra_filter` to AND an extra raw LDAP clause (must be pre-escaped).
    """
    s = _Session(domain)
    return _present(
        msad.never_expires_password(s.conn, base or s.base, extra_filter=extra_filter, limit=limit)
    )


@tool
def never_expiring_accounts(
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List users whose ACCOUNT (not password) never expires.

    Matches `accountExpires` set to the "never" sentinel values (0 or
    9223372036854775807). Distinct from `never_expires_password`, which checks
    the password-never-expires UAC flag instead. Pass `base` (a DN) to scope
    to an OU.
    """
    s = _Session(domain)
    return _present(msad.find_never_expiring_accounts(s.conn, base or s.base, limit=limit))


@tool
def expired_accounts(
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List users whose `accountExpires` date is in the past (excluding "never").

    Pass `base` (a DN) to scope to an OU.
    """
    s = _Session(domain)
    return _present(msad.find_expired_accounts(s.conn, base or s.base, limit=limit))


@tool
def password_not_required(
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Risk: list users with the PASSWD_NOTREQD UAC flag (account may have no password).

    These accounts may have no password at all, letting anyone authenticate as
    them and set their own. Pass `base` (a DN) to scope to an OU.
    """
    s = _Session(domain)
    return _present(msad.find_password_not_required(s.conn, base or s.base, limit=limit))


@tool
def kerberos_preauth_not_required(
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Risk: list users not requiring Kerberos pre-authentication.

    These accounts are vulnerable to offline (AS-REP roasting) password
    guessing. Pass `base` (a DN) to scope to an OU.
    """
    s = _Session(domain)
    return _present(msad.find_kerberos_preauth_not_required(s.conn, base or s.base, limit=limit))


@tool
def not_delegated(
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Risk: list accounts flagged "sensitive and cannot be delegated".

    Worth auditing when a sensitive privilege was granted without also
    excluding the account from delegation (or vice versa). Pass `base` (a DN)
    to scope to an OU.
    """
    s = _Session(domain)
    return _present(msad.find_not_delegated(s.conn, base or s.base, limit=limit))


@tool
def get_dn(entry: str, base: str | None = None, domain: str | None = None) -> str | None:
    """Resolve a sAMAccountName (or DN) to a distinguished name (DN).

    Returns the value unchanged if it already looks like a DN, otherwise looks
    it up. Returns None if not found. Handy before `get_by_dn` or
    `get_ou_contents`.
    """
    s = _Session(domain)
    return msad.get_dn(s.conn, base or s.base, entry)


@tool
def audit_admin_accounts(
    nested: bool = True,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Audit administrative accounts: members of well-known privileged groups.

    Builds on `get_privileged_groups` (Domain Admins, Enterprise Admins,
    Administrators, ...) and returns, per group that exists, its attributes,
    `member_count` and the expanded `members` list. Set `nested=False` to list
    only direct members instead of recursing into nested groups.
    """
    s = _Session(domain)
    return _present(msad.get_privileged_groups(s.conn, s.base, with_members=True, nested=nested))


@tool
def list_fsmo_roles(
    config_base: str | None = None,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Report the owner of each of the five FSMO roles (audit).

    Returns one entry per role (`schema_master`, `domain_naming_master`,
    `pdc_emulator`, `rid_master`, `infrastructure_master`) with the `container`
    queried and the owning DSA DN (`owner`). The schema and domain-naming
    masters live in the Configuration naming context, derived from the domain
    base for a single-domain forest; pass `config_base` explicitly for a
    multi-domain forest. Containers the service account cannot read are skipped.
    """
    s = _Session(domain)
    return _present(msad.list_fsmo_roles(s.conn, s.base, config_base=config_base))


@tool
def list_trusts(
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List the domain's trust relationships (audit).

    Reads `trustedDomain` objects under `CN=System,<base>`: trust partner,
    direction, type and attributes. Returns an empty list if the container
    cannot be read.
    """
    s = _Session(domain)
    return _present(msad.list_trusts(s.conn, s.base, limit=limit))


@tool
def list_sites(
    config_base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List the Active Directory sites (audit).

    Reads `site` objects from `CN=Sites,CN=Configuration,<forest root>`. The
    Configuration naming context is derived from the domain base for a
    single-domain forest; pass `config_base` explicitly for a multi-domain
    forest. Returns an empty list if the container cannot be read.
    """
    s = _Session(domain)
    return _present(msad.list_sites(s.conn, s.base, config_base=config_base, limit=limit))


@tool
def list_domain_controllers(
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List the domain controllers (computer accounts flagged as DCs).

    Matches the `SERVER_TRUST_ACCOUNT` userAccountControl flag. Returns the
    usual computer attributes for each DC.
    """
    s = _Session(domain)
    return _present(msad.list_domain_controllers(s.conn, s.base, limit=limit))


@tool
def list_empty_groups(
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List groups with no direct members (hygiene/audit).

    Matches groups whose `member` attribute is unset. Pass `base` (a DN) to
    scope to an OU.
    """
    s = _Session(domain)
    return _present(msad.list_empty_groups(s.conn, base or s.base, limit=limit))


@tool
def find_security_groups(
    scope: str | None = None,
    base: str | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List security-enabled groups (as opposed to distribution groups).

    Pass `scope` to restrict to one group scope: "global", "domain_local" or
    "universal" (None returns security groups of any scope). Pass `base` (a
    DN) to scope to an OU.
    """
    s = _Session(domain)
    return _present(msad.find_security_groups(s.conn, base or s.base, scope=scope, limit=limit))


@tool
def summarize_computer_os(
    base: str | None = None,
    limit: int = 0,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Summarize computer accounts grouped by operating system (audit/report).

    Returns `{operatingSystem, count}` rows sorted by descending count;
    computers without an `operatingSystem` are grouped under `(unknown)`. Pass
    `base` (a DN) to scope to an OU.
    """
    s = _Session(domain)
    return _jsonable(msad.summarize_computer_os(s.conn, base or s.base, limit=limit))


@tool
def list_gpos(
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List Group Policy Objects (audit).

    Reads `groupPolicyContainer` objects under `CN=Policies,CN=System,<base>`.
    Each GPO's `cn` is its GUID and `displayName` the friendly name. Returns an
    empty list if the Policies container cannot be read.
    """
    s = _Session(domain)
    return _present(msad.list_gpos(s.conn, s.base, limit=limit))


@tool
def get_gpo(identifier: str, domain: str | None = None) -> dict[str, Any] | None:
    """Get a single Group Policy Object by its `cn` (GUID) or `displayName`.

    The GUID may be given with or without braces. Returns None if not found.
    """
    s = _Session(domain)
    return _present(msad.get_gpo(s.conn, s.base, identifier))


@tool
def list_fine_grained_password_policies(
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List fine-grained password policies (PSOs) (audit).

    Reads `msDS-PasswordSettings` objects under
    `CN=Password Settings Container,CN=System,<base>`. Reading them may require
    extra directory rights; returns an empty list if the container is not
    readable.
    """
    s = _Session(domain)
    return _present(msad.list_fine_grained_password_policies(s.conn, s.base, limit=limit))


@tool
def search_ldap(
    search_filter: str,
    base: str | None = None,
    attributes: list[str] | None = None,
    limit: int = 100,
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """Run a raw LDAP search with a custom filter (read-only, power-user escape hatch).

    Use this when the typed tools (`find_users`, `find_groups`, ...) don't cover
    a query. The `search_filter` is passed to LDAP verbatim, so it must be a
    valid, already-escaped RFC 4515 filter, e.g.
    `(&(objectClass=user)(title=Manager))` or
    `(&(objectClass=group)(!(member=*)))` for empty groups.

    Args:
        search_filter: a raw LDAP filter (used as-is; escape any user input).
        base: DN to search under (defaults to the domain base).
        attributes: attributes to return (defaults to all attributes).
        limit: max entries to return (default 100; 0 = no limit).

    Returns:
        A list of entries, each a dict of attribute name -> value(s).
    """
    s = _Session(domain)
    return _present(
        msad.search(s.conn, base or s.base, search_filter, limit=limit, attributes=attributes)
    )


# --- Write tools (opt-in via MCPAD_ALLOW_WRITE) ----------------------------
#
# These modify AD and are therefore registered only when the operator enables
# writes. Keeping them behind a flag preserves the read-only default.

if _ALLOW_WRITE:

    def _check_membership_guardrails(group: str, user: str) -> None:
        """Refuse a membership change that touches a protected account or group.

        Raises _GuardRailError with an explanation when blocked. Disabled when
        MCPAD_DISABLE_GUARDRAILS is set.
        """
        if not _GUARDRAILS_ENABLED:
            return
        if _is_protected_account(user):
            raise _GuardRailError(
                f"Account '{user}' is protected (administrative or service/machine "
                f"account) and cannot be modified. Override via MCPAD_PROTECTED_ACCOUNTS "
                f"or disable with MCPAD_DISABLE_GUARDRAILS=1."
            )
        if _is_protected_group(group):
            raise _GuardRailError(
                f"Group '{group}' is a protected / critical group and membership "
                f"changes are refused. Override via MCPAD_PROTECTED_GROUPS or disable "
                f"with MCPAD_DISABLE_GUARDRAILS=1."
            )

    @tool(destructive=True)
    def add_group_member(
        group: str, user: str, confirm: bool = False, domain: str | None = None
    ) -> dict[str, Any]:
        """Add a user to a group (both as sAMAccountName or DN). WRITE operation.

        Only available when MCPAD_ALLOW_WRITE is enabled. Two-phase: the first
        call (``confirm=False``) returns a preview with
        ``status="confirmation_required"`` and makes NO change; call again with
        ``confirm=True`` — only after explicit human approval — to apply it.

        Guard-rails refuse changes to protected accounts (administrative /
        service / machine) and protected groups (Domain Admins, ...) regardless
        of ``confirm``. Raises if the group or user cannot be resolved.
        """
        try:
            _check_membership_guardrails(group, user)
        except _GuardRailError as exc:
            return {"status": "error", "ok": False, "message": str(exc)}

        if not confirm:
            return {
                "status": "confirmation_required",
                "ok": False,
                "action": "add_group_member",
                "group": group,
                "user": user,
                "message": (
                    f"Would add user '{user}' to group '{group}'. Re-call with "
                    f"confirm=true to apply — only after explicit human approval."
                ),
            }

        s = _Session(domain)
        result = msad.add_member(s.conn, s.base, group, user)
        return {
            "status": "success",
            "ok": bool(result),
            "action": "add_group_member",
            "group": group,
            "user": user,
            "result": _jsonable(result),
        }

    @tool(destructive=True)
    def remove_group_member(
        group: str, user: str, confirm: bool = False, domain: str | None = None
    ) -> dict[str, Any]:
        """Remove a user from a group (both as sAMAccountName or DN). WRITE operation.

        Only available when MCPAD_ALLOW_WRITE is enabled. Two-phase: the first
        call (``confirm=False``) returns a preview with
        ``status="confirmation_required"`` and makes NO change; call again with
        ``confirm=True`` — only after explicit human approval — to apply it.

        Guard-rails refuse changes to protected accounts (administrative /
        service / machine) and protected groups (Domain Users, ...) regardless
        of ``confirm``. Raises if the group or user cannot be resolved.
        """
        try:
            _check_membership_guardrails(group, user)
        except _GuardRailError as exc:
            return {"status": "error", "ok": False, "message": str(exc)}

        if not confirm:
            return {
                "status": "confirmation_required",
                "ok": False,
                "action": "remove_group_member",
                "group": group,
                "user": user,
                "message": (
                    f"Would remove user '{user}' from group '{group}'. Re-call with "
                    f"confirm=true to apply — only after explicit human approval."
                ),
            }

        s = _Session(domain)
        result = msad.remove_member(s.conn, s.base, group, user)
        return {
            "status": "success",
            "ok": bool(result),
            "action": "remove_group_member",
            "group": group,
            "user": user,
            "result": _jsonable(result),
        }

    @tool(destructive=True)
    def unlock_account(
        user: str, confirm: bool = False, domain: str | None = None
    ) -> dict[str, Any]:
        """Unlock a locked-out user account (sets lockoutTime=0). WRITE operation.

        Only available when MCPAD_ALLOW_WRITE is enabled. Two-phase: the first
        call (``confirm=False``) returns a preview with
        ``status="confirmation_required"`` and makes NO change; call again with
        ``confirm=True`` — only after explicit human approval — to apply it.

        Guard-rails refuse unlocking a protected account (administrative /
        service / machine) regardless of ``confirm``. Raises if the user cannot
        be resolved. Use `locked_users` to find locked accounts first.
        """
        if _GUARDRAILS_ENABLED and _is_protected_account(user):
            return {
                "status": "error",
                "ok": False,
                "message": (
                    f"Account '{user}' is protected (administrative or service/machine "
                    f"account) and cannot be unlocked. Override via "
                    f"MCPAD_PROTECTED_ACCOUNTS or disable with MCPAD_DISABLE_GUARDRAILS=1."
                ),
            }

        if not confirm:
            return {
                "status": "confirmation_required",
                "ok": False,
                "action": "unlock_account",
                "user": user,
                "message": (
                    f"Would unlock account '{user}' (reset lockoutTime to 0). Re-call "
                    f"with confirm=true to apply — only after explicit human approval."
                ),
            }

        s = _Session(domain)
        result = msad.unlock_user(s.conn, s.base, user)
        return {
            "status": "success",
            "ok": bool(result),
            "action": "unlock_account",
            "user": user,
            "result": _jsonable(result),
        }


# --- Prompts: reusable workflows for common AD tasks -----------------------
#
# These guide an MCP client/agent through multi-step tasks using the read-only
# tools above. They produce text instructions only; they never call tools
# themselves.


@mcp.prompt
def security_audit(domain: str | None = None) -> str:
    """Guide a read-only security audit of the Active Directory domain."""
    scope = f" for domain '{domain}'" if domain else ""
    return (
        f"Perform a read-only Active Directory security audit{scope} using the "
        "available tools, then summarize the findings. Steps:\n"
        "1. `get_domain_info` and `get_password_policy` — capture domain settings "
        "and the password policy.\n"
        "2. `audit_admin_accounts` — list members of privileged groups and flag "
        "any unexpected or stale admins.\n"
        "3. `never_expires_password` — list accounts whose password never expires.\n"
        "4. `get_password_policy_violations` — list accounts violating the policy.\n"
        "5. `disabled_users` and `locked_users` — note disabled and locked accounts.\n"
        "6. `find_inactive_users` (days=90) and `find_stale_computers` (days=90) — "
        "note dormant objects.\n"
        "Present a concise report grouped by risk, with counts and the notable "
        "accounts. Do not modify anything."
    )


@mcp.prompt
def find_inactive(days: int = 90, domain: str | None = None) -> str:
    """Guide finding and triaging inactive users and stale computers."""
    scope = f" in domain '{domain}'" if domain else ""
    return (
        f"Find objects inactive for at least {days} days{scope} and help triage "
        "them. Steps:\n"
        f"1. `find_inactive_users` with days={days} (set include_never=true to also "
        "catch accounts that never logged on).\n"
        f"2. `find_stale_computers` with days={days}.\n"
        "3. For each notable account, use `is_disabled` / `user_groups` to decide "
        "whether it is safe to disable or remove.\n"
        "Summarize as a table (name, username, last logon, department) and suggest "
        "candidates for cleanup. Do not modify anything."
    )


@mcp.prompt
def group_membership_report(group: str, domain: str | None = None) -> str:
    """Guide a membership report for a specific group."""
    scope = f" in domain '{domain}'" if domain else ""
    return (
        f"Produce a membership report for the group '{group}'{scope}. Steps:\n"
        f"1. `get_group` with identifier='{group}' — confirm the group exists and "
        "read its description / managedBy.\n"
        f"2. `group_members` with group='{group}', nested=false — list direct "
        "members.\n"
        f"3. `group_members` with group='{group}', nested=true — list the full "
        "effective membership (via nested groups).\n"
        "4. Note the difference between direct and nested membership, and resolve "
        "`managedBy` with `get_by_dn` if present.\n"
        "Present the members (name, username) and the owner. Do not modify anything."
    )


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
