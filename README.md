# mcpAD

A [FastMCP](https://gofastmcp.com) server that exposes the
[`msad`](https://github.com/matteoredaelli/msad) Active Directory / LDAP library as MCP tools.

Built with **Python 3.14** and **uv**. It reuses the typed, public `msad` API
(search users/groups, memberships, account status, read-only security audits).
All tools are read-only by default; optional group-membership write tools are
disabled unless `MCPAD_ALLOW_WRITE` is enabled (see [Write tools](#write-tools)).

## Tools

| Tool | Description |
|---|---|
| `find_users` | Find users by name/surname/mail/sam/department (ANDed, `*` wildcards) |
| `get_user` | Get a single user (exact match) |
| `find_groups` | Find groups (`*` wildcards) |
| `get_group` | Get a single group (exact match) |
| `find_computers` | Find computers by name/dns/os (`*` wildcards); optionally `exclude_domain_controllers` |
| `get_computer` | Get a single computer (sAMAccountName/cn/dNSHostName) |
| `find_contacts` | Find AD contact objects by cn/mail/displayName (`*` wildcards) |
| `find_ous` | Find organizational units by name (`*` wildcards) |
| `get_ou` | Get a single OU by its `ou` name or full DN (exact match) |
| `get_ou_contents` | List objects under an OU (optionally filtered by `object_class`) |
| `find_inactive_users` | Find users whose last logon is older than `days` (default 90) |
| `find_stale_computers` | Find computers whose last logon is older than `days` (default 90) |
| `disabled_users` | List disabled user accounts (audit; counterpart of `is_disabled`) |
| `locked_users` | List locked-out user accounts (audit; counterpart of `is_locked`) |
| `never_expires_password` | List users whose password never expires (audit) |
| `never_expiring_accounts` | List users whose ACCOUNT (not password) never expires |
| `expired_accounts` | List users whose `accountExpires` date is in the past |
| `password_not_required` | Risk: users with the `PASSWD_NOTREQD` UAC flag (account may have no password) |
| `kerberos_preauth_not_required` | Risk: users not requiring Kerberos pre-auth (AS-REP roasting exposure) |
| `not_delegated` | Risk: accounts flagged "sensitive and cannot be delegated" |
| `audit_admin_accounts` | Members of well-known privileged groups (admin-account audit) |
| `list_fsmo_roles` | Owners of the five FSMO roles (schema, domain-naming, PDC, RID, infrastructure) |
| `list_trusts` | Domain trust relationships (`trustedDomain` objects) |
| `list_sites` | Active Directory sites (from the Configuration naming context) |
| `list_domain_controllers` | Domain controllers (computer accounts flagged `SERVER_TRUST_ACCOUNT`) |
| `summarize_computer_os` | Count of computer accounts grouped by operating system |
| `list_empty_groups` | Groups with no direct members (hygiene/audit) |
| `find_security_groups` | List security-enabled groups, optionally by `scope` (global/domain_local/universal) |
| `list_gpos` | Group Policy Objects (`groupPolicyContainer`) |
| `get_gpo` | A single GPO by its `cn` (GUID) or `displayName` |
| `list_fine_grained_password_policies` | Fine-grained password policies (PSOs) |
| `get_domain_info` | Domain object: security-relevant settings and metadata (audit) |
| `get_password_policy` | Default domain password policy (audit) |
| `get_password_policy_violations` | Users whose password violates the policy (audit) |
| `get_privileged_groups` | Well-known privileged groups with member counts (audit) |
| `get_by_dn` | Fetch any entry directly by its DN (resolve `manager` / `managedBy`) |
| `get_dn` | Resolve a sAMAccountName (or DN) to a distinguished name |
| `search_ldap` | Run a raw, read-only LDAP search with a custom filter (power-user escape hatch) |
| `group_members` | List group members (direct or `nested`) |
| `user_groups` | List a user's groups (nested by default) |
| `is_member` | Is a user a (nested) member of a group? |
| `is_disabled` | Is an account disabled? |
| `is_locked` | Is an account locked? |
| `test_connection` | Test AD connectivity and bind (returns ok/target/auth/error) |
| `health` | Server health check (server name, msad version, connectivity) |

The `find_users`, `find_groups`, `find_computers` and `find_ous` tools accept an
optional `base` (a DN, e.g. an OU) to restrict the search to that subtree
instead of the whole domain.

### Tool annotations

Every tool advertises standard MCP behavior hints so a client can reason about
its risk without parsing the name or docstring. All the tools above are
read-only (`readOnlyHint: true`); the optional write tools (see below) are
marked `destructiveHint: true` (and `readOnlyHint: false`).

### Returned attributes

By default `get_user` / `find_users` return a useful attribute set: identity
fields plus `manager` — the **distinguished name (DN)** of the user's manager,
e.g. `CN=Anna Bianchi,OU=Staff,DC=group,DC=example,DC=com` — as well as
`memberOf` (direct group DNs), `userAccountControl`, `accountExpires`,
`lastLogonTimestamp` and `whenCreated`. Group lookups include `managedBy` (the
DN of the group's owner), `member`, `groupType` and `whenCreated`.

To expand a manager (or any DN-valued field) into a full record, call
`get_by_dn` with that DN. This is a direct, efficient lookup (the DN is used as
the search base), so an agent can do: `get_user("mrossi")` → read `manager` →
`get_by_dn("<that DN>")`.

### Decoded attributes

By default the server also adds **decoded companion keys** next to the raw
attributes, so a client doesn't have to interpret AD's opaque numbers and
binary blobs:

- `userAccountControl_decoded` — a flag list plus booleans (`disabled`,
  `locked`, `password_never_expires`, ...);
- `groupType_decoded` — `scope` (global / domain_local / universal) and
  security vs. distribution;
- `objectSid_decoded` / `objectGUID_decoded` — canonical `S-1-5-...` / GUID
  strings;
- `<attr>_iso` — an ISO-8601 timestamp for FILETIME attributes
  (`accountExpires`, `lastLogonTimestamp`, `pwdLastSet`, `lockoutTime`, ...),
  omitted for the "never"/unset sentinels.

The raw attributes are always preserved. Decoding is on by default; set
`MCPAD_DECODE_ATTRS` to a falsy value (`0`, `false`, `no`, `off`) to return raw
attributes only.

### Write tools

The tools above are all **read-only**. Two optional **write** tools modify AD
group membership and are therefore **disabled by default**. They are registered
only when the `MCPAD_ALLOW_WRITE` environment variable is set to a truthy value
(`1`, `true`, `yes`, `on`):

| Tool | Description |
|---|---|
| `add_group_member` | Add a user to a group (both as sAMAccountName or DN) |
| `remove_group_member` | Remove a user from a group (both as sAMAccountName or DN) |
| `unlock_account` | Unlock a locked-out user account (resets `lockoutTime` to 0) |

```bash
MCPAD_ALLOW_WRITE=1 uv run mcpad      # write tools registered
uv run mcpad                          # read-only (default)
```

The service account used by `msad` must have the directory permissions to
modify the target groups; otherwise the call fails with an `MsadError`. When
writes are disabled the tools are not advertised at all, so an agent cannot
invoke them.

#### Two-phase confirmation

All write tools are **two-phase**. The first call (`confirm=false`, the
default) makes no change and returns a preview:

```json
{ "status": "confirmation_required", "ok": false, "group": "Sales", "user": "jdoe",
  "message": "Would add user 'jdoe' to group 'Sales'. Re-call with confirm=true ..." }
```

Call again with `confirm=true` — only after explicit human approval — to apply
the change. An agent must never set `confirm=true` on its own.

#### Safety guard-rails

Even with writes enabled, membership changes that touch sensitive objects are
**refused** (returned as `status: "error"`), regardless of `confirm`:

- **Protected accounts** — `administrator`, `admin`, `krbtgt`, `guest`,
  `system`, plus any name matching a service/machine pattern
  (`*$` machine accounts, `svc_*`, `service_*`, `sa_*`, `adm_*`, `sys_*`).
- **Protected groups** — `Domain Admins`, `Enterprise Admins`, `Schema Admins`,
  `Administrators`, the operator groups, `Group Policy Creator Owners`,
  `DnsAdmins`, and `Domain Users` (critical system group).

Matching is case-insensitive and works whether you pass a `sAMAccountName` or a
full DN. Extend or tune via environment variables:

| Variable | Effect |
|---|---|
| `MCPAD_PROTECTED_ACCOUNTS` | Comma-separated extra account names to protect |
| `MCPAD_PROTECTED_GROUPS` | Comma-separated extra group names to protect |
| `MCPAD_DISABLE_GUARDRAILS` | Set truthy to turn the checks off (not recommended) |

## Audit logging

Set `MCPAD_AUDIT_LOG` to a file path to record **every tool call** (read-only
and write alike) as one JSON object per line (JSON-lines). Logging is off by
default.

```bash
MCPAD_AUDIT_LOG=/var/log/mcpad/audit.log uv run mcpad
```

Each entry carries the UTC timestamp, the tool name, the (redacted) arguments,
the status, the business outcome, the duration, and — on failure — the error:

```json
{"ts": "2026-10-18T20:09:34.029995+00:00", "tool": "add_group_member",
 "params": {"group": "Sales", "user": "jdoe", "confirm": true},
 "status": "ok", "outcome": "applied", "duration_ms": 12.4}
```

Notes:

- Sensitive argument values (`password`, `new_password`, `old_password`,
  `token`, ...) are replaced with `***REDACTED***`.
- `status` records only whether the Python call returned (`ok`) or raised
  (`error`). The **`outcome`** field records what actually happened:
  - `completed` — a read-only tool returned normally (the common case);
  - `preview` — a two-phase write returned its confirmation preview and
    changed nothing (`confirm=false`);
  - `blocked` — a safety guard-rail refused the write;
  - `applied` — a write was confirmed and executed;
  - `failed` — the call raised (paired with `status: "error"`).
- The parent directory is created if needed; if the path cannot be opened the
  server logs a warning and continues **without** audit logging (tool calls are
  never blocked by an unwritable log).

## Result limits

Every tool's `limit` argument is clamped to a hard ceiling so a single call
can't pull an unbounded number of rows from a domain controller. The default
ceiling is **1000**; a `limit` above it — or `limit=0`, which the underlying
`msad` library treats as "no limit" — is rewritten to the ceiling. A `limit`
below the ceiling is used as-is.

```bash
MCPAD_MAX_LIMIT=500 uv run mcpad      # lower the ceiling to 500
```

`MCPAD_MAX_LIMIT` must be a positive integer; a missing, empty, non-numeric or
non-positive value falls back to the default of 1000. The effective (capped)
value is what appears in the audit log.

## Prompts

The server ships a few **MCP prompts** — reusable, read-only workflows that
guide an agent through multi-step tasks using the tools above. They produce
instructions only and never modify anything.

| Prompt | Description |
|---|---|
| `security_audit` | Walk a read-only domain security audit (policy, admins, stale/violating accounts) and summarize by risk |
| `find_inactive` | Find and triage inactive users and stale computers (parameter: `days`, default 90) |
| `group_membership_report` | Report direct vs. nested membership and the owner of a given `group` |

## Authentication & connection

The server has **no connection settings of its own**: it reuses the `msad`
configuration file, `~/.msad.toml` by default (create it with `msad init`).
Each tool call opens a short-lived connection through `msad.connect()`.

### Domain parameters (`~/.msad.toml`)

```toml
[defaults]
domain = "group"              # used when a tool call omits `domain`

[domains.group]
host = "dc.example.com"       # hostname only (no scheme, no :port)
base = "dc=group,dc=example,dc=com"
port = 636                    # default: 389
use_ssl = true                # default: false  (true = LDAPS)
# user = "svc_account"        # optional (see auth below)
# password = "..."            # optional

# A second domain (here using user/password auth):
[domains.lab]
host = "dc.lab.example.com"
base = "dc=lab,dc=example,dc=com"
port = 636
use_ssl = true
user = "svc_reader"
password = "s3cr3t"
```

You can declare several `[domains.<name>]` blocks and pick one per call with the
tool's `domain` argument, or globally via `MSAD_DOMAIN`. For example, an agent
can call `find_users(surname="Rossi", domain="lab")` to target the `lab` domain
while `[defaults].domain` stays `group`.

### Overrides via environment

- `MSAD_DOMAIN` — default domain when a tool call omits `domain`
- `MSAD_CONFIG_FILE` — path to an alternative TOML config

### Authentication modes

The mode is chosen **automatically** from the domain block:

- **Kerberos (SASL)** — when `user`/`password` are *not both* set (the default).
  Requires installing mcpAD with the optional `kerberos` extra (see
  [Installation](#installation) below), which pulls in `msad`'s `gssapi`
  dependency. Obtain a ticket first:

  ```bash
  kinit                # or: kinit <user>@REALM
  ```

  The server relies on the system Kerberos ticket cache (or a keytab via
  `KRB5_CLIENT_KTNAME`). If the ticket is missing or expired, tools fail with a
  clean `MsadConnectionError` message. When running as a background/remote
  service, make sure that process can see a valid ticket or keytab.

- **User / password** — when **both** `user` and `password` are set. Simple LDAP
  bind. The password is stored in clear text in the TOML, so restrict the file
  permissions (`chmod 600 ~/.msad.toml`).

  > Note: setting only one of `user`/`password` silently falls back to Kerberos.
  > Set both, or neither.

Use LDAPS (`port = 636`, `use_ssl = true`) whenever possible.

## Installation

```bash
uvx --from git+https://github.com/matteoredaelli/mcpAD mcpAD
# or, from a checkout:
uv sync
```

Kerberos (SASL/GSSAPI) authentication is optional: `msad`'s `gssapi`
dependency is a native extension that needs the system Kerberos dev headers
to build (e.g. `libkrb5-dev` + `krb5-config` on Debian/Ubuntu, `krb5-devel` on
RHEL/Fedora, `krb5` via Homebrew on macOS). If you only authenticate with
user/password, skip it entirely; to enable Kerberos, install/sync the
`kerberos` extra instead:

```bash
uv sync --extra kerberos
# or: pip install 'mcpad[kerberos]'
# or, with uvx: uvx --from 'mcpad[kerberos]' mcpad
```

## Running

Using uvx:

  uvx --from git+https://github.com/matteoredaelli/mcpAD mcpAD

The `Makefile` wraps the common cases. Transport, host and port are
configurable:

```bash
make start-stdio                        # stdio (for local MCP clients)
make start-http                         # streamable-http on 127.0.0.1:8000
make start-http HOST=0.0.0.0 PORT=9000  # bind elsewhere
make start-sse                          # sse transport
make start TRANSPORT=streamable-http PORT=9000   # generic form
```

Equivalent raw commands (the server reads `MCP_TRANSPORT` / `MCP_HOST` /
`MCP_PORT` from the environment):

```bash
uv run mcpad                                        # stdio (default)
MCP_TRANSPORT=streamable-http MCP_PORT=9000 uv run mcpad
```


## Registering the server with an MCP client / agent

MCP clients (Claude Desktop, IDE agents, custom agents, ...) usually accept a
JSON config with a `mcpServers` map. Two deployment styles:

### Local (stdio) — the client launches the server

The client spawns the process and talks to it over stdio. This is the simplest
setup and keeps everything on your machine (including your Kerberos ticket).

```json
{
  "mcpServers": {
    "mcpAD": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/path/to/mcpAD",
        "mcpad"
      ],
      "env": {
        "MSAD_DOMAIN": "group"
      }
    }
  }
}
```

Notes:
- `--directory` makes `uv` use this project's environment regardless of the
  client's working directory.
- Kerberos: the spawned process inherits your environment, so a ticket obtained
  with `kinit` in the same user session is used automatically. For an unattended
  client, point it at a keytab (e.g. add `"KRB5_CLIENT_KTNAME": "/path/to.keytab"`
  to `env`).

### Remote (streamable-http) — the server runs as a service

Start the server as a long-running HTTP service, then point the client at its
URL. Useful when the server runs on a host that has AD/Kerberos access while the
client runs elsewhere.

Start the service:

```bash
make start-http HOST=0.0.0.0 PORT=9000
# serves the MCP endpoint at http://<host>:9000/mcp
```

Client config referencing the URL:

```json
{
  "mcpServers": {
    "mcpAD": {
      "transport": "http",
      "url": "http://mcp-host.example.com:9000/mcp"
    }
  }
}
```

Notes:
- The default streamable-http path is `/mcp`.
- The server itself performs no client authentication; if you expose it beyond
  localhost, put it behind a reverse proxy / network controls and treat the AD
  credentials on that host accordingly.
- Kerberos runs where the **server** runs: that host needs a valid ticket or a
  keytab, not the client.

## Development

```bash
uv sync
uv run python -c "import asyncio; from mcpad import mcp; print(asyncio.run(mcp.list_tools()))"
```

The [`msad`](https://github.com/matteoredaelli/msad) dependency can be installed
from its Git repository, or as an editable local path during development so that
library changes are picked up immediately.
