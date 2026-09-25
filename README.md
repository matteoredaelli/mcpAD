# mcpAD

A [FastMCP](https://gofastmcp.com) server that exposes the
[`msad`](../msad) Active Directory / LDAP library as MCP tools.

Built with **Python 3.14** and **uv**. It reuses the typed, public `msad` API
(search users/groups, memberships, account status). All tools are read-only.

## Tools

| Tool | Description |
|---|---|
| `find_users` | Find users by name/surname/mail/sam/department (ANDed, `*` wildcards) |
| `get_user` | Get a single user (exact match) |
| `find_groups` | Find groups (`*` wildcards) |
| `get_group` | Get a single group (exact match) |
| `find_computers` | Find computers by name/dns/os (`*` wildcards) |
| `get_computer` | Get a single computer (sAMAccountName/cn/dNSHostName) |
| `get_by_dn` | Fetch any entry directly by its DN (resolve `manager` / `managedBy`) |
| `group_members` | List group members (direct or `nested`) |
| `user_groups` | List a user's groups (nested by default) |
| `is_member` | Is a user a (nested) member of a group? |
| `is_disabled` | Is an account disabled? |
| `is_locked` | Is an account locked? |

### Returned attributes

By default `get_user` / `find_users` return a useful attribute set that includes
`manager` — the **distinguished name (DN)** of the user's manager, e.g.
`CN=Anna Bianchi,OU=Staff,DC=group,DC=example,DC=com`. Group lookups include
`managedBy`, the DN of the group's owner.

To expand a manager (or any DN-valued field) into a full record, call
`get_by_dn` with that DN. This is a direct, efficient lookup (the DN is used as
the search base), so an agent can do: `get_user("mrossi")` → read `manager` →
`get_by_dn("<that DN>")`.

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
search_base = "dc=group,dc=example,dc=com"
port = 636                    # default: 389
use_ssl = true                # default: false  (true = LDAPS)
# user = "svc_account"        # optional (see auth below)
# password = "..."            # optional
```

You can declare several `[domains.<name>]` blocks and pick one per call with the
tool's `domain` argument, or globally via `MSAD_DOMAIN`.

### Overrides via environment

- `MSAD_DOMAIN` — default domain when a tool call omits `domain`
- `MSAD_CONFIG_FILE` — path to an alternative TOML config

### Authentication modes

The mode is chosen **automatically** from the domain block:

- **Kerberos (SASL)** — when `user`/`password` are *not both* set (the default).
  Obtain a ticket first:

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

## Running

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

The `msad` dependency is installed as an editable local path (`../msad`), so
library changes are picked up immediately.
