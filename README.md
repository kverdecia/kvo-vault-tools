# kvo-vault-tools

Desktop application built with [Python](https://www.python.org/) and [Flet](https://flet.dev/) to run checks and maintenance tasks on a [HashiCorp Vault](https://www.vaultproject.io/) server.

## Requirements

- Python 3.14 or later
- [uv](https://docs.astral.sh/uv/) for environment and dependency management
- Access to a HashiCorp Vault server

## Installation

```bash
git clone <repository-url>
cd kvo-vault-tools
uv sync
```

## Usage

To start the application:

```bash
uv run kvo-vault-tools
```

or, as a Python module:

```bash
uv run python -m kvo_vault_tools
```

### Connection

On startup, the application shows a connection window where you enter the Vault server URL and the root token, then press **Connect**. The application checks that the server is reachable and that the token is valid.

### Vault view

After a successful connection, the application opens the Vault view, centered on the screen. For now it has one section:

- **Authentication**: lists every authentication backend enabled on the server (`GET /v1/sys/auth`), showing its path, type, description, accessor and whether it is local.
  - **Search by name**: filters the backends by path as you type. It ignores case and matches partial text.
  - **Type**: filters the backends by type. The options are built from the types found on the server.
  - The refresh button reloads the list from the server.
  - Click a row (or its arrow button) to open the backend details.

### Authentication backend details

The details view of a backend shows:

- **General**: path, type, description, accessor, UUID, local, seal wrap, external entropy access and plugin versions.
- **Configuration**: the mount tuning (default and max lease TTL, token type, etc.).
- **Options**: the mount options, when there are any.
- **Roles**: the roles of the backend (`LIST /v1/auth/<path>/<roles endpoint>`), with a search field and a refresh button. Supported types: `alicloud`, `approle`, `aws`, `azure`, `cert`, `cf`, `gcp`, `jwt`, `kubernetes`, `oci`, `oidc`, `saml` and `token`. Other types (such as `userpass` or `ldap`) have no roles.
  - For `approle` backends, each role shows whether it has expired. AppRole roles have no expiration of their own; what expires are their secret IDs. So the status is worked out from the role's secret IDs (`LIST .../role/<name>/secret-id` and `POST .../secret-id-accessor/lookup`):
    - **Active**: at least one secret ID has not expired. Shows how many there are and when the last one expires (or "never expires").
    - **Expired**: every secret ID has expired, or the role has none, so it can't be used to log in.
    - **No expiration**: the role has `bind_secret_id=false`, so it doesn't use secret IDs.
    - The roles title shows how many roles have expired.

The back arrow returns to the backend list and keeps the current filters.

The token must be allowed to read `sys/auth` and to list the roles of each backend. A root token works.

## Project structure

```
kvo-vault-tools/
├── pyproject.toml          # Project configuration and dependencies
├── README.md
└── src/
    └── kvo_vault_tools/
        ├── __init__.py
        ├── __main__.py     # Application entry point (main)
        ├── app.py          # Connection screen (Flet)
        ├── vault_view.py   # Vault view and Authentication section (Flet)
        └── vault.py        # Vault HTTP API client (httpx2)
```

## Author

Karel Antonio Verdecia Ortiz
