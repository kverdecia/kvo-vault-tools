# kvo-vault-tools

Desktop application built with [Python](https://www.python.org/) and [Flet](https://flet.dev/) to run checks and maintenance tasks on a [HashiCorp Vault](https://www.vaultproject.io/) server. It also ships an equivalent console (TUI) application built with [Textual](https://textual.textualize.io/).

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
    - Each role has a **Reveal** button. Click it to show the role's **role ID** (`GET .../role/<name>/role-id`) and its **secret IDs**, newest first, each with its accessor, status (active/expired), creation, expiration and last-update times, remaining uses, TTL, CIDR list, token bound CIDRs and metadata. Vault never returns the secret ID values, only their accessors. Click **Hide** to collapse it.
    - Each role (except those with `bind_secret_id=false`) has a **New secret ID** button. It creates a secret ID (`POST .../role/<name>/secret-id`) and shows it in a dialog with a **Copy** button, its accessor, TTL and allowed uses. Copy it right away: Vault only returns the value when it is created, so once the dialog is closed it can't be retrieved. The role status, and the secret ID list if it is revealed, are then reloaded.

The back arrow returns to the backend list and keeps the current filters.

The token must be allowed to read `sys/auth` and to list the roles of each backend. A root token works.

### Console (TUI) version

The same features are available in the terminal:

```bash
uv run kvo-vault-tools-tui
```

or `uv run python -m kvo_vault_tools.tui`.

The connection screen is filled in from the `VAULT_ADDR` and `VAULT_TOKEN` environment variables when they are set. The screens work like the desktop ones; the keyboard shortcuts are shown in the footer:

| Screen | Key | Action |
| --- | --- | --- |
| Connection | `Enter` | Move to the token field / connect |
| | `Ctrl+T` | Show or hide the token |
| Backend list | `Enter` | Open the highlighted backend |
| | `Ctrl+F` | Go to the search field |
| | `F5` | Reload the backends |
| Backend details | `Esc` | Back to the backend list (keeps the filters) |
| | `Ctrl+F` | Go to the role search field |
| | `F5` | Reload the roles |
| | `Enter` / `Ctrl+R` | AppRole: reveal or hide the role ID and secret IDs of the highlighted role |
| | `Ctrl+N` | AppRole: create a new secret ID for the highlighted role |
| New secret ID dialog | `Ctrl+Y` | Copy the secret ID |
| Anywhere | `Ctrl+Q` | Quit |

The **Copy** button sends the secret ID to the system clipboard (`pbcopy`, `wl-copy`, `xclip`, `xsel` or `clip`, whichever is installed) and to the terminal clipboard (OSC 52, which also works over SSH in most terminals).

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
        ├── tui.py          # Console version of the application (Textual)
        ├── formatting.py   # Text formatting helpers shared by both interfaces
        └── vault.py        # Vault HTTP API client (httpx2)
```

## Author

Karel Antonio Verdecia Ortiz
