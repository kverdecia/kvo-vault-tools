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

The token must be allowed to read `sys/auth`. A root token works.

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
