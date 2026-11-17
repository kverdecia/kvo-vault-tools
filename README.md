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

On startup, the application shows a connection window where you enter the Vault server URL and the root token, then press **Connect**. The application checks that the server is reachable and that the token is valid.

## Project structure

```
kvo-vault-tools/
├── pyproject.toml          # Project configuration and dependencies
├── README.md
└── src/
    └── kvo_vault_tools/
        ├── __init__.py     # Application entry point (main)
        ├── app.py          # Flet user interface
        └── vault.py        # Vault HTTP API client (httpx2)
```

## Author

Karel Antonio Verdecia Ortiz
