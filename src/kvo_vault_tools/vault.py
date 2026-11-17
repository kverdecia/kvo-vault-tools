from dataclasses import dataclass, field
from typing import Any

import httpx2


class VaultConnectionError(Exception):
    """Raised when a connection to the Vault server cannot be established."""


@dataclass(frozen=True)
class AuthMethod:
    """An authentication backend enabled on the Vault server."""

    path: str
    type: str
    description: str
    accessor: str
    local: bool
    seal_wrap: bool
    uuid: str = ""
    external_entropy_access: bool = False
    plugin_version: str = ""
    running_plugin_version: str = ""
    config: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    options: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    @property
    def mount_path(self) -> str:
        """Path of the backend without the trailing slash (e.g. ``approle``)."""
        return self.path.rstrip("/")

    @property
    def supports_roles(self) -> bool:
        return self.type in ROLE_ENDPOINTS


# Sub-path that lists the roles of each authentication backend type
# (LIST /v1/auth/<mount>/<sub-path>). Types not listed here have no roles.
ROLE_ENDPOINTS: dict[str, str] = {
    "alicloud": "role",
    "approle": "role",
    "aws": "roles",
    "azure": "role",
    "cert": "certs",
    "cf": "roles",
    "gcp": "role",
    "jwt": "role",
    "kubernetes": "role",
    "oci": "role",
    "oidc": "role",
    "saml": "role",
    "token": "roles",
}


class VaultClient:
    """Minimal Vault HTTP API client built on httpx2."""

    def __init__(self, url: str, token: str, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self._http = httpx2.AsyncClient(
            base_url=f"{self.url}/v1",
            headers={"X-Vault-Token": token},
            timeout=timeout,
        )

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx2.Response:
        return await self._http.request(method, path, **kwargs)

    async def lookup_self(self) -> dict[str, Any]:
        """Return the data of the current token (GET /v1/auth/token/lookup-self)."""
        response = await self.request("GET", "/auth/token/lookup-self")
        response.raise_for_status()
        return response.json()["data"]

    async def list_auth_methods(self) -> list[AuthMethod]:
        """Return the enabled authentication backends (GET /v1/sys/auth), sorted by path."""
        response = await self.request("GET", "/sys/auth")
        response.raise_for_status()
        body = response.json()
        mounts = body.get("data", body)
        return sorted(
            (
                AuthMethod(
                    path=path,
                    type=info.get("type", ""),
                    description=info.get("description", ""),
                    accessor=info.get("accessor", ""),
                    local=bool(info.get("local", False)),
                    seal_wrap=bool(info.get("seal_wrap", False)),
                    uuid=info.get("uuid", ""),
                    external_entropy_access=bool(info.get("external_entropy_access", False)),
                    plugin_version=info.get("plugin_version", ""),
                    running_plugin_version=info.get("running_plugin_version", ""),
                    config=info.get("config") or {},
                    options=info.get("options") or {},
                )
                for path, info in mounts.items()
                if isinstance(info, dict) and "type" in info
            ),
            key=lambda method: method.path,
        )

    async def list_auth_roles(self, method: AuthMethod) -> list[str]:
        """Return the role names of an authentication backend, sorted.

        Uses LIST /v1/auth/<mount>/<role endpoint>. Returns an empty list when the
        backend has no roles (Vault answers 404) or its type does not support roles.
        """
        endpoint = ROLE_ENDPOINTS.get(method.type)
        if endpoint is None:
            return []
        response = await self.request(
            "GET", f"/auth/{method.mount_path}/{endpoint}", params={"list": "true"}
        )
        if response.status_code == 404:
            return []
        response.raise_for_status()
        keys = response.json().get("data", {}).get("keys") or []
        return sorted(keys)

    async def aclose(self) -> None:
        await self._http.aclose()


async def connect(url: str, token: str, timeout: float = 10.0) -> VaultClient:
    """Create a Vault client and verify that the token is valid.

    Raises VaultConnectionError if the server is unreachable or the token is rejected.
    """
    client = VaultClient(url, token, timeout)
    try:
        await client.lookup_self()
    except httpx2.HTTPStatusError as exc:
        await client.aclose()
        if exc.response.status_code == 403:
            raise VaultConnectionError("The token is invalid or has expired.") from exc
        raise VaultConnectionError(
            f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
        ) from exc
    except httpx2.HTTPError as exc:
        await client.aclose()
        raise VaultConnectionError(f"Could not reach the Vault server: {exc}") from exc
    except (ValueError, KeyError) as exc:
        await client.aclose()
        raise VaultConnectionError("The server did not return a valid Vault response.") from exc
    return client
