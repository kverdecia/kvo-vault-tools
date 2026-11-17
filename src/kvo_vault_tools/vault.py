import asyncio
import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
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


class AppRoleState(enum.Enum):
    """Whether an AppRole role can still be used to log in."""

    ACTIVE = "active"
    """At least one secret ID has not expired."""
    EXPIRED = "expired"
    """The role has secret IDs, but all of them have expired."""
    NO_SECRET_IDS = "no_secret_ids"
    """The role requires a secret ID but has none (never created, or already tidied)."""
    NOT_REQUIRED = "not_required"
    """The role does not require a secret ID (``bind_secret_id=false``), so it never expires."""


@dataclass(frozen=True)
class AppRoleStatus:
    """Expiration status of an AppRole role, based on its secret IDs."""

    state: AppRoleState
    secret_id_count: int = 0
    expires_at: datetime | None = None
    """For ACTIVE: latest expiration of the valid secret IDs (None means never).
    For EXPIRED: when the last secret ID expired."""

    @property
    def is_expired(self) -> bool:
        return self.state in (AppRoleState.EXPIRED, AppRoleState.NO_SECRET_IDS)


@dataclass(frozen=True)
class AppRoleSecretId:
    """Information about one secret ID of an AppRole role (the secret value is never returned)."""

    accessor: str
    creation_time: datetime | None = None
    expiration_time: datetime | None = None
    """None means the secret ID never expires."""
    last_updated_time: datetime | None = None
    num_uses: int = 0
    """Remaining uses; 0 means unlimited."""
    ttl: int = 0
    cidr_list: list[str] = field(default_factory=list, hash=False, compare=False)
    token_bound_cidrs: list[str] = field(default_factory=list, hash=False, compare=False)
    metadata: dict[str, str] = field(default_factory=dict, hash=False, compare=False)

    @property
    def is_expired(self) -> bool:
        return self.expiration_time is not None and self.expiration_time <= datetime.now(UTC)

    @classmethod
    def from_lookup(cls, accessor: str, data: dict[str, Any]) -> AppRoleSecretId:
        def as_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        return cls(
            accessor=data.get("secret_id_accessor") or accessor,
            creation_time=_parse_vault_time(data.get("creation_time")),
            expiration_time=_parse_vault_time(data.get("expiration_time")),
            last_updated_time=_parse_vault_time(data.get("last_updated_time")),
            num_uses=as_int(data.get("secret_id_num_uses")),
            ttl=as_int(data.get("secret_id_ttl")),
            cidr_list=list(data.get("cidr_list") or []),
            token_bound_cidrs=list(data.get("token_bound_cidrs") or []),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class AppRoleCredentials:
    """Role ID and secret IDs of an AppRole role."""

    role_id: str
    secret_ids: list[AppRoleSecretId] = field(default_factory=list, hash=False, compare=False)


def _parse_vault_time(value: Any) -> datetime | None:
    """Parse a Vault RFC 3339 timestamp. Returns None for empty or zero times (no expiration)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.year <= 1:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


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

    async def approle_role_status(
        self, method: AuthMethod, role: str, concurrency: asyncio.Semaphore | None = None
    ) -> AppRoleStatus:
        """Return whether an AppRole role has expired, based on its secret IDs.

        A role whose secret IDs have all expired (or that has none) cannot be used
        to log in, so it is considered expired. Roles with ``bind_secret_id=false``
        never expire.
        """
        semaphore = concurrency or asyncio.Semaphore(8)
        base = f"/auth/{method.mount_path}/role/{role}"

        async with semaphore:
            response = await self.request("GET", base)
        response.raise_for_status()
        if not response.json().get("data", {}).get("bind_secret_id", True):
            return AppRoleStatus(AppRoleState.NOT_REQUIRED)

        secret_ids = await self._approle_secret_ids(base, semaphore)
        if not secret_ids:
            return AppRoleStatus(AppRoleState.NO_SECRET_IDS)

        now = datetime.now(UTC)
        expirations = [s.expiration_time for s in secret_ids]
        valid = [e for e in expirations if e is None or e > now]
        if valid:
            expires_at = None if None in valid else max(e for e in valid if e is not None)
            return AppRoleStatus(AppRoleState.ACTIVE, len(secret_ids), expires_at)
        return AppRoleStatus(
            AppRoleState.EXPIRED,
            len(secret_ids),
            max(e for e in expirations if e is not None),
        )

    async def approle_credentials(self, method: AuthMethod, role: str) -> AppRoleCredentials:
        """Return the role ID and the secret IDs (with their information) of an AppRole role.

        Uses GET .../role/<name>/role-id, LIST .../role/<name>/secret-id and
        POST .../role/<name>/secret-id-accessor/lookup. Secret IDs are sorted from
        newest to oldest.
        """
        base = f"/auth/{method.mount_path}/role/{role}"
        semaphore = asyncio.Semaphore(8)

        async def role_id() -> str:
            async with semaphore:
                response = await self.request("GET", f"{base}/role-id")
            response.raise_for_status()
            return response.json().get("data", {}).get("role_id", "")

        rid, secret_ids = await asyncio.gather(
            role_id(), self._approle_secret_ids(base, semaphore)
        )
        oldest = datetime.min.replace(tzinfo=UTC)
        secret_ids.sort(key=lambda s: s.creation_time or oldest, reverse=True)
        return AppRoleCredentials(rid, secret_ids)

    async def _approle_secret_ids(
        self, base: str, semaphore: asyncio.Semaphore
    ) -> list[AppRoleSecretId]:
        """List the secret IDs of an AppRole role and look up each accessor."""
        async with semaphore:
            response = await self.request("GET", f"{base}/secret-id", params={"list": "true"})
        if response.status_code == 404:
            return []
        response.raise_for_status()
        accessors = response.json().get("data", {}).get("keys") or []

        async def lookup(accessor: str) -> AppRoleSecretId | None:
            async with semaphore:
                resp = await self.request(
                    "POST",
                    f"{base}/secret-id-accessor/lookup",
                    json={"secret_id_accessor": accessor},
                )
            # The secret ID may have been deleted or tidied between the list and the lookup.
            if resp.status_code in (204, 404):
                return None
            resp.raise_for_status()
            data = resp.json().get("data")
            return AppRoleSecretId.from_lookup(accessor, data) if data else None

        return [s for s in await asyncio.gather(*map(lookup, accessors)) if s]

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
