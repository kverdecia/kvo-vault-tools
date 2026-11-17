import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import flet as ft
import httpx2

from kvo_vault_tools.vault import AppRoleState, AppRoleStatus, AuthMethod, VaultClient

AUTH_BACKEND_ICON = ft.Icons.KEY


def _auth_backend_icon() -> ft.Icon:
    return ft.Icon(AUTH_BACKEND_ICON, size=20, color=ft.Colors.PRIMARY)


OpenBackend = Callable[[AuthMethod], Awaitable[None]]


def _auth_methods_table(methods: list[AuthMethod], on_open: OpenBackend) -> ft.DataTable:
    def open_handler(method: AuthMethod) -> Callable[[ft.Event], Awaitable[None]]:
        async def handler(_: ft.Event) -> None:
            await on_open(method)

        return handler

    return ft.DataTable(
        show_checkbox_column=False,
        columns=[
            ft.DataColumn("Path"),
            ft.DataColumn("Type"),
            ft.DataColumn("Description"),
            ft.DataColumn("Accessor"),
            ft.DataColumn("Local"),
            ft.DataColumn(""),
        ],
        rows=[
            ft.DataRow(
                on_select_change=open_handler(method),
                cells=[
                    ft.DataCell(
                        ft.Row(
                            [
                                _auth_backend_icon(),
                                ft.Text(method.path, weight=ft.FontWeight.BOLD),
                            ],
                            spacing=8,
                            tight=True,
                        )
                    ),
                    ft.DataCell(method.type),
                    ft.DataCell(method.description or "—"),
                    ft.DataCell(ft.Text(method.accessor, selectable=True)),
                    ft.DataCell("Yes" if method.local else "No"),
                    ft.DataCell(
                        ft.IconButton(
                            ft.Icons.CHEVRON_RIGHT,
                            tooltip="Show details",
                            on_click=open_handler(method),
                        )
                    ),
                ]
            )
            for method in methods
        ],
    )


ALL_TYPES = "__all__"


class AuthenticationSection(ft.Column):
    """Section that lists the authentication backends enabled on the server."""

    def __init__(self, client: VaultClient, on_open: OpenBackend) -> None:
        self.client = client
        self.on_open = on_open
        self.methods: list[AuthMethod] = []
        self.search_field = ft.TextField(
            label="Search by name",
            prefix_icon=ft.Icons.SEARCH,
            width=320,
            on_change=self.on_filter,
        )
        self.type_dropdown = ft.Dropdown(
            label="Type",
            value=ALL_TYPES,
            options=[ft.DropdownOption(key=ALL_TYPES, text="All types")],
            width=220,
            on_select=self.on_filter,
        )
        self.progress = ft.ProgressRing(width=20, height=20, visible=False)
        self.body = ft.Column(horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        super().__init__(
            controls=[
                ft.Row(
                    [
                        ft.Text("Authentication", size=18, weight=ft.FontWeight.BOLD),
                        ft.IconButton(
                            ft.Icons.REFRESH,
                            tooltip="Reload authentication backends",
                            on_click=self.on_refresh,
                        ),
                        self.progress,
                    ],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Row([self.search_field, self.type_dropdown], spacing=12),
                self.body,
            ],
            spacing=8,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        )

    async def on_refresh(self, _: ft.Event) -> None:
        await self.load()

    async def on_filter(self, _: ft.Event) -> None:
        self.render()
        self.update()

    def render(self) -> None:
        if not self.methods:
            self.body.controls = [ft.Text("No authentication backends enabled.")]
            return
        query = (self.search_field.value or "").strip().lower()
        selected_type = self.type_dropdown.value or ALL_TYPES
        methods = [
            m
            for m in self.methods
            if query in m.path.lower() and selected_type in (ALL_TYPES, m.type)
        ]
        self.body.controls = [
            _auth_methods_table(methods, self.on_open)
            if methods
            else ft.Text("No authentication backends match the current filters.")
        ]

    def update_type_options(self) -> None:
        types = sorted({m.type for m in self.methods})
        self.type_dropdown.options = [
            ft.DropdownOption(key=ALL_TYPES, text="All types"),
            *(ft.DropdownOption(key=t, text=t) for t in types),
        ]
        if self.type_dropdown.value not in (ALL_TYPES, *types):
            self.type_dropdown.value = ALL_TYPES

    async def load(self) -> None:
        self.progress.visible = True
        self.update()
        try:
            self.methods = await self.client.list_auth_methods()
        except httpx2.HTTPStatusError as exc:
            self.body.controls = [self._error(f"Vault returned HTTP {exc.response.status_code}.")]
        except httpx2.HTTPError as exc:
            self.body.controls = [self._error(f"Could not reach the Vault server: {exc}")]
        else:
            self.update_type_options()
            self.render()
        finally:
            self.progress.visible = False
            self.update()

    @staticmethod
    def _error(message: str) -> ft.Text:
        return ft.Text(message, color=ft.Colors.ERROR)


def _format_ttl(value: Any) -> str:
    """Format a TTL in seconds; 0 means the system default."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return str(value)
    if seconds == 0:
        return "System default"
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        amount, seconds = divmod(seconds, size)
        if amount:
            parts.append(f"{amount}{unit}")
    return " ".join(parts)


def _format_value(key: str, value: Any) -> str:
    if key.endswith("_ttl"):
        return _format_ttl(value)
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) or "—"
    if value in (None, ""):
        return "—"
    return str(value)


def _properties_card(title: str, items: list[tuple[str, str]]) -> ft.Card:
    rows = [
        ft.Row(
            [
                ft.Text(label, weight=ft.FontWeight.BOLD, width=220),
                ft.Text(value, selectable=True, expand=True),
            ],
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        for label, value in items
    ] or [ft.Text("No values.", italic=True)]
    return ft.Card(
        content=ft.Container(
            ft.Column(
                [ft.Text(title, size=16, weight=ft.FontWeight.BOLD), *rows],
                spacing=8,
            ),
            padding=16,
        )
    )


def _format_datetime(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M")


def _status_chip(text: str, color: ft.Colors, tooltip: str | None = None) -> ft.Container:
    return ft.Container(
        ft.Text(text, size=12, color=color, weight=ft.FontWeight.BOLD),
        border=ft.Border.all(1, color),
        border_radius=12,
        padding=ft.Padding.symmetric(horizontal=8, vertical=2),
        tooltip=tooltip,
    )


def _approle_status_controls(status: AppRoleStatus | Exception | None) -> list[ft.Control]:
    """Chip (and detail text) that tells whether an AppRole role has expired."""
    if status is None:
        return [
            ft.ProgressRing(width=12, height=12, stroke_width=2),
            ft.Text("Checking…", size=12, color=ft.Colors.ON_SURFACE_VARIANT),
        ]
    if isinstance(status, Exception):
        return [_status_chip("Unknown", ft.Colors.ON_SURFACE_VARIANT, tooltip=str(status))]

    count = f"{status.secret_id_count} secret ID{'s' if status.secret_id_count != 1 else ''}"
    match status.state:
        case AppRoleState.ACTIVE:
            detail = (
                f"expires {_format_datetime(status.expires_at)}"
                if status.expires_at
                else "never expires"
            )
            chip = _status_chip("Active", ft.Colors.GREEN)
            return [chip, ft.Text(f"{count}, {detail}", size=12)]
        case AppRoleState.EXPIRED:
            chip = _status_chip("Expired", ft.Colors.ERROR)
            detail = f"{count}, all expired"
            if status.expires_at:
                detail += f" (last on {_format_datetime(status.expires_at)})"
            return [chip, ft.Text(detail, size=12)]
        case AppRoleState.NO_SECRET_IDS:
            chip = _status_chip(
                "Expired",
                ft.Colors.ERROR,
                tooltip="The role needs a secret ID to log in but has none.",
            )
            return [chip, ft.Text("no secret IDs", size=12)]
        case AppRoleState.NOT_REQUIRED:
            return [
                _status_chip(
                    "No expiration",
                    ft.Colors.ON_SURFACE_VARIANT,
                    tooltip="bind_secret_id is false: the role does not use secret IDs.",
                ),
            ]


def _humanize(key: str) -> str:
    return key.replace("_", " ").capitalize()


class AuthBackendDetail(ft.Column):
    """Details of one authentication backend, including its roles."""

    def __init__(
        self,
        client: VaultClient,
        method: AuthMethod,
        on_back: Callable[[], Awaitable[None]],
    ) -> None:
        self.client = client
        self.method = method
        self.on_back = on_back
        self.roles: list[str] = []
        # AppRole only: status of each role (None while it is being checked).
        self.role_statuses: dict[str, AppRoleStatus | Exception | None] = {}
        self._load_id = 0
        self.role_search = ft.TextField(
            label="Search roles",
            prefix_icon=ft.Icons.SEARCH,
            width=320,
            on_change=self.on_filter,
        )
        self.roles_title = ft.Text("Roles", size=16, weight=ft.FontWeight.BOLD)
        self.progress = ft.ProgressRing(width=20, height=20, visible=False)
        self.roles_body = ft.Column(spacing=4)

        general = [
            ("Path", method.path),
            ("Type", method.type),
            ("Description", method.description or "—"),
            ("Accessor", method.accessor),
            ("UUID", method.uuid or "—"),
            ("Local", _format_value("local", method.local)),
            ("Seal wrap", _format_value("seal_wrap", method.seal_wrap)),
            (
                "External entropy access",
                _format_value("external_entropy_access", method.external_entropy_access),
            ),
            ("Plugin version", method.plugin_version or "—"),
            ("Running plugin version", method.running_plugin_version or "—"),
        ]
        config = [(_humanize(k), _format_value(k, v)) for k, v in sorted(method.config.items())]
        options = [(_humanize(k), _format_value(k, v)) for k, v in sorted(method.options.items())]

        cards = [
            _properties_card("General", general),
            _properties_card("Configuration", config),
        ]
        if options:
            cards.append(_properties_card("Options", options))

        super().__init__(
            controls=[
                ft.Row(
                    [
                        ft.IconButton(
                            ft.Icons.ARROW_BACK,
                            tooltip="Back to authentication backends",
                            on_click=self.on_back_click,
                        ),
                        _auth_backend_icon(),
                        ft.Text(method.path, size=18, weight=ft.FontWeight.BOLD),
                        ft.Text(f"({method.type})", color=ft.Colors.ON_SURFACE_VARIANT),
                    ],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                *cards,
                self._roles_card(),
            ],
            spacing=8,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        )

    def _roles_card(self) -> ft.Card:
        controls: list[ft.Control] = [
            ft.Row(
                [
                    self.roles_title,
                    ft.IconButton(
                        ft.Icons.REFRESH,
                        tooltip="Reload roles",
                        on_click=self.on_refresh,
                        visible=self.method.supports_roles,
                    ),
                    self.progress,
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
        ]
        if self.method.supports_roles:
            controls += [self.role_search, self.roles_body]
        else:
            controls.append(
                ft.Text(
                    f"Authentication backends of type '{self.method.type}' have no roles.",
                    italic=True,
                )
            )
        return ft.Card(content=ft.Container(ft.Column(controls, spacing=8), padding=16))

    async def on_back_click(self, _: ft.Event) -> None:
        await self.on_back()

    async def on_refresh(self, _: ft.Event) -> None:
        await self.load()

    async def on_filter(self, _: ft.Event) -> None:
        self.render_roles()
        self.update()

    @property
    def is_approle(self) -> bool:
        return self.method.type == "approle"

    def render_roles(self) -> None:
        title = f"Roles ({len(self.roles)})"
        if self.is_approle:
            expired = sum(
                1
                for s in self.role_statuses.values()
                if isinstance(s, AppRoleStatus) and s.is_expired
            )
            if expired:
                title += f" — {expired} expired"
        self.roles_title.value = title
        if not self.roles:
            self.roles_body.controls = [ft.Text("This backend has no roles.", italic=True)]
            return
        query = (self.role_search.value or "").strip().lower()
        roles = [r for r in self.roles if query in r.lower()]
        self.roles_body.controls = (
            [
                ft.Row(
                    [
                        ft.Icon(ft.Icons.BADGE, size=18, color=ft.Colors.PRIMARY),
                        ft.Text(role, selectable=True),
                        *(
                            _approle_status_controls(self.role_statuses.get(role))
                            if self.is_approle
                            else []
                        ),
                    ],
                    spacing=8,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                )
                for role in roles
            ]
            if roles
            else [ft.Text("No roles match the search.", italic=True)]
        )

    async def load(self) -> None:
        if not self.method.supports_roles:
            return
        self._load_id += 1
        load_id = self._load_id
        self.progress.visible = True
        self.update()
        try:
            self.roles = await self.client.list_auth_roles(self.method)
            self.role_statuses = {role: None for role in self.roles} if self.is_approle else {}
        except httpx2.HTTPStatusError as exc:
            self.roles_body.controls = [
                AuthenticationSection._error(
                    f"Vault returned HTTP {exc.response.status_code} while listing roles."
                )
            ]
        except httpx2.HTTPError as exc:
            self.roles_body.controls = [
                AuthenticationSection._error(f"Could not reach the Vault server: {exc}")
            ]
        else:
            self.render_roles()
            if self.is_approle:
                self.update()
                await self.load_approle_statuses(load_id)
        finally:
            if load_id == self._load_id:
                self.progress.visible = False
                self.update()

    async def load_approle_statuses(self, load_id: int) -> None:
        """Check whether each AppRole role has expired, refreshing the list as results arrive."""
        semaphore = asyncio.Semaphore(8)

        async def check(role: str) -> None:
            try:
                status: AppRoleStatus | Exception = await self.client.approle_role_status(
                    self.method, role, semaphore
                )
            except httpx2.HTTPStatusError as exc:
                status = Exception(f"Vault returned HTTP {exc.response.status_code}.")
            except httpx2.HTTPError as exc:
                status = Exception(f"Could not reach the Vault server: {exc}")
            if load_id != self._load_id:
                return  # A newer reload started; drop stale results.
            self.role_statuses[role] = status
            self.render_roles()
            self.update()

        await asyncio.gather(*(check(role) for role in self.roles))


async def show_vault_view(page: ft.Page, client: VaultClient) -> None:
    """Replace the page content with the main Vault view."""
    page.clean()
    page.window.width = 1280
    page.window.height = 720
    page.vertical_alignment = ft.MainAxisAlignment.START
    page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH
    page.scroll = ft.ScrollMode.AUTO
    page.appbar = ft.AppBar(title=ft.Text(f"Vault — {client.url}"))

    async def show_list() -> None:
        page.controls = [auth_section]
        page.update()

    async def open_backend(method: AuthMethod) -> None:
        detail = AuthBackendDetail(client, method, on_back=show_list)
        page.controls = [detail]
        page.update()
        await detail.load()

    auth_section = AuthenticationSection(client, on_open=open_backend)
    page.add(auth_section)
    await page.window.center()
    await auth_section.load()
