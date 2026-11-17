import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import flet as ft
import httpx2

from kvo_vault_tools.vault import (
    AppRoleCredentials,
    AppRoleSecretId,
    AppRoleState,
    AppRoleStatus,
    AuthMethod,
    GeneratedSecretId,
    VaultClient,
)

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


def _secret_id_status_chip(secret_id: AppRoleSecretId) -> ft.Container:
    if secret_id.is_expired:
        return _status_chip("Expired", ft.Colors.ERROR)
    return _status_chip("Active", ft.Colors.GREEN)


def _optional_datetime(value: datetime | None, empty: str = "—") -> str:
    return _format_datetime(value) if value else empty


def _secret_ids_table(secret_ids: list[AppRoleSecretId]) -> ft.Control:
    table = ft.DataTable(
        show_checkbox_column=False,
        columns=[
            ft.DataColumn("Accessor"),
            ft.DataColumn("Status"),
            ft.DataColumn("Created"),
            ft.DataColumn("Expires"),
            ft.DataColumn("Last updated"),
            ft.DataColumn("Uses left"),
            ft.DataColumn("TTL"),
            ft.DataColumn("CIDR list"),
            ft.DataColumn("Token bound CIDRs"),
            ft.DataColumn("Metadata"),
        ],
        rows=[
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(s.accessor, selectable=True, font_family="monospace")),
                    ft.DataCell(_secret_id_status_chip(s)),
                    ft.DataCell(_optional_datetime(s.creation_time)),
                    ft.DataCell(_optional_datetime(s.expiration_time, "Never")),
                    ft.DataCell(_optional_datetime(s.last_updated_time)),
                    ft.DataCell(str(s.num_uses) if s.num_uses else "Unlimited"),
                    ft.DataCell(_format_ttl(s.ttl) if s.ttl else "None"),
                    ft.DataCell(", ".join(s.cidr_list) or "—"),
                    ft.DataCell(", ".join(s.token_bound_cidrs) or "—"),
                    ft.DataCell(
                        ft.Text(
                            ", ".join(f"{k}={v}" for k, v in sorted(s.metadata.items())) or "—",
                            selectable=True,
                        )
                    ),
                ]
            )
            for s in secret_ids
        ],
    )
    # The table is wide: let it scroll horizontally instead of overflowing.
    return ft.Row([table], scroll=ft.ScrollMode.AUTO)


def _approle_credentials_panel(credentials: AppRoleCredentials | Exception | None) -> ft.Control:
    """Role ID and secret IDs of an AppRole role, shown under the role when revealed."""
    if credentials is None:
        content: ft.Control = ft.Row(
            [
                ft.ProgressRing(width=14, height=14, stroke_width=2),
                ft.Text("Loading role ID and secret IDs…", size=12),
            ],
            spacing=8,
        )
    elif isinstance(credentials, Exception):
        content = ft.Text(str(credentials), color=ft.Colors.ERROR)
    else:
        count = len(credentials.secret_ids)
        content = ft.Column(
            [
                ft.Row(
                    [
                        ft.Text("Role ID", weight=ft.FontWeight.BOLD, width=120),
                        ft.Text(
                            credentials.role_id or "—",
                            selectable=True,
                            font_family="monospace",
                        ),
                    ],
                ),
                ft.Text(f"Secret IDs ({count})", weight=ft.FontWeight.BOLD),
                _secret_ids_table(credentials.secret_ids)
                if count
                else ft.Text("This role has no secret IDs.", italic=True),
            ],
            spacing=8,
        )
    return ft.Container(
        content,
        margin=ft.Margin.only(left=26, bottom=8),
        padding=ft.Padding.only(left=12, top=4, bottom=4),
        border=ft.Border.only(left=ft.BorderSide(2, ft.Colors.OUTLINE_VARIANT)),
    )


def _new_secret_id_dialog(
    role: str, generated: GeneratedSecretId, on_close: Callable[[ft.Event], Any]
) -> ft.AlertDialog:
    """Modal dialog that shows a secret ID just created, with a copy button."""
    copied = ft.Text("", size=12, color=ft.Colors.GREEN)

    async def on_copy(_: ft.Event) -> None:
        copied.value = "Copied to the clipboard."
        copied.update()

    details = [
        ("Accessor", generated.accessor or "—"),
        ("TTL", _format_ttl(generated.ttl) if generated.ttl else "Never expires"),
        ("Uses", str(generated.num_uses) if generated.num_uses else "Unlimited"),
    ]
    return ft.AlertDialog(
        modal=True,
        title=ft.Text(f"New secret ID for '{role}'"),
        content=ft.Column(
            [
                ft.Container(
                    ft.Row(
                        [
                            ft.Icon(ft.Icons.WARNING_AMBER, color=ft.Colors.ON_ERROR_CONTAINER),
                            ft.Text(
                                "Copy this secret ID now. Vault won't show it again: "
                                "once you close this dialog, you can't get it back.",
                                color=ft.Colors.ON_ERROR_CONTAINER,
                                weight=ft.FontWeight.BOLD,
                                expand=True,
                            ),
                        ],
                        spacing=8,
                    ),
                    bgcolor=ft.Colors.ERROR_CONTAINER,
                    border_radius=8,
                    padding=12,
                ),
                ft.Row(
                    [
                        ft.Text(
                            generated.secret_id,
                            selectable=True,
                            font_family="monospace",
                            expand=True,
                        ),
                        ft.FilledButton(
                            "Copy",
                            icon=ft.Icons.COPY,
                            action=ft.CopyToClipboard(generated.secret_id),
                            on_click=on_copy,
                        ),
                    ],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                copied,
                *(
                    ft.Row(
                        [
                            ft.Text(label, weight=ft.FontWeight.BOLD, width=100),
                            ft.Text(value, selectable=True, font_family="monospace"),
                        ]
                    )
                    for label, value in details
                ),
            ],
            spacing=12,
            tight=True,
            width=560,
        ),
        actions=[ft.TextButton("Close", on_click=on_close)],
    )


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
        # AppRole only: credentials of the revealed roles (None while they are loading).
        self.revealed: dict[str, AppRoleCredentials | Exception | None] = {}
        # AppRole only: roles whose new secret ID is being created.
        self.generating: set[str] = set()
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
        if not roles:
            self.roles_body.controls = [ft.Text("No roles match the search.", italic=True)]
            return
        controls: list[ft.Control] = []
        for role in roles:
            controls.append(self._role_row(role))
            if role in self.revealed:
                controls.append(_approle_credentials_panel(self.revealed[role]))
        self.roles_body.controls = controls

    def _role_row(self, role: str) -> ft.Row:
        controls: list[ft.Control] = [
            ft.Icon(ft.Icons.BADGE, size=18, color=ft.Colors.PRIMARY),
            ft.Text(role, selectable=True),
        ]
        if self.is_approle:
            controls += _approle_status_controls(self.role_statuses.get(role))
            revealed = role in self.revealed
            controls.append(
                ft.TextButton(
                    "Hide" if revealed else "Reveal",
                    icon=ft.Icons.VISIBILITY_OFF if revealed else ft.Icons.VISIBILITY,
                    tooltip=None if revealed else "Show the role ID and the secret IDs",
                    on_click=self._reveal_handler(role),
                )
            )
            status = self.role_statuses.get(role)
            # Roles with bind_secret_id=false don't use secret IDs.
            if not (isinstance(status, AppRoleStatus) and status.state is AppRoleState.NOT_REQUIRED):
                generating = role in self.generating
                controls.append(
                    ft.TextButton(
                        "Creating…" if generating else "New secret ID",
                        icon=ft.Icons.ADD,
                        tooltip="Create a new secret ID for this role",
                        disabled=generating,
                        on_click=self._new_secret_id_handler(role),
                    )
                )
        return ft.Row(controls, spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    def _reveal_handler(self, role: str) -> Callable[[ft.Event], Awaitable[None]]:
        async def handler(_: ft.Event) -> None:
            await self.toggle_reveal(role)

        return handler

    def _new_secret_id_handler(self, role: str) -> Callable[[ft.Event], Awaitable[None]]:
        async def handler(_: ft.Event) -> None:
            await self.create_secret_id(role)

        return handler

    async def create_secret_id(self, role: str) -> None:
        """Create a secret ID for an AppRole role and show it once, so it can be copied."""
        if role in self.generating:
            return
        self.generating.add(role)
        self.render_roles()
        self.update()
        try:
            generated = await self.client.approle_generate_secret_id(self.method, role)
        except httpx2.HTTPStatusError as exc:
            error = f"Vault returned HTTP {exc.response.status_code} while creating the secret ID."
        except httpx2.HTTPError as exc:
            error = f"Could not reach the Vault server: {exc}"
        else:
            error = None
        finally:
            self.generating.discard(role)
            self.render_roles()
            self.update()

        if error is not None:
            self.page.show_dialog(ft.SnackBar(ft.Text(error), bgcolor=ft.Colors.ERROR_CONTAINER))
            return

        def on_close(_: ft.Event) -> None:
            self.page.pop_dialog()

        self.page.show_dialog(_new_secret_id_dialog(role, generated, on_close))
        await self.refresh_role(role)

    async def refresh_role(self, role: str) -> None:
        """Reload the status (and the credentials, if revealed) of one AppRole role."""
        load_id = self._load_id
        try:
            status: AppRoleStatus | Exception = await self.client.approle_role_status(
                self.method, role
            )
        except httpx2.HTTPStatusError as exc:
            status = Exception(f"Vault returned HTTP {exc.response.status_code}.")
        except httpx2.HTTPError as exc:
            status = Exception(f"Could not reach the Vault server: {exc}")
        if load_id != self._load_id:
            return
        self.role_statuses[role] = status
        self.render_roles()
        self.update()
        if role in self.revealed:
            # Hide and reveal again to fetch the new secret ID list.
            del self.revealed[role]
            await self.toggle_reveal(role)

    async def toggle_reveal(self, role: str) -> None:
        """Show (fetching them) or hide the role ID and secret IDs of an AppRole role."""
        if role in self.revealed:
            del self.revealed[role]
            self.render_roles()
            self.update()
            return
        load_id = self._load_id
        self.revealed[role] = None
        self.render_roles()
        self.update()
        try:
            credentials: AppRoleCredentials | Exception = await self.client.approle_credentials(
                self.method, role
            )
        except httpx2.HTTPStatusError as exc:
            credentials = Exception(
                f"Vault returned HTTP {exc.response.status_code} while reading the role credentials."
            )
        except httpx2.HTTPError as exc:
            credentials = Exception(f"Could not reach the Vault server: {exc}")
        # Drop the result if the roles were reloaded or the role was hidden meanwhile.
        if load_id != self._load_id or role not in self.revealed:
            return
        self.revealed[role] = credentials
        self.render_roles()
        self.update()

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
            self.revealed = {}
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
