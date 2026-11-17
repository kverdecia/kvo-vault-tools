import flet as ft
import httpx2

from kvo_vault_tools.vault import AuthMethod, VaultClient

AUTH_BACKEND_ICON = ft.Icons.KEY


def _auth_backend_icon() -> ft.Icon:
    return ft.Icon(AUTH_BACKEND_ICON, size=20, color=ft.Colors.PRIMARY)


def _auth_methods_table(methods: list[AuthMethod]) -> ft.DataTable:
    return ft.DataTable(
        columns=[
            ft.DataColumn("Path"),
            ft.DataColumn("Type"),
            ft.DataColumn("Description"),
            ft.DataColumn("Accessor"),
            ft.DataColumn("Local"),
        ],
        rows=[
            ft.DataRow(
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
                ]
            )
            for method in methods
        ],
    )


ALL_TYPES = "__all__"


class AuthenticationSection(ft.Column):
    """Section that lists the authentication backends enabled on the server."""

    def __init__(self, client: VaultClient) -> None:
        self.client = client
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
            _auth_methods_table(methods)
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


async def show_vault_view(page: ft.Page, client: VaultClient) -> None:
    """Replace the page content with the main Vault view."""
    page.clean()
    page.window.width = 1280
    page.window.height = 720
    page.vertical_alignment = ft.MainAxisAlignment.START
    page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH
    page.scroll = ft.ScrollMode.AUTO
    page.appbar = ft.AppBar(title=ft.Text(f"Vault — {client.url}"))

    auth_section = AuthenticationSection(client)
    page.add(auth_section)
    await page.window.center()
    await auth_section.load()
