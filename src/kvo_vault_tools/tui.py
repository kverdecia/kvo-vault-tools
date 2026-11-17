"""Terminal (TUI) version of KVO Vault Tools, built with Textual.

It offers the same features as the desktop application: connect to a Vault server,
list the authentication backends, show the details and roles of each backend and,
for AppRole backends, check whether each role has expired, reveal its role ID and
secret IDs, and create new secret IDs.
"""

import asyncio
import os
import shutil
import subprocess

import httpx2
from rich.console import RenderableType
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    LoadingIndicator,
    Select,
    Static,
)
from textual.widgets.data_table import CellDoesNotExist, RowDoesNotExist

from kvo_vault_tools.formatting import (
    format_datetime,
    format_ttl,
    format_value,
    humanize,
    optional_datetime,
)
from kvo_vault_tools.vault import (
    AppRoleCredentials,
    AppRoleSecretId,
    AppRoleState,
    AppRoleStatus,
    AuthMethod,
    GeneratedSecretId,
    VaultClient,
    VaultConnectionError,
    connect,
)


def _describe_error(exc: httpx2.HTTPError, action: str = "") -> str:
    """Error message for a failed Vault request; ``action`` says what was being done."""
    if isinstance(exc, httpx2.HTTPStatusError):
        suffix = f" while {action}" if action else ""
        return f"Vault returned HTTP {exc.response.status_code}{suffix}."
    return f"Could not reach the Vault server: {exc}"


def _properties(items: list[tuple[str, str]]) -> RenderableType:
    """Two-column grid of label/value pairs."""
    if not items:
        return Text("No values.", style="italic")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", min_width=24, no_wrap=True)
    grid.add_column(overflow="fold")
    for label, value in items:
        grid.add_row(label, value)
    return grid


def _copy_to_system_clipboard(text: str) -> bool:
    """Copy text with the operating system's clipboard tool, if one is installed."""
    commands = (
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip"],
    )
    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        try:
            subprocess.run(command, input=text.encode(), check=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        return True
    return False


# --------------------------------------------------------------------------- connection


class ConnectScreen(Screen[None]):
    """Asks for the Vault server URL and the root token."""

    AUTO_FOCUS = "#url"
    BINDINGS = [Binding("ctrl+t", "toggle_token", "Show/hide token")]

    def compose(self) -> ComposeResult:
        with Vertical(id="connect-box"):
            yield Label("Connect to HashiCorp Vault", id="connect-title")
            yield Label("Vault server URL")
            yield Input(
                os.environ.get("VAULT_ADDR", ""),
                placeholder="https://vault.example.com:8200",
                id="url",
            )
            yield Label("Root token")
            yield Input(os.environ.get("VAULT_TOKEN", ""), password=True, id="token")
            with Horizontal(id="connect-actions"):
                yield Button("Connect", variant="primary", id="connect")
                yield LoadingIndicator(id="connect-progress")
            yield Static(id="connect-status")
        yield Footer()

    def action_toggle_token(self) -> None:
        token = self.query_one("#token", Input)
        token.password = not token.password

    @on(Input.Submitted, "#url")
    def focus_token(self) -> None:
        self.query_one("#token", Input).focus()

    @on(Input.Submitted, "#token")
    @on(Button.Pressed, "#connect")
    def on_connect(self) -> None:
        url_field = self.query_one("#url", Input)
        token_field = self.query_one("#token", Input)
        url = url_field.value.strip()
        token = token_field.value.strip()

        url_field.set_class(not url, "-invalid")
        token_field.set_class(not token, "-invalid")
        missing = [name for name, value in (("URL", url), ("token", token)) if not value]
        if missing:
            verb = "is" if len(missing) == 1 else "are"
            self._set_status(f"The {' and the '.join(missing)} {verb} required.", error=True)
            return
        self.do_connect(url, token)

    def _set_status(self, message: str, error: bool = False) -> None:
        status = self.query_one("#connect-status", Static)
        status.update(message)
        status.set_class(error, "error")

    @work(exclusive=True)
    async def do_connect(self, url: str, token: str) -> None:
        button = self.query_one("#connect", Button)
        progress = self.query_one("#connect-progress", LoadingIndicator)
        button.disabled = True
        progress.display = True
        self._set_status("Connecting...")
        try:
            client = await connect(url, token)
        except VaultConnectionError as exc:
            self._set_status(str(exc), error=True)
            button.disabled = False
            progress.display = False
            return
        app = self.app
        assert isinstance(app, VaultToolsApp)
        app.client = client
        # Not awaited: this worker belongs to this screen, which the switch removes
        # (cancelling the worker), so awaiting it would cut the new screen's mount short.
        app.switch_screen(AuthListScreen(client))


# --------------------------------------------------------------------------- backend list


class AuthListScreen(Screen[None]):
    """Lists the authentication backends enabled on the server, with filters."""

    AUTO_FOCUS = "#auth-table"
    BINDINGS = [
        Binding("f5", "refresh", "Reload"),
        Binding("ctrl+f", "focus_search", "Search"),
    ]

    def __init__(self, client: VaultClient) -> None:
        super().__init__()
        self.client = client
        self.methods: list[AuthMethod] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="auth-section", classes="section"):
            with Horizontal(classes="filters"):
                yield Input(placeholder="Search by name", id="auth-search")
                yield Select[str]([], prompt="All types", id="auth-type")
            yield Static(id="auth-message")
            yield DataTable(id="auth-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"Vault — {self.client.url}"
        self.query_one("#auth-section").border_title = "Authentication"
        table = self.query_one("#auth-table", DataTable)
        table.add_columns("Path", "Type", "Description", "Accessor", "Local")
        self.load()

    def action_refresh(self) -> None:
        self.load()

    def action_focus_search(self) -> None:
        self.query_one("#auth-search", Input).focus()

    @on(Input.Changed, "#auth-search")
    @on(Select.Changed, "#auth-type")
    def on_filter(self) -> None:
        self.render_methods()

    @on(Input.Submitted, "#auth-search")
    def focus_table(self) -> None:
        self.query_one("#auth-table", DataTable).focus()

    @on(DataTable.RowSelected, "#auth-table")
    def open_backend(self, event: DataTable.RowSelected) -> None:
        method = next(m for m in self.methods if m.path == event.row_key.value)
        self.app.push_screen(BackendDetailScreen(self.client, method))

    def _show_message(self, message: str, error: bool = False) -> None:
        widget = self.query_one("#auth-message", Static)
        widget.update(message)
        widget.set_class(error, "error")
        widget.display = bool(message)

    def render_methods(self) -> None:
        table = self.query_one("#auth-table", DataTable)
        table.clear()
        if not self.methods:
            self._show_message("No authentication backends enabled.")
            return
        query = self.query_one("#auth-search", Input).value.strip().lower()
        selected = self.query_one("#auth-type", Select).value
        selected_type = selected if isinstance(selected, str) else None
        methods = [
            m
            for m in self.methods
            if query in m.path.lower() and selected_type in (None, m.type)
        ]
        for m in methods:
            table.add_row(
                Text(m.path, style="bold"),
                m.type,
                m.description or "—",
                m.accessor,
                "Yes" if m.local else "No",
                key=m.path,
            )
        self._show_message(
            "" if methods else "No authentication backends match the current filters."
        )

    def update_type_options(self) -> None:
        select = self.query_one("#auth-type", Select)
        current = select.value
        types = sorted({m.type for m in self.methods})
        select.set_options((t, t) for t in types)
        if isinstance(current, str) and current in types:
            select.value = current

    @work(exclusive=True, group="auth-methods")
    async def load(self) -> None:
        table = self.query_one("#auth-table", DataTable)
        table.loading = True
        try:
            self.methods = await self.client.list_auth_methods()
        except httpx2.HTTPError as exc:
            table.clear()
            self._show_message(_describe_error(exc), error=True)
        else:
            self.update_type_options()
            self.render_methods()
        finally:
            table.loading = False


# --------------------------------------------------------------------------- backend detail


def _approle_status_cells(status: AppRoleStatus | Exception | None) -> tuple[Text, Text]:
    """Status and detail cells telling whether an AppRole role has expired."""
    if status is None:
        return Text("Checking…", style="dim"), Text("")
    if isinstance(status, Exception):
        return Text("Unknown", style="bold dim"), Text(str(status), style="red")

    count = f"{status.secret_id_count} secret ID{'s' if status.secret_id_count != 1 else ''}"
    match status.state:
        case AppRoleState.ACTIVE:
            detail = (
                f"expires {format_datetime(status.expires_at)}"
                if status.expires_at
                else "never expires"
            )
            return Text("Active", style="bold green"), Text(f"{count}, {detail}")
        case AppRoleState.EXPIRED:
            detail = f"{count}, all expired"
            if status.expires_at:
                detail += f" (last on {format_datetime(status.expires_at)})"
            return Text("Expired", style="bold red"), Text(detail)
        case AppRoleState.NO_SECRET_IDS:
            return Text("Expired", style="bold red"), Text(
                "no secret IDs (the role needs one to log in)"
            )
        case AppRoleState.NOT_REQUIRED:
            return Text("No expiration", style="bold"), Text(
                "bind_secret_id is false: the role does not use secret IDs", style="dim"
            )


def _secret_id_status(secret_id: AppRoleSecretId) -> Text:
    if secret_id.is_expired:
        return Text("Expired", style="bold red")
    return Text("Active", style="bold green")


class CredentialsPanel(Vertical):
    """Role ID and secret IDs of a revealed AppRole role."""

    def __init__(self, role: str, credentials: AppRoleCredentials | Exception | None) -> None:
        super().__init__(classes="credentials")
        self.role = role
        self.credentials = credentials
        self.border_title = f"{role} — credentials"

    def compose(self) -> ComposeResult:
        credentials = self.credentials
        if credentials is None:
            yield Static("Loading role ID and secret IDs…", classes="dim")
            return
        if isinstance(credentials, Exception):
            yield Static(str(credentials), classes="error")
            return
        yield Static(_properties([("Role ID", credentials.role_id or "—")]))
        count = len(credentials.secret_ids)
        yield Static(Text(f"Secret IDs ({count})", style="bold"))
        if count:
            yield DataTable(cursor_type="row", zebra_stripes=True)
        else:
            yield Static(Text("This role has no secret IDs.", style="italic"))

    def on_mount(self) -> None:
        if not isinstance(self.credentials, AppRoleCredentials) or not self.credentials.secret_ids:
            return
        table = self.query_one(DataTable)
        table.add_columns(
            "Accessor",
            "Status",
            "Created",
            "Expires",
            "Last updated",
            "Uses left",
            "TTL",
            "CIDR list",
            "Token bound CIDRs",
            "Metadata",
        )
        for s in self.credentials.secret_ids:
            table.add_row(
                s.accessor,
                _secret_id_status(s),
                optional_datetime(s.creation_time),
                optional_datetime(s.expiration_time, "Never"),
                optional_datetime(s.last_updated_time),
                str(s.num_uses) if s.num_uses else "Unlimited",
                format_ttl(s.ttl) if s.ttl else "None",
                ", ".join(s.cidr_list) or "—",
                ", ".join(s.token_bound_cidrs) or "—",
                ", ".join(f"{k}={v}" for k, v in sorted(s.metadata.items())) or "—",
            )


class BackendDetailScreen(Screen[None]):
    """Details of one authentication backend, including its roles."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("f5", "refresh", "Reload roles"),
        Binding("ctrl+f", "focus_search", "Search roles"),
        Binding("ctrl+r", "toggle_reveal", "Reveal/Hide"),
        Binding("ctrl+n", "new_secret_id", "New secret ID"),
    ]

    def __init__(self, client: VaultClient, method: AuthMethod) -> None:
        super().__init__()
        self.client = client
        self.method = method
        self.roles: list[str] = []
        # AppRole only: status of each role (None while it is being checked).
        self.role_statuses: dict[str, AppRoleStatus | Exception | None] = {}
        # AppRole only: credentials of the revealed roles (None while they are loading).
        self.revealed: dict[str, AppRoleCredentials | Exception | None] = {}
        # AppRole only: roles whose new secret ID is being created.
        self.generating: set[str] = set()
        self._load_id = 0
        self._revealed_lock = asyncio.Lock()

    @property
    def is_approle(self) -> bool:
        return self.method.type == "approle"

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in ("toggle_reveal", "new_secret_id"):
            return self.is_approle
        if action in ("refresh", "focus_search"):
            return self.method.supports_roles
        return True

    # ----------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        method = self.method
        general = [
            ("Path", method.path),
            ("Type", method.type),
            ("Description", method.description or "—"),
            ("Accessor", method.accessor),
            ("UUID", method.uuid or "—"),
            ("Local", format_value("local", method.local)),
            ("Seal wrap", format_value("seal_wrap", method.seal_wrap)),
            (
                "External entropy access",
                format_value("external_entropy_access", method.external_entropy_access),
            ),
            ("Plugin version", method.plugin_version or "—"),
            ("Running plugin version", method.running_plugin_version or "—"),
        ]
        config = [(humanize(k), format_value(k, v)) for k, v in sorted(method.config.items())]
        options = [(humanize(k), format_value(k, v)) for k, v in sorted(method.options.items())]

        yield Header()
        with VerticalScroll(id="detail"):
            yield Static(_properties(general), id="general", classes="section")
            yield Static(_properties(config), id="config", classes="section")
            if options:
                yield Static(_properties(options), id="options", classes="section")
            with Vertical(id="roles", classes="section"):
                if method.supports_roles:
                    yield Input(placeholder="Search roles", id="role-search")
                    yield Static(id="roles-message")
                    yield DataTable(id="roles-table", cursor_type="row", zebra_stripes=True)
                    if self.is_approle:
                        # Buttons that act on the role highlighted in the table.
                        with Horizontal(id="role-actions"):
                            yield Label(id="selected-role")
                            yield Button("Reveal", id="reveal-button", disabled=True)
                            yield Button(
                                "New secret ID",
                                variant="primary",
                                id="new-secret-id-button",
                                disabled=True,
                            )
                    yield Vertical(id="revealed")
                else:
                    yield Static(
                        Text(
                            f"Authentication backends of type '{method.type}' have no roles.",
                            style="italic",
                        )
                    )
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"Vault — {self.client.url} — {self.method.path} ({self.method.type})"
        self.query_one("#general").border_title = "General"
        self.query_one("#config").border_title = "Configuration"
        for options in self.query("#options"):
            options.border_title = "Options"
        self.query_one("#roles").border_title = "Roles"
        if not self.method.supports_roles:
            return
        table = self.query_one("#roles-table", DataTable)
        table.add_column("Role", key="role")
        if self.is_approle:
            table.add_column("Status", key="status")
            table.add_column("Details", key="details")
            table.add_column("Credentials", key="credentials")
        table.focus()
        self.load()

    # ----------------------------------------------------------------- actions

    def action_refresh(self) -> None:
        self.load()

    def action_focus_search(self) -> None:
        self.query_one("#role-search", Input).focus()

    def action_toggle_reveal(self) -> None:
        if (role := self._current_role()) is not None:
            self.run_worker(self.toggle_reveal(role), group="reveal")

    def action_new_secret_id(self) -> None:
        role = self._current_role()
        if role is None:
            return
        status = self.role_statuses.get(role)
        if isinstance(status, AppRoleStatus) and status.state is AppRoleState.NOT_REQUIRED:
            self.notify(
                f"The role '{role}' has bind_secret_id=false: it does not use secret IDs.",
                severity="warning",
            )
            return
        self.run_worker(self.create_secret_id(role), group="secret-id")

    @on(Input.Changed, "#role-search")
    async def on_filter(self) -> None:
        self.rebuild_roles_table()
        await self.render_revealed()

    @on(Input.Submitted, "#role-search")
    def focus_roles(self) -> None:
        self.query_one("#roles-table", DataTable).focus()

    @on(DataTable.RowSelected, "#roles-table")
    def on_role_selected(self) -> None:
        if self.is_approle:
            self.action_toggle_reveal()

    @on(DataTable.RowHighlighted, "#roles-table")
    def on_role_highlighted(self) -> None:
        self.update_role_actions()

    @on(Button.Pressed, "#reveal-button")
    def on_reveal_pressed(self) -> None:
        self.action_toggle_reveal()

    @on(Button.Pressed, "#new-secret-id-button")
    def on_new_secret_id_pressed(self) -> None:
        self.action_new_secret_id()

    def _current_role(self) -> str | None:
        table = self.query_one("#roles-table", DataTable)
        if not table.row_count:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return row_key.value

    # ----------------------------------------------------------------- rendering

    def _filtered_roles(self) -> list[str]:
        query = self.query_one("#role-search", Input).value.strip().lower()
        return [r for r in self.roles if query in r.lower()]

    def _show_message(self, message: str, error: bool = False) -> None:
        widget = self.query_one("#roles-message", Static)
        widget.update(message)
        widget.set_class(error, "error")
        widget.display = bool(message)

    def update_roles_title(self) -> None:
        title = f"Roles ({len(self.roles)})"
        if self.is_approle:
            expired = sum(
                1
                for s in self.role_statuses.values()
                if isinstance(s, AppRoleStatus) and s.is_expired
            )
            if expired:
                title += f" — {expired} expired"
        self.query_one("#roles").border_title = title

    def _role_cells(self, role: str) -> dict[str, Text | str]:
        cells: dict[str, Text | str] = {"role": role}
        if self.is_approle:
            status, details = _approle_status_cells(self.role_statuses.get(role))
            if role in self.generating:
                details = Text.assemble(details, ("  creating secret ID…", "italic yellow"))
            cells["status"] = status
            cells["details"] = details
            cells["credentials"] = Text("shown", style="cyan") if role in self.revealed else ""
        return cells

    def rebuild_roles_table(self) -> None:
        table = self.query_one("#roles-table", DataTable)
        current = self._current_role()
        table.clear()
        self.update_roles_title()
        if not self.roles:
            self._show_message("This backend has no roles.")
            return
        roles = self._filtered_roles()
        for role in roles:
            table.add_row(*self._role_cells(role).values(), key=role)
        self._show_message("" if roles else "No roles match the search.")
        if current in roles:
            table.move_cursor(row=roles.index(current))
        self.update_role_actions()

    def update_role_row(self, role: str) -> None:
        """Refresh the cells of one role without rebuilding the table."""
        self.update_roles_title()
        self.update_role_actions()
        table = self.query_one("#roles-table", DataTable)
        try:
            for column, value in self._role_cells(role).items():
                table.update_cell(role, column, value, update_width=True)
        except (CellDoesNotExist, RowDoesNotExist):
            pass  # The role is filtered out.

    def update_role_actions(self) -> None:
        """Enable and label the AppRole buttons for the role highlighted in the table."""
        if not self.is_approle:
            return
        role = self._current_role()
        reveal = self.query_one("#reveal-button", Button)
        new_secret_id = self.query_one("#new-secret-id-button", Button)
        self.query_one("#selected-role", Label).update(
            Text.assemble("Role: ", (role, "bold")) if role else Text("No role selected", "dim")
        )
        if role is None:
            reveal.disabled = new_secret_id.disabled = True
            return
        reveal.disabled = False
        reveal.label = "Hide" if role in self.revealed else "Reveal"
        status = self.role_statuses.get(role)
        # Roles with bind_secret_id=false don't use secret IDs.
        not_required = (
            isinstance(status, AppRoleStatus) and status.state is AppRoleState.NOT_REQUIRED
        )
        generating = role in self.generating
        new_secret_id.disabled = not_required or generating
        new_secret_id.label = "Creating…" if generating else "New secret ID"
        new_secret_id.tooltip = (
            "bind_secret_id is false: the role does not use secret IDs."
            if not_required
            else "Create a new secret ID for this role"
        )

    async def render_revealed(self, scroll_to: str | None = None) -> None:
        """Show a credentials panel under the table for each revealed role that matches the search."""
        async with self._revealed_lock:
            container = self.query_one("#revealed", Vertical)
            await container.remove_children()
            panels = [
                CredentialsPanel(role, self.revealed[role])
                for role in self._filtered_roles()
                if role in self.revealed
            ]
            if panels:
                await container.mount_all(panels)
            for panel in panels:
                if panel.role == scroll_to:
                    self.query_one("#detail", VerticalScroll).scroll_to_widget(panel)

    # ----------------------------------------------------------------- Vault calls

    @work(exclusive=True, group="roles")
    async def load(self) -> None:
        self._load_id += 1
        load_id = self._load_id
        table = self.query_one("#roles-table", DataTable)
        table.loading = True
        try:
            roles = await self.client.list_auth_roles(self.method)
        except httpx2.HTTPError as exc:
            table.clear()
            self._show_message(_describe_error(exc, "listing roles"), error=True)
            table.loading = False
            return
        self.roles = roles
        self.role_statuses = {role: None for role in roles} if self.is_approle else {}
        self.revealed = {}
        self.rebuild_roles_table()
        await self.render_revealed()
        table.loading = False
        if self.is_approle:
            await self.load_approle_statuses(load_id)

    async def load_approle_statuses(self, load_id: int) -> None:
        """Check whether each AppRole role has expired, refreshing the table as results arrive."""
        semaphore = asyncio.Semaphore(8)

        async def check(role: str) -> None:
            try:
                status: AppRoleStatus | Exception = await self.client.approle_role_status(
                    self.method, role, semaphore
                )
            except httpx2.HTTPError as exc:
                status = Exception(_describe_error(exc))
            if load_id != self._load_id:
                return  # A newer reload started; drop stale results.
            self.role_statuses[role] = status
            self.update_role_row(role)

        await asyncio.gather(*(check(role) for role in self.roles))

    async def toggle_reveal(self, role: str) -> None:
        """Show (fetching them) or hide the role ID and secret IDs of an AppRole role."""
        if role in self.revealed:
            del self.revealed[role]
            self.update_role_row(role)
            await self.render_revealed()
            return
        load_id = self._load_id
        self.revealed[role] = None
        self.update_role_row(role)
        await self.render_revealed(scroll_to=role)
        try:
            credentials: AppRoleCredentials | Exception = await self.client.approle_credentials(
                self.method, role
            )
        except httpx2.HTTPError as exc:
            credentials = Exception(_describe_error(exc, "reading the role credentials"))
        # Drop the result if the roles were reloaded or the role was hidden meanwhile.
        if load_id != self._load_id or role not in self.revealed:
            return
        self.revealed[role] = credentials
        await self.render_revealed()

    async def create_secret_id(self, role: str) -> None:
        """Create a secret ID for an AppRole role and show it once, so it can be copied."""
        if role in self.generating:
            return
        self.generating.add(role)
        self.update_role_row(role)
        try:
            generated = await self.client.approle_generate_secret_id(self.method, role)
        except httpx2.HTTPError as exc:
            self.notify(
                _describe_error(exc, "creating the secret ID"), severity="error", timeout=10
            )
            return
        finally:
            self.generating.discard(role)
            self.update_role_row(role)

        self.app.push_screen(NewSecretIdDialog(role, generated))
        await self.refresh_role(role)

    async def refresh_role(self, role: str) -> None:
        """Reload the status (and the credentials, if revealed) of one AppRole role."""
        load_id = self._load_id
        try:
            status: AppRoleStatus | Exception = await self.client.approle_role_status(
                self.method, role
            )
        except httpx2.HTTPError as exc:
            status = Exception(_describe_error(exc))
        if load_id != self._load_id:
            return
        self.role_statuses[role] = status
        self.update_role_row(role)
        if role in self.revealed:
            # Hide and reveal again to fetch the new secret ID list.
            del self.revealed[role]
            await self.toggle_reveal(role)


# --------------------------------------------------------------------------- new secret ID


class NewSecretIdDialog(ModalScreen[None]):
    """Shows a secret ID just created, with a copy button. It can't be shown again."""

    BINDINGS = [Binding("ctrl+y", "copy", "Copy secret ID")]

    def __init__(self, role: str, generated: GeneratedSecretId) -> None:
        super().__init__()
        self.role = role
        self.generated = generated

    def compose(self) -> ComposeResult:
        generated = self.generated
        details = [
            ("Accessor", generated.accessor or "—"),
            ("TTL", format_ttl(generated.ttl) if generated.ttl else "Never expires"),
            ("Uses", str(generated.num_uses) if generated.num_uses else "Unlimited"),
        ]
        with Vertical(id="dialog"):
            yield Label(Text(f"New secret ID for '{self.role}'", style="bold"))
            yield Static(
                "⚠ Copy this secret ID now. Vault won't show it again: "
                "once you close this dialog, you can't get it back.",
                id="dialog-warning",
            )
            yield Static(generated.secret_id, id="secret-value")
            yield Static(id="copied")
            yield Static(_properties(details))
            with Horizontal(id="dialog-actions"):
                yield Button("Copy", variant="primary", id="copy")
                yield Button("Close", id="close")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#copy", Button).focus()

    @on(Button.Pressed, "#copy")
    def action_copy(self) -> None:
        # OSC 52 works in most terminals (also over SSH); the system tool covers the rest.
        self.app.copy_to_clipboard(self.generated.secret_id)
        native = _copy_to_system_clipboard(self.generated.secret_id)
        self.query_one("#copied", Static).update(
            "Copied to the clipboard."
            if native
            else "Sent to the terminal clipboard. If it didn't work, select the value and copy it."
        )

    @on(Button.Pressed, "#close")
    def close(self) -> None:
        self.dismiss()


# --------------------------------------------------------------------------- application


class VaultToolsApp(App[None]):
    TITLE = "KVO Vault Tools"
    CSS = """
    .error { color: $error; }
    .dim { color: $text-muted; }
    .section {
        border: round $primary;
        border-title-style: bold;
        border-title-color: $accent;
        padding: 0 1;
        height: auto;
    }
    .-invalid { border: tall $error; }

    ConnectScreen { align: center middle; }
    #connect-box {
        width: 72;
        height: auto;
        border: round $primary;
        padding: 1 2;
    }
    #connect-title { text-style: bold; width: 100%; content-align: center middle; margin-bottom: 1; }
    #connect-box Input { margin-bottom: 1; }
    #connect-actions { height: auto; align: center middle; }
    #connect-progress { width: 8; height: 3; display: none; }
    #connect-status { width: 100%; content-align: center middle; margin-top: 1; }

    #auth-section { height: 1fr; }
    .filters { height: auto; }
    #auth-search, #role-search { width: 40; }
    #auth-type { width: 30; }
    #auth-message, #roles-message { display: none; padding: 0 1; }
    #auth-table { height: 1fr; }

    #roles-table { height: auto; max-height: 20; }
    #role-actions { height: auto; align: left middle; margin-top: 1; }
    #role-actions Button { margin-left: 1; }
    #selected-role { width: 1fr; height: 3; content-align: left middle; }
    #revealed { height: auto; }
    .credentials {
        border: round $secondary;
        height: auto;
        padding: 0 1;
        margin: 1 0 0 2;
    }
    .credentials DataTable { height: auto; max-height: 12; }

    NewSecretIdDialog { align: center middle; }
    #dialog {
        width: 90;
        max-width: 100%;
        height: auto;
        border: thick $warning;
        background: $surface;
        padding: 1 2;
    }
    #dialog > * { margin-bottom: 1; }
    #dialog-warning { background: $error-muted; text-style: bold; padding: 1; }
    #secret-value { background: $boost; text-style: bold; padding: 0 1; }
    #copied { color: $success; height: auto; }
    #dialog-actions { height: auto; align: right middle; margin-bottom: 0; }
    #dialog-actions Button { margin-left: 1; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.client: VaultClient | None = None

    def on_mount(self) -> None:
        self.push_screen(ConnectScreen())

    async def on_unmount(self) -> None:
        if self.client is not None:
            await self.client.aclose()


def main() -> None:
    VaultToolsApp().run()


if __name__ == "__main__":
    main()
