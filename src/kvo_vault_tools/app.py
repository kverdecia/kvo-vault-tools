import flet as ft

from kvo_vault_tools.vault import VaultConnectionError, connect


async def main(page: ft.Page) -> None:
    page.title = "KVO Vault Tools"
    page.window.width = 480
    page.window.height = 420
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    url_field = ft.TextField(
        label="Vault server URL",
        hint_text="https://vault.example.com:8200",
        autofocus=True,
        width=400,
    )
    token_field = ft.TextField(
        label="Root token",
        password=True,
        can_reveal_password=True,
        width=400,
    )
    status = ft.Text()
    progress = ft.ProgressRing(width=20, height=20, visible=False)

    async def on_connect(_: ft.Event) -> None:
        url = (url_field.value or "").strip()
        token = (token_field.value or "").strip()

        url_field.error = None if url else "The URL is required"
        token_field.error = None if token else "The token is required"
        if not url or not token:
            page.update()
            return

        connect_button.disabled = True
        progress.visible = True
        status.value = "Connecting..."
        status.color = None
        page.update()

        try:
            page.session.store.set("vault_client", await connect(url, token))
        except VaultConnectionError as exc:
            status.value = str(exc)
            status.color = ft.Colors.ERROR
        else:
            status.value = f"Connected to {url}"
            status.color = ft.Colors.GREEN
        finally:
            connect_button.disabled = False
            progress.visible = False
            page.update()

    connect_button = ft.FilledButton("Connect", on_click=on_connect)
    async def focus_token(_: ft.Event) -> None:
        await token_field.focus()

    url_field.on_submit = focus_token
    token_field.on_submit = on_connect

    page.add(
        ft.Column(
            [
                ft.Text("Connect to HashiCorp Vault", size=20, weight=ft.FontWeight.BOLD),
                url_field,
                token_field,
                ft.Row([connect_button, progress], alignment=ft.MainAxisAlignment.CENTER),
                status,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=16,
        )
    )


def run() -> None:
    ft.run(main)
