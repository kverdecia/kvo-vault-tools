"""Text formatting helpers shared by the desktop (Flet) and terminal (Textual) interfaces."""

from datetime import datetime
from typing import Any


def format_ttl(value: Any) -> str:
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


def format_value(key: str, value: Any) -> str:
    if key.endswith("_ttl"):
        return format_ttl(value)
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) or "—"
    if value in (None, ""):
        return "—"
    return str(value)


def format_datetime(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M")


def optional_datetime(value: datetime | None, empty: str = "—") -> str:
    return format_datetime(value) if value else empty


def humanize(key: str) -> str:
    return key.replace("_", " ").capitalize()
