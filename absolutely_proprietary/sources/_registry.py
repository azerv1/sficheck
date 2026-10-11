"""Read-only Windows registry access. Off Windows, or when a key is missing or denied, results are empty."""

from __future__ import annotations

import sys
from typing import Any

# winreg's KEY_WOW64_* flags, kept here so callers needn't import winreg.
WOW64_64, WOW64_32 = 0x0100, 0x0200
_HIVES = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER"}


def _open(key: str, hive: str, view: int) -> Any:
    assert sys.platform == "win32"
    import winreg

    return winreg.OpenKey(getattr(winreg, _HIVES[hive]), key, 0, winreg.KEY_READ | view)


def subkeys(key: str, hive: str = "HKLM", view: int = 0) -> list[str]:
    if sys.platform != "win32":
        return []
    import winreg

    try:
        with _open(key, hive, view) as handle:
            return [winreg.EnumKey(handle, i) for i in range(winreg.QueryInfoKey(handle)[0])]
    except OSError:
        return []


def values(key: str, hive: str = "HKLM", view: int = 0) -> dict[str, object]:
    if sys.platform != "win32":
        return {}
    import winreg

    try:
        with _open(key, hive, view) as handle:
            return {
                name: data
                for name, data, _ in (winreg.EnumValue(handle, i) for i in range(winreg.QueryInfoKey(handle)[1]))
            }
    except OSError:
        return {}


def value(key: str, name: str, hive: str = "HKLM") -> str:
    return str(values(key, hive).get(name, ""))
