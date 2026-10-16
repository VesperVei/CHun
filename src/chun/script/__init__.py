"""脚本态对外入口。"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_COMPAT_EXPORTS = {"ELF", "ROP", "args", "context", "gdb", "log", "pause"}
_MODEL_EXPORTS = {"FmtTaskPolicy", "FmtWriteStrategy"}
_CONSTANT_EXPORTS = {"DEFAULT_SCRIPT_TERMINAL"}
_ENTRY_EXPORTS = {"ScriptEntry"}
_RETRY_EXPORTS = {"RetryResult"}

__all__ = [
    "DEFAULT_SCRIPT_TERMINAL",
    "ELF",
    "FmtTaskPolicy",
    "FmtWriteStrategy",
    "ROP",
    "RetryResult",
    "ScriptEntry",
    "args",
    "context",
    "gdb",
    "log",
    "pause",
]


def __getattr__(name: str) -> Any:
    if name in _COMPAT_EXPORTS:
        return getattr(import_module(".._compat", __name__), name)
    if name in _MODEL_EXPORTS:
        return getattr(import_module("..core.models", __name__), name)
    if name in _CONSTANT_EXPORTS:
        return getattr(import_module(".constants", __name__), name)
    if name in _ENTRY_EXPORTS:
        return getattr(import_module(".entry", __name__), name)
    if name in _RETRY_EXPORTS:
        return getattr(import_module(".retry", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
