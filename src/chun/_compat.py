"""pwntools 兼容层。

对外继续保留统一入口：

- 轻对象：`args` / `context` / `log` / `gdb`
- 重对象：`ELF` / `ROP` / `DynELF` / `MemLeak` / `Corefile` / `process` / `remote` / `ssh`

与旧实现不同的是，这里不再在模块导入阶段直接 `import pwn`。
真正的 pwntools 依赖会在首次访问对应对象时再加载。
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from importlib import import_module
from typing import Any, Iterator

LOGGER = logging.getLogger("chun")


def _runtime_error(name: str) -> RuntimeError:
    """构造统一的运行期错误信息。"""
    return RuntimeError(f"使用 '{name}' 需要 pwntools，请先安装：pip install pwntools")


def _load_pwn_attr(name: str) -> Any:
    try:
        module = import_module("pwn")
    except Exception as exc:  # pragma: no cover - 仅在缺依赖环境触发
        raise _runtime_error(name) from exc
    return getattr(module, name)


def _load_pwn_context() -> Any:
    return _load_pwn_attr("context")


class _ArgsProxy:
    """惰性代理 pwntools `args`。"""

    def __init__(self) -> None:
        object.__setattr__(self, "_values", {"REMOTE": False, "GDB": False})

    def __getattribute__(self, name: str) -> Any:
        if name in {"_values", "__dict__", "__class__"}:
            return object.__getattribute__(self, name)
        values = object.__getattribute__(self, "_values")
        if name in values:
            try:
                target = _load_pwn_attr("args")
            except RuntimeError:
                return values[name]
            try:
                return getattr(target, name)
            except AttributeError:
                return values[name]
        return object.__getattribute__(self, name)

    def __setattr__(self, name: str, value: object) -> None:
        values = object.__getattribute__(self, "_values")
        if name in values:
            values[name] = value
            try:
                target = _load_pwn_attr("args")
            except RuntimeError:
                return
            setattr(target, name, value)
            return
        object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        try:
            target = _load_pwn_attr("args")
        except RuntimeError:
            raise AttributeError(name) from None
        return getattr(target, name)


class _ContextLocal:
    """兼容 `with context.local(...):` 的轻量上下文。"""

    def __init__(self, proxy: "_ContextProxy", **updates: object) -> None:
        self._proxy = proxy
        self._updates = updates
        self._stack: list[tuple[str, object]] = []
        self._real_context_manager: object | None = None

    def __enter__(self) -> object:
        try:
            real_context = _load_pwn_context()
        except RuntimeError:
            for key, value in self._updates.items():
                self._stack.append((key, self._proxy._values.get(key)))
                self._proxy._values[key] = value
            return self._proxy
        manager = real_context.local(**self._updates)
        self._real_context_manager = manager
        return manager.__enter__()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> object:
        if self._real_context_manager is not None:
            manager = self._real_context_manager
            return manager.__exit__(exc_type, exc, tb)  # type: ignore[attr-defined]
        for key, value in reversed(self._stack):
            self._proxy._values[key] = value
        return False


class _ContextProxy:
    """惰性代理 pwntools `context`，并保留最小 fallback 状态。"""

    def __init__(self) -> None:
        object.__setattr__(
            self,
            "_values",
            {
                "binary": None,
                "log_level": "info",
                "terminal": ["tmux", "splitw", "-h", "-d"],
                "bits": None,
                "arch": None,
                "endian": None,
            },
        )
        values = object.__getattribute__(self, "_values")
        for key, value in values.items():
            object.__setattr__(self, key, value)

    def __getattribute__(self, name: str) -> Any:
        if name in {"_values", "local", "__dict__", "__class__"}:
            return object.__getattribute__(self, name)
        values = object.__getattribute__(self, "_values")
        if name in values:
            try:
                real_context = _load_pwn_context()
            except RuntimeError:
                return values[name]
            try:
                resolved = getattr(real_context, name)
            except Exception:
                return values[name]
            if resolved is None and values[name] is not None:
                return values[name]
            return resolved
        return object.__getattribute__(self, name)

    def __setattr__(self, name: str, value: object) -> None:
        values = object.__getattribute__(self, "_values")
        if name in values:
            values[name] = value
            object.__setattr__(self, name, value)
            try:
                real_context = _load_pwn_context()
            except RuntimeError:
                return
            setattr(real_context, name, value)
            return
        object.__setattr__(self, name, value)

    @contextmanager
    def local(self, **updates: object) -> Iterator[object]:
        manager = _ContextLocal(self, **updates)
        entered = manager.__enter__()
        try:
            yield entered
        finally:
            manager.__exit__(None, None, None)


class _FallbackLog:
    """简单日志适配器，接口尽量贴合 pwntools 的 `log`。"""

    def info(self, message: str) -> None:
        LOGGER.info(message)

    def warning(self, message: str) -> None:
        LOGGER.warning(message)

    def warn(self, message: str) -> None:
        LOGGER.warning(message)

    def error(self, message: str) -> None:
        LOGGER.error(message)

    def failure(self, message: str) -> None:
        LOGGER.error(message)

    def debug(self, message: str) -> None:
        LOGGER.debug(message)

    def success(self, message: str) -> None:
        LOGGER.info("[成功] %s", message)


class _LogProxy:
    """优先透传 pwntools `log`，缺失时退回标准 logging。"""

    def __init__(self) -> None:
        object.__setattr__(self, "_fallback", _FallbackLog())

    def __getattr__(self, name: str) -> Any:
        try:
            target = _load_pwn_attr("log")
        except RuntimeError:
            target = object.__getattribute__(self, "_fallback")
        return getattr(target, name)


class _GdbProxy:
    """惰性代理 pwntools `gdb`。"""

    def attach(self, *args: Any, **kwargs: Any) -> Any:
        return _load_pwn_attr("gdb").attach(*args, **kwargs)

    def debug(self, *args: Any, **kwargs: Any) -> Any:
        return _load_pwn_attr("gdb").debug(*args, **kwargs)


args = _ArgsProxy()
context = _ContextProxy()
gdb = _GdbProxy()
log = _LogProxy()


def pause(*args: Any, **kwargs: Any) -> Any:
    return _load_pwn_attr("pause")(*args, **kwargs)


def process(*args: Any, **kwargs: Any) -> Any:
    return _load_pwn_attr("process")(*args, **kwargs)


def remote(*args: Any, **kwargs: Any) -> Any:
    return _load_pwn_attr("remote")(*args, **kwargs)


def ssh(*args: Any, **kwargs: Any) -> Any:
    return _load_pwn_attr("ssh")(*args, **kwargs)


def cyclic_find(*args: Any, **kwargs: Any) -> Any:
    return _load_pwn_attr("cyclic_find")(*args, **kwargs)


_LAZY_EXPORTS = {
    "Corefile",
    "DynELF",
    "ELF",
    "MemLeak",
    "ROP",
}

__all__ = [
    "Corefile",
    "DynELF",
    "ELF",
    "MemLeak",
    "ROP",
    "args",
    "context",
    "cyclic_find",
    "gdb",
    "log",
    "pause",
    "process",
    "remote",
    "ssh",
]


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        return _load_pwn_attr(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
