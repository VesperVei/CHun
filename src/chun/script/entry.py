"""脚本模式 ScriptEntry。"""

from __future__ import annotations

import re
import sys
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Literal, Sequence

from ..core.cache import CacheService, default_cache_dir
from ..core.errors import TransportConfigError
from ..core.models import ContextKind, RecordDomain, TargetSpec
from .constants import DEFAULT_SCRIPT_TERMINAL, HEX_POINTER_RE
from .lazy import LazyELFProxy
from .replay import ReplayScriptMixin
from .retry import RetryScriptMixin

if TYPE_CHECKING:
    from ..bridges.gdb import PwntoolsGdbBridge
    from ..core.analysis import CorefileAnalyzer
    from ..core.inference import InferenceService
    from ..core.registry import EvidenceRegistry
    from ..core.resolve import ResolveService
    from ..core.session import CHunSession
    from ..transports.pwntools_tube import PwntoolsTubeTransport
    from .fmt import _ScriptFmtFacade
    from .gadget import _ScriptGadgetFacade


_DOMAIN_ALIASES: dict[str, RecordDomain] = {
    item.value: item for item in RecordDomain
}


def _script_module() -> Any:
    return sys.modules[__package__]


def _coerce_record_domain(domain: RecordDomain | str | None) -> RecordDomain:
    if domain is None:
        return RecordDomain.LIBC
    if isinstance(domain, RecordDomain):
        return domain
    normalized = domain.strip().lower()
    if normalized in _DOMAIN_ALIASES:
        return _DOMAIN_ALIASES[normalized]
    return RecordDomain(normalized)


class ScriptEntry(ReplayScriptMixin, RetryScriptMixin):
    """为手写 exp 保留薄包装入口。"""

    def __init__(
        self,
        factory: type[Any],
        binary: str,
        *,
        host: str | None = None,
        port: int | None = None,
        libc: str | None = None,
        ld: str | None = None,
        argv: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float | None = None,
        cache: bool = True,
        cache_dir: str | None = None,
        auto_local_libc: bool = False,
        log_level: str = "debug",
        terminal: Sequence[str] = DEFAULT_SCRIPT_TERMINAL,
    ) -> None:
        self._factory = factory
        resolved_terminal = tuple(terminal) if terminal else DEFAULT_SCRIPT_TERMINAL
        self._target = self._factory._build_process_target(
            binary,
            argv=argv,
            libc=libc,
            ld=ld,
            env=env,
            cwd=cwd,
            log_level=log_level,
            terminal=resolved_terminal,
        )
        self._target.host = host
        self._target.port = port
        self.timeout = timeout
        resolved_cache_dir = cache_dir if cache_dir else str(default_cache_dir())
        self._cache = CacheService(resolved_cache_dir, enabled=cache)
        self._auto_local_libc = bool(auto_local_libc)
        self._elf: LazyELFProxy | None = None
        self._libc: LazyELFProxy | None = None
        self._libc_source: str = "unresolved"
        self._libc_trusted: bool = False
        self._libc_usable_for_remote: bool = False
        self._libc_path: str | None = None
        self._session: CHunSession | None = None
        self._initialize_script_context()

    def _initialize_script_context(self) -> None:
        context = _script_module().context
        log_level = self.target.metadata.get("log_level", "debug")
        terminal = self.target.metadata.get("terminal", list(DEFAULT_SCRIPT_TERMINAL))
        context.log_level = str(log_level)
        context.terminal = list(terminal)

        if self.target.binary is None:
            raise TransportConfigError("CHun.script(...) 需要提供 binary。")

        loader = _script_module().ELF
        self._elf = LazyELFProxy(
            self.target.binary,
            cache=self._cache,
            loader=loader,
            runtime_base_getter=self._read_elf_base,
            warning_emitter=self._emit_script_warning,
            runtime_name="elf.base",
        )

        self._set_context_binary(self._elf)

        self._prepare_libc_provider()

    @staticmethod
    def _set_context_binary(binary: Any) -> None:
        context = _script_module().context
        try:
            context.binary = binary
            return
        except Exception:
            pass

        tls = getattr(context, "_tls", None)
        if isinstance(tls, dict):
            tls["binary"] = binary
            return
        if tls is not None:
            try:
                setattr(tls, "binary", binary)
                return
            except Exception:
                pass

        object.__setattr__(context, "binary", binary)

    def _prepare_libc_provider(self) -> None:
        loader = _script_module().ELF
        explicit = self.target.libc
        if isinstance(explicit, str) and explicit:
            self._libc_path = explicit
            self._libc = LazyELFProxy(explicit, cache=self._cache, loader=loader)
            self._libc_source = "specified"
            self._libc_trusted = True
            self._libc_usable_for_remote = True
            return

        self._libc = None
        self._libc_path = None
        self._libc_source = "unresolved"
        self._libc_trusted = False
        self._libc_usable_for_remote = False

    def _try_detect_local_libc(self) -> LazyELFProxy | None:
        if not self._auto_local_libc:
            return None
        if self._libc is not None:
            return self._libc
        if self._elf is None:
            return None
        try:
            candidate = self._elf.libc
        except Exception:
            return None
        libc_path = getattr(candidate, "path", None)
        if not isinstance(libc_path, str) or not libc_path:
            return None
        loader = _script_module().ELF
        self._libc = LazyELFProxy(libc_path, cache=self._cache, loader=loader)
        self._libc_path = libc_path
        self._libc_source = "local_detected"
        self._libc_trusted = True
        self._libc_usable_for_remote = False
        self.target.libc = libc_path
        return self._libc

    def _prepare_cache_records(self) -> None:
        if self._elf is None:
            raise TransportConfigError("脚本 ELF 尚未初始化。")
        if not self._cache.enabled:
            return
        self._elf.ensure_minimal_info()
        elf_info = self._elf.ensure_minimal_info()
        self._sync_pwntools_context_from_elf_info(elf_info)

        libc = self.libc
        if libc is None or self._libc_path is None:
            return

        if self._libc_source == "unresolved":
            return

        self._cache.ensure_libc_record(
            self._libc_path,
            loader=_script_module().ELF,
            source=self._libc_source,  # type: ignore[arg-type]
            trusted=self._libc_trusted,
            usable_for_remote=self._libc_usable_for_remote,
        )
        self._cache.bind_elf_libc(
            self._elf.path,
            libc_path=self._libc_path,
            source=self._libc_source,  # type: ignore[arg-type]
        )

    def _emit_script_warning(self, message: str) -> None:
        _script_module().log.warning(message)

    def _read_elf_base(self) -> int | None:
        session = self._session
        if session is None:
            return None
        getter = getattr(session.rec, "get_fact", None)
        if not callable(getter):
            return None
        fact = getter("elf.base")
        value = getattr(fact, "value", None) if fact is not None else None
        if isinstance(value, int) and value > 0:
            return int(value)
        return None

    @staticmethod
    def _sync_pwntools_context_from_elf_info(elf_info: dict[str, Any]) -> None:
        context = _script_module().context
        bits = elf_info.get("bits")
        if isinstance(bits, int) and bits > 0:
            context.bits = int(bits)

        arch = elf_info.get("arch")
        if isinstance(arch, str) and arch:
            context.arch = arch

        endian = elf_info.get("endian")
        if isinstance(endian, str) and endian in {"little", "big"}:
            context.endian = endian

    def _target_for_mode(self) -> TargetSpec:
        args = _script_module().args
        if args.REMOTE:
            if self.target.host is None or self.target.port is None:
                raise TransportConfigError(
                    "REMOTE 模式需要在 CHun.script(...) 中提供 host 和 port。"
                )
            return self._factory._build_remote_target(
                self.target.host,
                self.target.port,
                binary=self.target.binary,
                libc=self.target.libc,
                log_level=(
                    str(self.target.metadata.get("log_level", "debug"))
                    if args.GDB
                    else "info"
                ),
                terminal=list(
                    self.target.metadata.get("terminal", list(DEFAULT_SCRIPT_TERMINAL))
                ),
            )
        return replace(self.target, kind="process")

    def _build_session(self) -> "CHunSession":
        target = self._target_for_mode()

        transport = self._factory._build_pwntools_tube_transport(timeout=self.timeout)

        session = self._factory.from_specs(target, transport)
        return session

    def start(self) -> "ScriptEntry":
        """启动并缓存当前脚本对应的 `CHunSession`，并返回脚本入口自身。"""
        if self._session is None:
            self._session = self._build_session()

            self._prepare_cache_records()

            self._session.bind_binaries(elf=self.elf, libc_elf=self.libc)
            self._bind_cache_contexts(self._session)
            if hasattr(self._session.resolve, "configure_libc_cache"):
                self._session.resolve.configure_libc_cache(
                    cache_service=self._cache,
                    libc_path=self._libc_path,
                    source=self._libc_source,
                    trusted=self._libc_trusted,
                    usable_for_remote=self._libc_usable_for_remote,
                )
        return self

    def _bind_cache_contexts(self, session: "CHunSession") -> None:
        setter = getattr(session.rec, "set_context", None)
        if not callable(setter):
            return
        setter(
            "libc.source",
            self._libc_source,
            kind=ContextKind.LIBC,
            domain=RecordDomain.LIBC,
            source="script.start",
        )
        setter(
            "libc.trusted_source",
            bool(self._libc_trusted),
            kind=ContextKind.LIBC,
            domain=RecordDomain.LIBC,
            source="script.start",
        )
        setter(
            "libc.usable_for_remote",
            bool(self._libc_usable_for_remote),
            kind=ContextKind.LIBC,
            domain=RecordDomain.LIBC,
            source="script.start",
        )

    def gdb(self, script: str = "") -> object | None:
        """在 `GDB` 模式下对本地 process session 执行 attach。"""
        script_mod = _script_module()
        if not script_mod.args.GDB:
            return None

        self.start()
        session = self.session
        if session.target.kind != "process":
            script_mod.log.warning("当前为 REMOTE 模式，跳过 GDB attach。")
            return None
        return session.dbg.attach(script=script)

    def debug(self, script: str = "") -> "ScriptEntry":
        """在 `GDB` 下启动本地 process，并将 tube 接入当前脚本入口。"""
        script_mod = _script_module()
        if not script_mod.args.GDB:
            return self.start()

        self.start()
        session = self.session
        if session.target.kind != "process":
            raise TransportConfigError("ScriptEntry.debug() 仅支持本地 process 目标。")
        from ..transports.pwntools_tube import PwntoolsTubeTransport

        if not isinstance(session.transport, PwntoolsTubeTransport):
            raise TransportConfigError(
                "ScriptEntry.debug() 仅支持 pwntools-tube transport。"
            )
        if session.transport.is_open:
            session.close()

        argv = list(session.target.argv)
        if not argv:
            if session.target.binary is None:
                raise TransportConfigError("process 模式至少需要 binary 或 argv。")
            argv = [session.target.binary]

        debug_tube = script_mod.gdb.debug(
            argv,
            gdbscript=script or None,
            exe=session.target.binary,
            env=session.target.env or None,
            api=True,
            cwd=session.target.cwd,
        )
        session.transport.adopt_tube(debug_tube)
        session.dbg.bind_runtime(controller=getattr(debug_tube, "gdb", None))
        if hasattr(session, "_sync_transport_context"):
            session._sync_transport_context()
        return self

    @property
    def session(self) -> "CHunSession":
        """返回当前已启动的 session，用于访问完整框架能力。"""
        if self._session is None:
            raise RuntimeError("ScriptEntry 尚未启动，请先调用 start()。")
        return self._session

    @property
    def io(self) -> Any:
        """返回当前 session 的 `io` 入口，适合直接做 tube 交互。"""
        return self.session.io

    @property
    def target(self) -> TargetSpec:
        """返回脚本入口缓存的 `TargetSpec` 配置。"""
        return self._target

    @property
    def elf(self) -> Any:
        """返回脚本主程序 lazy ELF 代理。"""
        return self._elf

    @property
    def libc(self) -> Any:
        """返回当前脚本绑定的 libc lazy ELF 代理。"""
        if self._libc is not None:
            return self._libc
        if self._auto_local_libc:
            return self._try_detect_local_libc()
        return self._libc

    @property
    def libc_base(self) -> int:
        """返回当前 session 中已确认的 libc base。"""
        return self.session.libc_base

    @property
    def elf_base(self) -> int:
        """返回当前 session 中已确认的 PIE base。"""
        try:
            return self.session.rec.require_int_fact("elf.base")
        except KeyError as exc:
            raise RuntimeError("elf.base 尚未推导，请先记录符号泄漏并推导 PIE base。") from exc
        except TypeError as exc:
            raise RuntimeError("elf.base 已存在，但其值不是整数。") from exc

    @property
    def libc_version(self) -> str:
        """返回当前 session 中已确认的 libc 版本名。"""
        return self.session.libc_version

    @property
    def rec(self) -> EvidenceRegistry:
        """访问 session 的事实记录入口，常用于记录 leak 和 context。"""
        return self.session.rec

    @property
    def infer(self) -> InferenceService:
        """访问 session 的最小 inference 服务。"""
        return self.session.infer

    @property
    def resolve(self) -> ResolveService:
        """访问 session 的解析服务，用于符号、DynELF 等推导。"""
        return self.session.resolve

    @property
    def dbg(self) -> PwntoolsGdbBridge:
        """访问 session 的交互式 GDB bridge。"""
        return self.session.dbg

    @property
    def crash(self) -> "CorefileAnalyzer":
        """访问 session 的 core dump / crash 分析入口。"""
        return self.session.crash

    @property
    def fmt(self) -> _ScriptFmtFacade:
        """访问 session 的 fmt 服务。"""
        from .fmt import _ScriptFmtFacade

        return _ScriptFmtFacade(self.session.fmt)

    @property
    def gadget(self) -> _ScriptGadgetFacade:
        """访问脚本态 gadget 语法糖，支持 `s.gadget[\"rdi\"]`。"""
        from .gadget import _ScriptGadgetFacade

        return _ScriptGadgetFacade(self)

    def checkpoint(
        self, name: str, *, metadata: dict[str, object] | None = None
    ) -> object:
        """在 replay trace 中打一个手工检查点。"""
        return self.session.checkpoint(name, metadata=metadata or {})

    def send(self, data: bytes) -> None:
        """转发到当前 `io.send()`。"""
        self.io.send(data)

    def sendline(self, data: bytes) -> None:
        """转发到当前 `io.sendline()`。"""
        self.io.sendline(data)

    def sendafter(self, delim: bytes, data: bytes) -> None:
        """转发到当前 `io.sendafter()`。"""
        self.io.sendafter(delim, data)

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        """转发到当前 `io.sendlineafter()`。"""
        self.io.sendlineafter(delim, data)

    def recv(self, n: int = 4096) -> bytes:
        """转发到当前 `io.recv()`。"""
        return self.io.recv(n)

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        """转发到当前 `io.recvuntil()`。"""
        return self.io.recvuntil(delim, drop=drop)

    def recvline(self, keepends: bool = True) -> bytes:
        """转发到当前 `io.recvline()`。"""
        return self.io.recvline(keepends=keepends)

    @staticmethod
    def _coerce_delim_or_regex(value: bytes | str, *, field_name: str) -> bytes | str:
        if isinstance(value, (bytes, str)):
            return value
        raise ValueError(f"{field_name} 必须是 bytes 或 str。")

    @staticmethod
    def _extract_regex_capture(match: object) -> bytes:
        if isinstance(match, bytes):
            return match
        if isinstance(match, str):
            return match.encode()
        if hasattr(match, "group"):
            groups = match.groups()  # type: ignore[attr-defined]
            if groups:
                group = groups[0]
            else:
                group = match.group(0)  # type: ignore[attr-defined]
            if isinstance(group, bytes):
                return group
            if isinstance(group, str):
                return group.encode()
            raise ValueError("regex capture 必须是 bytes 或 str。")
        if isinstance(match, (tuple, list)) and match:
            group = match[0]
            if isinstance(group, bytes):
                return group
            if isinstance(group, str):
                return group.encode()
        raise ValueError("recvregex(capture=True) 未返回可用的捕获组。")

    @staticmethod
    def _search_regex_capture(payload: bytes, regex: bytes | str) -> bytes:
        if isinstance(regex, bytes):
            match = re.search(regex, payload)
        else:
            match = re.search(regex, payload.decode("latin-1"))
        if match is None:
            raise ValueError("主动 recv 后未匹配到 regex 指定的泄漏。")
        return ScriptEntry._extract_regex_capture(match)

    @staticmethod
    def _find_regex_captures(payload: bytes, regex: bytes | str) -> list[bytes]:
        matches = (
            list(re.finditer(regex, payload))
            if isinstance(regex, bytes)
            else list(re.finditer(regex, payload.decode("latin-1")))
        )
        if not matches:
            raise ValueError("主动 recv 后未匹配到 regex 指定的泄漏。")
        return [ScriptEntry._extract_regex_capture(match) for match in matches]

    def _drain_recv_buffer(self) -> bytes:
        cleaner = getattr(self.io, "clean", None)
        if not callable(cleaner):
            return b""
        try:
            drained = cleaner(timeout=0)
        except TypeError:
            drained = cleaner()
        if isinstance(drained, bytes):
            return drained
        if isinstance(drained, str):
            return drained.encode()
        return b""

    def _unrecv(self, data: bytes) -> None:
        if not data:
            return
        unread = getattr(self.io, "unrecv", None)
        if callable(unread):
            unread(data)

    def _buffer_has_pending_data(self, *, timeout: float = 0) -> bool:
        checker = getattr(self.io, "can_recv", None)
        if not callable(checker):
            return False
        try:
            return bool(checker(timeout=timeout))
        except TypeError:
            return bool(checker())

    def _recv_current_burst(self, *, chunk_size: int = 4096, idle_timeout: float = 0.05) -> bytes:
        payload = self.recv(chunk_size)
        if not payload:
            return payload
        chunks = [payload]
        while self._buffer_has_pending_data(timeout=idle_timeout):
            chunk = self.recv(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks) + self._drain_recv_buffer()

    def _recv_hex_tokens(self, *, index: int) -> bytes:
        tokens: list[bytes] = []
        current = bytearray()
        started = False
        saw_prefix = False

        while len(tokens) <= index:
            chunk = self.recv(1)
            if not chunk:
                if current:
                    tokens.append(bytes(current))
                break
            for offset, byte in enumerate(chunk):
                ch = bytes((byte,))
                if not started:
                    if not saw_prefix:
                        saw_prefix = ch == b"0"
                        continue
                    if ch in {b"x", b"X"}:
                        current = bytearray(b"0x")
                        started = True
                        saw_prefix = False
                        continue
                    saw_prefix = ch == b"0"
                    continue

                if ch in b"0123456789abcdefABCDEF":
                    current.extend(ch)
                    if not self._buffer_has_pending_data():
                        tokens.append(bytes(current))
                        return b" ".join(tokens)
                    continue

                tokens.append(bytes(current))
                current.clear()
                started = False
                saw_prefix = ch == b"0"
                if len(tokens) > index:
                    remaining = chunk[offset:]
                    self._unrecv(remaining)
                    return b" ".join(tokens)
                break

        return b" ".join(tokens)

    def recv_leak(
        self,
        name: str,
        delim: bytes | str | None = None,
        *,
        delim_end: bytes | str | None = None,
        regex: bytes | str | None = None,
        domain: RecordDomain | str | None = None,
        offset: int = 0,
        source: str = "leak",
        mode: Literal["raw", "hex"] = "raw",
        index: int = 0,
        size: int | None = None,
        recv: bool = False,
        strip_newline: bool = True,
    ) -> int:
        """接收一个泄漏值，完成解析、修正并自动写入 registry。"""
        log = _script_module().log
        if delim is not None and regex is not None:
            raise ValueError("delim 和 regex 不能同时提供。")
        if delim_end is not None and regex is not None:
            raise ValueError("delim_end 和 regex 不能同时提供。")
        if mode not in {"raw", "hex"}:
            raise ValueError("mode 必须是 'raw' 或 'hex'。")
        if mode == "raw" and delim_end is not None:
            raise ValueError("mode='raw' 时不支持 delim_end。")
        if regex is not None and not recv and index != 0:
            raise ValueError("recv=False 且提供 regex 时，index 仅支持 0；如需多命中选择，请设置 recv=True。")

        resolved_domain = _coerce_record_domain(domain)
        payload: bytes

        if delim is not None:
            resolved_delim = self._coerce_delim_or_regex(delim, field_name="delim")
            self.recvuntil(resolved_delim)
        if mode == "raw":
            default_size = 4 if int(getattr(self.elf, "bits", 64)) <= 32 else 6
            payload = self.recv(size or default_size)
            if strip_newline:
                payload = payload.rstrip(b"\r\n")
        else:
            compiled = (
                self._coerce_delim_or_regex(regex, field_name="regex")
                if regex is not None
                else None
            )
            used_regex = compiled is not None
            if delim_end is not None:
                resolved_delim_end = self._coerce_delim_or_regex(
                    delim_end, field_name="delim_end"
                )
                payload = self.recvuntil(resolved_delim_end, drop=True)
            elif compiled is not None and not recv:
                matched = self.recvregex(compiled, capture=True)
                payload = self._extract_regex_capture(matched)
            elif recv:
                payload = self._recv_current_burst()
                if strip_newline:
                    payload = payload.strip()
                if compiled is not None:
                    captures = self._find_regex_captures(payload, compiled)
                    payload = b" ".join(captures) if mode == "hex" else captures[index]
            else:
                payload = self._recv_hex_tokens(index=index)

        if mode == "raw":
            pointer_width = int(getattr(self.elf, "bytes", 8))
            leak_bytes = payload[:pointer_width]
            leak_val = int.from_bytes(
                leak_bytes.ljust(pointer_width, b"\x00"), "little"
            )
        else:
            matches = HEX_POINTER_RE.findall(payload)
            if not matches:
                if used_regex:
                    raise ValueError(
                        "regex 已命中，但其整体匹配或第一个捕获组未产出完整的 0x... 十六进制地址；"
                        "请让 regex 整体匹配完整地址，或让第一个捕获组返回完整地址。"
                    )
                raise ValueError(
                    "未读取到可解析的十六进制泄漏。mode='hex' 默认按流式 0x token 解析；"
                    "若需要自定义边界，请显式传 delim_end=... / regex=...，或设置 recv=True。"
                )
            try:
                selected = matches[index]
            except IndexError as exc:
                tokens = ",".join(token.decode() for token in matches)
                raise ValueError(
                    f"共匹配到 {len(matches)} 个地址：{tokens}，index={index} 越界。"
                ) from exc
            if len(matches) > 1:
                tokens = ",".join(token.decode() for token in matches)
                log.warning(
                    f"共匹配到 {len(matches)} 个地址：{tokens}|默认选 {selected.decode()}"
                )
            leak_val = int(selected, 16)

        actual_val = leak_val - offset
        self.rec.record_symbol_leak(
            name,
            actual_val,
            domain=resolved_domain,
            source=source,
        )
        log.success(f"Leak [{name}] captured: {hex(actual_val)}")
        return actual_val

    def interactive(self) -> None:
        """转发到当前 `io.interactive()`。"""
        self.io.interactive()

    def sl(self, data: bytes) -> None:
        """`sendline()` 的快捷别名。"""
        self.sendline(data)

    def sa(self, delim: bytes, data: bytes) -> None:
        """`sendafter()` 的快捷别名。"""
        self.sendafter(delim, data)

    def sla(self, delim: bytes, data: bytes) -> None:
        """`sendlineafter()` 的快捷别名。"""
        self.sendlineafter(delim, data)

    def ru(self, delim: bytes, drop: bool = False) -> bytes:
        """`recvuntil()` 的快捷别名。"""
        return self.recvuntil(delim, drop=drop)

    def rl(self, keepends: bool = True) -> bytes:
        """`recvline()` 的快捷别名。"""
        return self.recvline(keepends=keepends)

    def ia(self) -> None:
        """`interactive()` 的快捷别名。"""
        self.interactive()

    def __enter__(self) -> "ScriptEntry":
        self.start()
        self.session.open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.session.close()

    def __getattr__(self, name: str) -> Any:
        """将未显式声明的低频方法兜底转发到当前 `io`。"""
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.io, name)
