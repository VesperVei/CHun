"""CHun 顶层会话对象。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from ..transports.base import BaseTransport
from .catalog import LibcCatalogService
from .inference import InferenceService
from .models import ContextKind, RecordDomain, TargetSpec, TransportSpec
from .replay import ReplayEventKind
from .registry import EvidenceRegistry
from .resolve import ResolveService

if TYPE_CHECKING:
    from .analysis import CorefileAnalyzer
    from ..bridges.gdb import GdbMiBridge, PwntoolsGdbBridge
    from ..plugins.fmt import FmtService


@dataclass(slots=True)
class CHunSession:
    """当前阶段稳定的会话对象。

    当前阶段把 transport、registry、inference 与 bridge 一并挂回 session：
    - `target`：目标描述
    - `transport_spec`：transport 配置
    - `transport`：实际 transport 实例
    - `elf` / `libc_elf`：当前运行时绑定的二进制对象
    - `registry` / `rec`：统一事实层入口
    - `infer`：最小 inference 服务
    - `dbg` / `gdb_mi`：调试桥接入口
    - `resolve`：pwntools / DynELF 解析入口
    - `crash`：core dump 分析入口
    """

    target: TargetSpec
    transport_spec: TransportSpec
    transport: BaseTransport
    registry: EvidenceRegistry = field(default_factory=EvidenceRegistry)
    libc_catalog: LibcCatalogService = field(default_factory=LibcCatalogService)
    elf: object | None = field(default=None, init=False, repr=False)
    libc_elf: object | None = field(default=None, init=False, repr=False)
    infer: InferenceService = field(init=False)
    _dbg: "PwntoolsGdbBridge | None" = field(default=None, init=False, repr=False)
    _gdb_mi: "GdbMiBridge | None" = field(default=None, init=False, repr=False)
    resolve: ResolveService = field(init=False)
    _crash: "CorefileAnalyzer | None" = field(default=None, init=False, repr=False)
    _fmt: "FmtService | None" = field(default=None, init=False, repr=False)
    replay_session_factory: Callable[[], "CHunSession"] | None = field(
        default=None,
        repr=False,
    )
    replay_silent: bool = True

    def __post_init__(self) -> None:
        self.infer = InferenceService(
            self.registry, libc_catalog=self.libc_catalog, session=self
        )
        self.resolve = ResolveService(
            self.registry,
            self.infer,
            catalog_service=self.libc_catalog,
            session=self,
        )
        self._seed_context()
        self._bind_replay_hook()

    def _seed_context(self) -> None:
        self.registry.set_context(
            "session.target",
            self.target,
            kind=ContextKind.TARGET,
            domain=RecordDomain.TARGET,
        )
        self.registry.set_context(
            "session.target.kind",
            self.target.kind,
            kind=ContextKind.TARGET,
            domain=RecordDomain.TARGET,
        )
        self.registry.set_context(
            "session.transport",
            self.transport_spec,
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )
        self.registry.set_context(
            "session.transport.kind",
            self.transport_spec.kind,
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )
        self.registry.set_context(
            "session.transport.is_open",
            bool(getattr(self.transport, "is_open", False)),
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )

    def _sync_transport_context(self) -> None:
        self.registry.set_context(
            "session.transport.is_open",
            bool(getattr(self.transport, "is_open", False)),
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )
        raw = getattr(self.transport, "raw", None)
        if raw is not None:
            self.registry.set_context(
                "session.transport.raw_type",
                type(raw).__name__,
                kind=ContextKind.TRANSPORT,
                domain=RecordDomain.TRANSPORT,
            )

    def bind_binaries(
        self,
        *,
        elf: object | None = None,
        libc_elf: object | None = None,
        source: str = "session",
    ) -> None:
        """绑定当前会话使用的 ELF / libc ELF 富对象，并同步标量上下文。"""
        if elf is not None:
            self.elf = elf
        if libc_elf is not None:
            self.libc_elf = libc_elf

        if self.elf is not None:
            self._sync_binary_context(
                prefix="binary",
                binary=self.elf,
                kind=ContextKind.TARGET,
                domain=RecordDomain.ELF,
                source=source,
            )
            self._sync_binary_protection_context(
                binary=self.elf,
                kind=ContextKind.TARGET,
                domain=RecordDomain.ELF,
                source=source,
            )
            self._sync_arch_context(self.elf, source=source)

        if self.libc_elf is not None:
            self._sync_binary_context(
                prefix="libc",
                binary=self.libc_elf,
                kind=ContextKind.LIBC,
                domain=RecordDomain.LIBC,
                source=source,
            )

    def open(self) -> "CHunSession":
        """显式打开 transport。"""
        self.transport.open()
        self._sync_transport_context()
        return self

    def close(self) -> None:
        """关闭 transport。"""
        self.transport.close()
        self._sync_transport_context()

    def reconnect(self) -> None:
        """重建 transport。"""
        self.transport.reconnect()
        self._sync_transport_context()

    def checkpoint(self, name: str, *, metadata: dict[str, object] | None = None) -> object:
        """在 replay trace 中打一个手工检查点。"""
        return self.rec.checkpoint(name, metadata=metadata or {})

    def make_replay_session(self) -> "CHunSession":
        """构造用于 replay 验证的独立 session。"""
        if self.replay_session_factory is not None:
            return self.replay_session_factory()
        target = deepcopy(self.target)
        spec = deepcopy(self.transport_spec)
        if self.replay_silent:
            target.metadata = dict(target.metadata)
            target.metadata["log_level"] = "error"
        replay_session = CHunSession(
            target=target,
            transport_spec=spec,
            transport=self._build_transport(target, spec),
        )
        replay_session.bind_binaries(
            elf=self.elf,
            libc_elf=self.libc_elf,
            source="replay.clone",
        )
        return replay_session

    @property
    def rec(self) -> EvidenceRegistry:
        """`registry` 的语义化短别名。"""
        return self.registry

    @property
    def dbg(self) -> "PwntoolsGdbBridge":
        controller = self._dbg
        if controller is None:
            from ..bridges.gdb import PwntoolsGdbBridge

            controller = PwntoolsGdbBridge(self.registry, self.target, lambda: self.raw)
            self._dbg = controller
        return controller

    @dbg.setter
    def dbg(self, controller: "PwntoolsGdbBridge | None") -> None:
        self._dbg = controller

    @property
    def gdb_mi(self) -> "GdbMiBridge":
        bridge = self._gdb_mi
        if bridge is None:
            from ..bridges.gdb import GdbMiBridge

            bridge = GdbMiBridge(self.registry, self.target)
            self._gdb_mi = bridge
        return bridge

    @gdb_mi.setter
    def gdb_mi(self, bridge: "GdbMiBridge | None") -> None:
        self._gdb_mi = bridge

    @property
    def fmt(self) -> "FmtService":
        service = self._fmt
        if service is None:
            from ..plugins.fmt.service import FmtService

            service = FmtService(self)
            self._fmt = service
        return service

    @fmt.setter
    def fmt(self, service: "FmtService | None") -> None:
        self._fmt = service

    @property
    def crash(self) -> "CorefileAnalyzer":
        analyzer = self._crash
        if analyzer is None:
            from .analysis import CorefileAnalyzer

            analyzer = CorefileAnalyzer(self.registry)
            self._crash = analyzer
        return analyzer

    @crash.setter
    def crash(self, analyzer: "CorefileAnalyzer | None") -> None:
        self._crash = analyzer

    @property
    def io(self) -> BaseTransport:
        """提供统一 runtime 入口，并在首次访问时延迟打开 transport。"""
        if not self.transport.is_open:
            self.transport.open()
            self._sync_transport_context()
        return self.transport

    @property
    def raw(self) -> Any:
        """返回底层 transport 的原始对象。"""
        return self.io.raw

    @property
    def libc_base(self) -> int:
        """返回当前 session 中已确认的 libc base。"""
        try:
            return self.registry.require_int_fact("libc.base")
        except KeyError as exc:
            raise RuntimeError(
                "libc.base 尚未推导，可能是多候选情况，请明确指定或编写爆破逻辑。"
            ) from exc
        except TypeError as exc:
            raise RuntimeError("libc.base 已存在，但其值不是整数。") from exc

    @libc_base.setter
    def libc_base(self, value: int) -> None:
        """手工确认 libc base，等价于 `infer.set_libc_base(value)`。"""
        self.infer.set_libc_base(value)

    @property
    def libc_version(self) -> str:
        """返回当前 session 中已确认的 libc 版本名。"""
        try:
            return self.registry.require_str_fact("libc.version")
        except KeyError as exc:
            raise RuntimeError("libc.version 尚未确认。") from exc
        except TypeError as exc:
            raise RuntimeError("libc.version 已存在，但其值不是字符串。") from exc

    def __enter__(self) -> "CHunSession":
        return self.open()

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def _sync_binary_context(
        self,
        *,
        prefix: str,
        binary: object,
        kind: ContextKind,
        domain: RecordDomain,
        source: str,
    ) -> None:
        path = getattr(binary, "path", None)
        if isinstance(path, str) and path:
            self.registry.set_context(
                f"{prefix}.path",
                path,
                kind=kind,
                domain=domain,
                source=source,
            )

        arch_name = getattr(binary, "arch", None)
        if arch_name:
            self.registry.set_context(
                f"{prefix}.arch",
                str(arch_name),
                kind=kind,
                domain=domain,
                source=source,
            )

        bits = getattr(binary, "bits", None)
        if bits is not None:
            self.registry.set_context(
                f"{prefix}.bits",
                int(bits),
                kind=kind,
                domain=domain,
                source=source,
            )

    def _sync_arch_context(self, binary: object, *, source: str) -> None:
        bits = getattr(binary, "bits", None)
        if bits is not None:
            bits_value = int(bits)
            self.registry.set_context(
                "arch.bits",
                bits_value,
                kind=ContextKind.ENVIRONMENT,
                domain=RecordDomain.ELF,
                source=source,
            )
            self.registry.set_context(
                "arch.pointer_size",
                bits_value // 8,
                kind=ContextKind.ENVIRONMENT,
                domain=RecordDomain.ELF,
                source=source,
            )

        endian = self._binary_endian(binary)
        if endian is not None:
            self.registry.set_context(
                "arch.endian",
                endian,
                kind=ContextKind.ENVIRONMENT,
                domain=RecordDomain.ELF,
                source=source,
            )

    def _sync_binary_protection_context(
        self,
        *,
        binary: object,
        kind: ContextKind,
        domain: RecordDomain,
        source: str,
    ) -> None:
        pie = self._coerce_optional_bool(getattr(binary, "pie", None))
        if pie is not None:
            self.registry.set_context(
                "binary.pie",
                pie,
                kind=kind,
                domain=domain,
                source=source,
            )

        nx = self._coerce_optional_bool(getattr(binary, "nx", None))
        if nx is not None:
            self.registry.set_context(
                "binary.nx",
                nx,
                kind=kind,
                domain=domain,
                source=source,
            )

        canary = self._coerce_optional_bool(getattr(binary, "canary", None))
        if canary is not None:
            self.registry.set_context(
                "binary.canary",
                canary,
                kind=kind,
                domain=domain,
                source=source,
            )

        relro = self._normalize_relro(getattr(binary, "relro", None))
        if relro is not None:
            self.registry.set_context(
                "binary.relro",
                relro,
                kind=kind,
                domain=domain,
                source=source,
            )

    def _bind_replay_hook(self) -> None:
        if hasattr(self.transport, "bind_replay_hook"):
            self.transport.bind_replay_hook(self._handle_transport_replay_event)

    @staticmethod
    def _build_transport(target: TargetSpec, spec: TransportSpec) -> BaseTransport:
        from ..transports import build_transport

        return build_transport(target, spec)

    def _handle_transport_replay_event(self, event: str, payload: dict[str, object]) -> None:
        if event == "spawn":
            self.rec.append_event(
                ReplayEventKind.SPAWN,
                metadata={
                    "target_kind": payload.get("target_kind"),
                    "binary": payload.get("binary"),
                    "host": payload.get("host"),
                    "port": payload.get("port"),
                },
            )
            return
        if event == "send":
            data = payload.get("payload")
            if isinstance(data, bytes):
                self.rec.append_event(ReplayEventKind.SEND, payload=data)
            return
        if event == "sendline":
            data = payload.get("payload")
            if isinstance(data, bytes):
                self.rec.append_event(ReplayEventKind.SENDLINE, payload=data)
            return
        if event == "expect":
            data = payload.get("payload")
            if isinstance(data, bytes):
                self.rec.append_event(
                    ReplayEventKind.EXPECT,
                    payload=data,
                    drop=bool(payload.get("drop", False)),
                )

    @staticmethod
    def _binary_endian(binary: object) -> str | None:
        if hasattr(binary, "little_endian"):
            return "little" if bool(getattr(binary, "little_endian", True)) else "big"
        endianness = getattr(binary, "endianness", None)
        if isinstance(endianness, str) and endianness:
            normalized = endianness.lower()
            if normalized in {"little", "big"}:
                return normalized
        endian = getattr(binary, "endian", None)
        if isinstance(endian, str) and endian:
            normalized = endian.lower()
            if normalized in {"little", "big"}:
                return normalized
        return None

    @staticmethod
    def _coerce_optional_bool(value: object) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "enabled"}:
                return True
            if normalized in {"0", "false", "no", "off", "disabled"}:
                return False
        return None

    @classmethod
    def _normalize_relro(cls, value: object) -> str | None:
        if isinstance(value, str):
            normalized = value.strip().lower().replace("_", " ").replace("-", " ")
            if "full" in normalized:
                return "full"
            if "partial" in normalized:
                return "partial"
            if "none" in normalized or "no relro" in normalized:
                return "none"
            return None

        candidate_name = getattr(value, "name", None)
        if isinstance(candidate_name, str):
            resolved = cls._normalize_relro(candidate_name)
            if resolved is not None:
                return resolved

        candidate_value = getattr(value, "value", None)
        if isinstance(candidate_value, str):
            resolved = cls._normalize_relro(candidate_value)
            if resolved is not None:
                return resolved

        return None


__all__ = ["CHunSession"]
