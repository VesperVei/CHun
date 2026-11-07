"""Resolve service。"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable, Mapping, Protocol, SupportsInt

from ... import _compat
from ...bridges.pwntools import MemLeakAdapter
from ..cache import CacheService
from ..catalog import LibcCatalogService
from ..errors import ResolverError
from ..inference import InferenceService
from ..models import BaseInferenceResult, RecordDomain, ResolvedSymbolResult
from ..registry import EvidenceRegistry
from .dynelf import DynELFResolver

if TYPE_CHECKING:
    from ..session import CHunSession


def PWN_ELF(*args: object, **kwargs: object) -> object:
    return _compat.ELF(*args, **kwargs)


class SupportsSym(Protocol):
    """最小 ELF 协议：只要求提供 ``sym`` 映射。"""

    sym: Mapping[str, SupportsInt]


class ResolveService:
    """围绕 pwntools / DynELF 的最小解析入口。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        infer: InferenceService,
        *,
        session: "CHunSession | None" = None,
        catalog_service: LibcCatalogService | None = None,
        memleak_adapter_cls: type[MemLeakAdapter] = MemLeakAdapter,
        dynelf_resolver_cls: type[DynELFResolver] = DynELFResolver,
    ) -> None:
        self.registry = registry
        self.infer = infer
        self.session = session
        self.catalog_service = (
            catalog_service if catalog_service is not None else infer.libc_catalog
        )
        self.memleak_adapter_cls = memleak_adapter_cls
        self.dynelf_resolver = dynelf_resolver_cls(
            registry, adapter_cls=memleak_adapter_cls
        )
        self.default_elf: object | None = None
        self.default_libc_elf: object | None = None
        self.cache_service: CacheService | None = None
        self.libc_cache_path: str | None = None
        self.libc_cache_source: str = "unresolved"
        self.libc_cache_trusted: bool = False
        self.libc_cache_usable_for_remote: bool = False

    def _session_elf(self) -> object | None:
        if self.session is not None and self.session.elf is not None:
            return self.session.elf
        return self.default_elf

    def _session_libc_elf(self) -> object | None:
        if self.session is not None and self.session.libc_elf is not None:
            return self.session.libc_elf
        return self.default_libc_elf

    def bind_defaults(
        self,
        *,
        elf: object | None = None,
        libc_elf: object | None = None,
    ) -> None:
        """绑定脚本态 / session 共享的默认 ELF 对象。"""
        if elf is not None:
            self.default_elf = elf
        if libc_elf is not None:
            self.default_libc_elf = libc_elf
        if self.session is not None and (elf is not None or libc_elf is not None):
            self.session.bind_binaries(
                elf=elf,
                libc_elf=libc_elf,
                source="resolve.bind_defaults",
            )

    def configure_libc_cache(
        self,
        *,
        cache_service: CacheService | None,
        libc_path: str | None,
        source: str,
        trusted: bool,
        usable_for_remote: bool,
    ) -> None:
        self.cache_service = cache_service
        self.libc_cache_path = libc_path
        self.libc_cache_source = source
        self.libc_cache_trusted = bool(trusted)
        self.libc_cache_usable_for_remote = bool(usable_for_remote)

    def _normalize_symbol_name(self, raw_name: str) -> str:
        if self.catalog_service is not None:
            normalize = getattr(self.catalog_service, "_normalize_name", None)
            if callable(normalize):
                return str(normalize(raw_name))

        return re.split(r"[@_](got|plt|got\.plt)", raw_name, flags=re.IGNORECASE)[0].strip()

    @staticmethod
    def _offset_from_bound_object(obj: object, value: SupportsInt) -> int:
        resolved = int(value)
        base_hint = getattr(obj, "address", 0)
        if isinstance(base_hint, int) and base_hint > 0 and resolved >= base_hint:
            return resolved - base_hint
        return resolved

    def _resolve_from_bound_libc(self, name: str, *, base_value: int) -> int | None:
        libc_elf = self._session_libc_elf()
        if libc_elf is None:
            return None

        normalized = self._normalize_symbol_name(name)
        for attr in ("sym", "symbols"):
            table = getattr(libc_elf, attr, None)
            if not isinstance(table, Mapping):
                continue
            for candidate in (name, normalized):
                if candidate not in table:
                    continue
                return base_value + self._offset_from_bound_object(libc_elf, table[candidate])

        if normalized in {"str_bin_sh", "/bin/sh", "binsh"}:
            search = getattr(libc_elf, "search", None)
            if callable(search):
                try:
                    match = next(search(b"/bin/sh"))
                except Exception:
                    return None
                return base_value + self._offset_from_bound_object(libc_elf, match)
        return None

    def _read_libc_base(self) -> int:
        base_record = self.registry.get_fact("libc.base")
        if base_record is None:
            observation = self.registry.get_observation("libc.base")
            base_value = observation.value if observation is not None else None
        else:
            base_value = base_record.value
        if not isinstance(base_value, int):
            raise ResolverError("缺少已确认的 libc.base。")
        return base_value

    def memleak(
        self,
        leak_primitive: Callable[..., bytes | bytearray | None],
        *,
        domain: RecordDomain = RecordDomain.RESOLVE,
        chunk_size: int = 8,
        memleak_cls: type | None = None,
    ) -> MemLeakAdapter:
        """把原始内存泄漏函数包装为可供 DynELF 使用的 MemLeak 适配器。

        ``leak_primitive`` 应接收地址以及可选的读取长度，并返回读取到的
        bytes；适配器会把泄漏过程中的结果写入当前 session registry。
        """
        return self.memleak_adapter_cls(
            leak_primitive,
            self.registry,
            domain=domain,
            chunk_size=chunk_size,
            memleak_cls=memleak_cls,
        )

    def symbol_via_dynelf(
        self,
        symbol: str,
        pointer: int | None,
        *,
        leak_primitive: Callable[..., bytes | bytearray | None] | None = None,
        memleak: object | None = None,
        lib: str | None = None,
        elf: object | None = None,
        fact_name: str | None = None,
        domain: RecordDomain = RecordDomain.RESOLVE,
        memleak_cls: type | None = None,
        dynelf_cls: type | None = None,
    ) -> ResolvedSymbolResult:
        """通过 DynELF 解析运行时符号地址并写入 registry。

        ``pointer`` 是 DynELF 用来定位 ELF 的已知指针。``leak_primitive``
        与 ``memleak`` 二选一：前者由本方法创建 MemLeak，后者直接复用现成
        的 MemLeak 对象。解析结果默认写入
        ``resolved.<library-or-global>.<symbol>`` fact。
        """
        return self.dynelf_resolver.lookup(
            symbol,
            leak_primitive=leak_primitive,
            memleak=memleak,
            pointer=pointer,
            lib=lib,
            elf=elf,
            fact_name=fact_name,
            domain=domain,
            memleak_cls=memleak_cls,
            dynelf_cls=dynelf_cls,
        )

    def libc_base_from_elf_symbol(
        self,
        observation_name: str,
        symbol: str,
        *,
        libc_elf: SupportsSym | None = None,
        fact_name: str = "libc.base",
    ) -> BaseInferenceResult:
        """根据 libc ELF 中的符号偏移推导并记录 ``libc.base``。

        ``observation_name`` 必须对应 registry 中已记录的泄漏地址，
        ``symbol`` 是该地址对应的 libc 符号名。优先使用显式传入的
        ``libc_elf``，否则使用当前 session 绑定的 ``libc_elf``；该对象必须
        提供 ``.sym`` 映射。推导结果会委托给 inference 层并写入 fact。
        """
        candidate = (
            libc_elf
            if libc_elf is not None
            else self._session_libc_elf()
            if self._session_libc_elf() is not None
            else None
        )
        if candidate is None:
            raise ResolverError("缺少可用的 libc_elf，请显式传参或先绑定到 session。")
        if not hasattr(candidate, "sym"):
            raise ResolverError("libc_elf 需要提供 .sym 映射。")
        symbol_offset = int(candidate.sym[symbol])
        return self.infer.libc_base_from_symbol_leak(
            observation_name,
            symbol_offset,
            fact_name=fact_name,
        )

    def pie_base_from_elf_symbol(
        self,
        observation_name: str,
        symbol: str,
        *,
        elf: SupportsSym | None = None,
        fact_name: str = "elf.base",
    ) -> BaseInferenceResult:
        """根据主 ELF 中的符号偏移推导并记录 ``elf.base``。

        ``observation_name`` 必须对应 registry 中已记录的泄漏地址，
        ``symbol`` 是该地址对应的 ELF 符号名。优先使用显式传入的 ``elf``，
        否则使用当前 session 绑定的主 ELF；该对象必须提供 ``.sym`` 映射。
        """
        candidate = elf if elf is not None else self._session_elf()
        if candidate is None:
            raise ResolverError("缺少可用的 elf，请显式传参或先绑定到 session。")
        if not hasattr(candidate, "sym"):
            raise ResolverError("elf 需要提供 .sym 映射。")
        symbol_offset = int(candidate.sym[symbol])
        return self.infer.pie_base_from_symbol_leak(
            observation_name,
            symbol_offset=symbol_offset,
            fact_name=fact_name,
        )

    def symbol(self, name: str) -> int:
        """根据已确认的 libc base 解析符号的运行时绝对地址。

        符号解析按可信本地 libc 缓存、已绑定 libc ELF、libc catalog 的顺序
        尝试，并支持常见符号后缀和 ``str_bin_sh`` alias。要求 registry 中
        已存在 ``libc.base``，且至少有一个可信的 libc 符号来源。
        """
        base_value = self._read_libc_base()
        normalized = self._normalize_symbol_query(name)

        if self._libc_cache_allowed():
            offset = self._resolve_from_cached_libc_offset(normalized)
            if offset is not None:
                return base_value + offset

        resolved = self._resolve_from_bound_libc(normalized, base_value=base_value)
        if resolved is not None:
            return resolved

        offset = self._resolve_from_catalog(normalized)
        if offset is not None:
            return base_value + offset

        if self._libc_cache_allowed():
            offset = self._materialize_cached_libc_offset(normalized)
            if offset is not None:
                return base_value + offset

        raise ResolverError(
            "No trusted libc source configured; pass libc=..., run search_libc(...), "
            "or enable auto_local_libc explicitly."
        )

    def _normalize_symbol_query(self, raw_name: str) -> str:
        normalized = self._normalize_symbol_name(raw_name)
        lowered = normalized.strip().lower()
        if lowered in {"str_bin_sh", "/bin/sh", "binsh"}:
            return "/bin/sh"
        return normalized

    def _resolve_from_cached_libc_offset(self, normalized_name: str) -> int | None:
        if self.cache_service is None or self.libc_cache_path is None:
            return None
        return self.cache_service.lookup_libc_offset(self.libc_cache_path, normalized_name)

    def _materialize_cached_libc_offset(self, normalized_name: str) -> int | None:
        if self.cache_service is None or self.libc_cache_path is None:
            return None
        return self.cache_service.materialize_libc_offset(
            self.libc_cache_path,
            normalized_name,
            loader=PWN_ELF,
        )

    def _resolve_from_catalog(self, normalized_name: str) -> int | None:
        if self.catalog_service is None:
            return None
        version_fact = self.registry.get_fact("libc.version")
        if version_fact is None:
            return None
        libc_id = version_fact.metadata.get("libc_id")
        if not isinstance(libc_id, int):
            return None
        try:
            return int(self.catalog_service.get_offset(libc_id, normalized_name))
        except Exception:
            return None

    def _libc_cache_allowed(self) -> bool:
        if not self.libc_cache_trusted:
            return False
        if self.session is not None and self.session.target.kind == "remote":
            return self.libc_cache_usable_for_remote
        return True


__all__ = ["ResolveService"]
