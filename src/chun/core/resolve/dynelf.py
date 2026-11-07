"""DynELF 解析桥接。"""

from __future__ import annotations

from typing import Any, Callable

from ... import _compat
from ...bridges.pwntools import MemLeakAdapter
from ..errors import ResolverError
from ..models import FactKind, RecordDomain, ResolvedSymbolResult
from ..registry import EvidenceRegistry


class DynELFResolver:
    """把 MemLeak 和 DynELF 组合成结构化解析入口。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        *,
        adapter_cls: type[MemLeakAdapter] = MemLeakAdapter,
        dynelf_cls: type | None = None,
    ) -> None:
        self.registry = registry
        self.adapter_cls = adapter_cls
        self.dynelf_cls = dynelf_cls or _compat.DynELF

    def lookup(
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
        """使用 pwntools DynELF 查找符号并记录结构化解析事实。

        ``pointer`` 是目标 ELF 中可用于 DynELF 定位的已知指针；
        ``leak_primitive`` 与 ``memleak`` 二选一。解析成功后，地址会以
        ``SYMBOL_ADDRESS`` fact 写入 registry，并返回包含该 fact 的结果对象。
        """
        if memleak is None:
            if leak_primitive is None:
                raise ResolverError("DynELF 解析需要 leak_primitive 或现成的 MemLeak 对象。")
            adapter = self.adapter_cls(
                leak_primitive,
                self.registry,
                domain=domain,
                memleak_cls=memleak_cls,
            )
            memleak = adapter.create()

        dynelf_type = dynelf_cls or self.dynelf_cls
        dynelf = dynelf_type(memleak, pointer=pointer, elf=elf, libcdb=False)
        address = dynelf.lookup(symbol, lib=lib)
        if address is None:
            raise ResolverError(f"DynELF 未能解析符号：{symbol}")

        resolved_fact_name = fact_name or f"resolved.{lib or 'global'}.{symbol}"
        stored_fact = self.registry.record_fact(
            resolved_fact_name,
            int(address),
            kind=FactKind.SYMBOL_ADDRESS,
            domain=domain,
            source="dynelf",
            confidence=0.85,
            evidence=[],
            tags=["dynelf", symbol],
            metadata={
                "symbol": symbol,
                "library": lib,
                "pointer": pointer,
            },
            overwrite=True,
        )
        return ResolvedSymbolResult(
            symbol=symbol,
            library=lib,
            address=int(address),
            fact_name=resolved_fact_name,
            stored_fact=stored_fact,
        )


__all__ = ["DynELFResolver"]
