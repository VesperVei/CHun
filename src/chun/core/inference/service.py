"""最小 inference 服务。"""

from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING
from typing import Iterable

from ..._compat import log
from ..catalog import LibcCatalogService
from ..errors import InferenceInputError
from ..models import (
    ArtifactKind,
    BaseInferenceResult,
    FactKind,
    ObservationKind,
    RecordDomain,
)
from ..models.catalog import LibcCandidate, LibcSearchResult
from ..registry import EvidenceRegistry

if TYPE_CHECKING:
    from ..session import CHunSession


class InferenceService:
    """第二阶段最小可用 inference 入口。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        page_size: int = 0x1000,
        *,
        libc_catalog: LibcCatalogService | None = None,
        session: "CHunSession | None" = None,
    ) -> None:
        self.registry = registry
        self.page_size = page_size
        self.libc_catalog = libc_catalog
        self.session = session

    def _infer_base_from_symbol_leak(
        self,
        observation_name: str,
        symbol_offset: int,
        *,
        fact_name: str,
        domain: RecordDomain,
    ) -> BaseInferenceResult:
        observation = self.registry.get_observation(observation_name)
        if observation is None:
            raise InferenceInputError(f"缺少 observation：{observation_name}")

        if not isinstance(observation.value, int):
            raise InferenceInputError("symbol leak observation 必须是整数地址。")

        if symbol_offset < 0:
            raise InferenceInputError("symbol_offset 不能为负数。")

        raw_base = observation.value - symbol_offset
        aligned_base = raw_base - (raw_base % self.page_size)
        if domain == RecordDomain.LIBC and raw_base & 0xFFF:
            log.warning(
                f"计算 libc 为：{hex(raw_base)}，可能不是正确的 libc。"
                f"（{hex(observation.value)} - {hex(symbol_offset)} = {hex(raw_base)}）"
            )

        stored_fact = self.registry.record_fact(
            fact_name,
            aligned_base,
            kind=FactKind.BASE_ADDRESS,
            domain=domain,
            source="inference",
            confidence=observation.confidence,
            evidence=[observation.name],
            tags=["base", domain.value],
            metadata={
                "raw_base": raw_base,
                "aligned_base": aligned_base,
                "symbol_offset": symbol_offset,
                "observation": observation.name,
            },
            overwrite=True,
        )
        return BaseInferenceResult(
            fact_name=fact_name,
            observation_name=observation.name,
            symbol_offset=symbol_offset,
            raw_base=raw_base,
            aligned_base=aligned_base,
            stored_fact=stored_fact,
        )

    def libc_base_from_symbol_leak(
        self,
        observation_name: str,
        symbol_offset: int,
        *,
        fact_name: str = "libc.base",
    ) -> BaseInferenceResult:
        return self._infer_base_from_symbol_leak(
            observation_name,
            symbol_offset,
            fact_name=fact_name,
            domain=RecordDomain.LIBC,
        )

    def pie_base_from_symbol_leak(
        self,
        observation_name: str,
        *,
        symbol_offset: int,
        fact_name: str = "elf.base",
    ) -> BaseInferenceResult:
        return self._infer_base_from_symbol_leak(
            observation_name,
            symbol_offset,
            fact_name=fact_name,
            domain=RecordDomain.ELF,
        )

    def set_libc_base(
        self,
        base: int,
        *,
        fact_name: str = "libc.base",
        source: str = "manual",
        aligned: bool = True,
        overwrite: bool = True,
    ) -> BaseInferenceResult:
        """直接确认 libc base，适用于手工计算或外部已知 base 的场景。"""
        if not isinstance(base, int):
            raise InferenceInputError("libc base 必须是整数地址。")
        if base < 0:
            raise InferenceInputError("libc base 不能为负数。")

        raw_base = base
        if aligned:
            aligned_base = raw_base - (raw_base % self.page_size)
        else:
            aligned_base = raw_base

        if aligned and raw_base & 0xFFF:
            log.warning(
                f"计算 libc 为：{hex(raw_base)}，可能不是正确的 libc。"
                f"（{hex(raw_base)} 未页对齐）"
            )

        stored_fact = self.registry.record_fact(
            fact_name,
            aligned_base,
            kind=FactKind.BASE_ADDRESS,
            domain=RecordDomain.LIBC,
            source=source,
            confidence=1.0,
            evidence=[],
            tags=["base", RecordDomain.LIBC.value],
            metadata={
                "raw_base": raw_base,
                "aligned_base": aligned_base,
                "symbol_offset": 0,
                "observation": None,
            },
            overwrite=overwrite,
        )
        return BaseInferenceResult(
            fact_name=fact_name,
            observation_name="",
            symbol_offset=0,
            raw_base=raw_base,
            aligned_base=aligned_base,
            stored_fact=stored_fact,
        )

    def libc_candidates_from_leaks(
        self,
        leaks: dict[str, int],
        *,
        arch: str | None = None,
        single_arch: bool = True,
        require_all: bool = True,
        min_match_count: int | None = None,
        limit: int = 50,
        artifact_name: str = "libc.candidates",
        index: int | None = None,
    ) -> LibcSearchResult:
        """从多条泄漏中检索 libc 候选并回写 registry。"""
        if self.libc_catalog is None:
            raise InferenceInputError("缺少 libc_catalog 依赖。")

        resolved_arch = (
            arch
            if arch is not None
            else self._infer_search_arch(single_arch=single_arch, strict=True)
        )

        result = self.libc_catalog.find_candidates(
            leaks,
            arch=resolved_arch,
            require_all=require_all,
            min_match_count=min_match_count,
            limit=limit,
        )
        self.registry.record_artifact(
            artifact_name,
            result,
            kind=ArtifactKind.CATALOG_RESULT,
            domain=RecordDomain.LIBC,
            source="sqlite-catalog",
            metadata={
                "query_mode": result.query_mode,
                "exact_match": result.exact_match,
                "candidate_count": len(result.candidates),
            },
            overwrite=True,
        )
        target_candidate = self._select_target_candidate(
            result.candidates,
            index=index,
        )
        if target_candidate is not None:
            self.registry.record_fact(
                "libc.version",
                target_candidate.name,
                kind=FactKind.VERSION,
                domain=RecordDomain.LIBC,
                source="sqlite-catalog",
                evidence=list(leaks.keys()),
                metadata={
                    "libc_id": target_candidate.libc_id,
                    "build_id": target_candidate.build_id,
                    "arch": target_candidate.arch,
                },
                overwrite=True,
            )
            self._auto_record_libc_base(target_candidate.libc_id, leaks)
            if index is None and len(result.candidates) == 1:
                log.success(f"libc resolved: {target_candidate.name}")
        elif len(result.candidates) == 0:
            log.error("未找到符合当前条件的 libc 候选。")
        elif len(result.candidates) > 1:
            current_arch = (
                None
                if single_arch
                else self._infer_search_arch(single_arch=True, strict=False)
            )
            self._print_candidates(result.candidates, current_arch=current_arch)
        return result

    def _select_target_candidate(
        self,
        candidates: Iterable[LibcCandidate],
        *,
        index: int | None,
    ) -> LibcCandidate | None:
        candidate_list = tuple(candidates)
        if index is not None:
            if index < 0 or index >= len(candidate_list):
                raise InferenceInputError(f"候选索引越界：index={index}")
            return candidate_list[index]
        if len(candidate_list) == 1:
            return candidate_list[0]
        return None

    def _auto_record_libc_base(self, libc_id: int, leaks: dict[str, int]) -> None:
        """根据已确认 libc 与任一泄漏自动写回 libc.base。"""
        if self.libc_catalog is None:
            raise InferenceInputError("缺少 libc_catalog 依赖。")
        if not leaks:
            raise InferenceInputError("缺少可用于推导 libc.base 的 leak。")

        symbol_name, leaked_addr = next(iter(leaks.items()))
        offset = self.libc_catalog.get_offset(libc_id, symbol_name)
        base_addr = leaked_addr - offset
        self.registry.record_fact(
            "libc.base",
            base_addr,
            kind=FactKind.BASE_ADDRESS,
            domain=RecordDomain.LIBC,
            source="sqlite-catalog",
            evidence=[symbol_name],
            metadata={
                "symbol": symbol_name,
                "symbol_offset": offset,
                "libc_id": libc_id,
                "leaked_addr": leaked_addr,
            },
            overwrite=True,
        )

    @staticmethod
    def _print_candidate(index: int, candidate: LibcCandidate) -> None:
        total_score = candidate.metadata.get("total_score")
        score = float(total_score) if total_score is not None else 0.0
        symbols = ", ".join(candidate.matched_symbols)
        print(f"  [{index}] {candidate.name}")
        print(
            f"      matched={candidate.matched_count}  "
            f"score={score:.1f}  arch={candidate.arch}"
        )
        print(f"      symbols={symbols}")
        print()

    @classmethod
    def _print_candidates(
        cls,
        candidates: Iterable[LibcCandidate],
        *,
        current_arch: str | None = None,
    ) -> None:
        """在多候选场景下输出候选列表，便于外部爆破逻辑选取。"""
        candidate_list = tuple(candidates)
        print("[+] Multiple libc candidates matched current leaks:")
        print()
        if current_arch is None:
            for index, candidate in enumerate(candidate_list):
                cls._print_candidate(index, candidate)
            return

        current_bucket = [
            (index, candidate)
            for index, candidate in enumerate(candidate_list)
            if candidate.arch == current_arch
        ]
        other_bucket = [
            (index, candidate)
            for index, candidate in enumerate(candidate_list)
            if candidate.arch != current_arch
        ]

        if current_bucket:
            print(f"Current arch ({current_arch}):")
            for index, candidate in current_bucket:
                cls._print_candidate(index, candidate)
        if other_bucket:
            print("Other arch:")
            for index, candidate in other_bucket:
                cls._print_candidate(index, candidate)

    @staticmethod
    def _normalize_search_arch(raw_arch: str | None) -> str | None:
        if raw_arch is None:
            return None
        normalized = raw_arch.strip().lower()
        aliases = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "i386": "i386",
            "i686": "i386",
            "x86": "i386",
            "aarch64": "arm64",
            "arm64": "arm64",
        }
        return aliases.get(normalized, normalized)

    @staticmethod
    def _infer_arch_from_bits(bits: int | None) -> str | None:
        if bits == 64:
            return "amd64"
        if bits == 32:
            return "i386"
        return None

    def _infer_search_arch(self, *, single_arch: bool, strict: bool = True) -> str | None:
        if not single_arch:
            return None

        raw_arch = None
        raw_bits = None

        if self.session is not None and self.session.elf is not None:
            raw_arch = getattr(self.session.elf, "arch", None)
            raw_bits = getattr(self.session.elf, "bits", None)
            normalized = self._normalize_search_arch(raw_arch)
            if normalized:
                return normalized

        with suppress(Exception):
            binary_arch = self.registry.require_context("binary.arch").value
            if isinstance(binary_arch, str):
                normalized = self._normalize_search_arch(binary_arch)
                if normalized:
                    return normalized

        with suppress(Exception):
            binary_bits = self.registry.require_context("binary.bits").value
            if isinstance(binary_bits, int):
                raw_bits = binary_bits

        with suppress(Exception):
            arch_bits = self.registry.require_context("arch.bits").value
            if isinstance(arch_bits, int):
                raw_bits = arch_bits

        inferred = self._infer_arch_from_bits(raw_bits)
        if inferred is not None:
            return inferred

        if strict:
            bits_suffix = f"，当前仅拿到 bits={raw_bits}" if isinstance(raw_bits, int) else ""
            raise InferenceInputError(
                "无法确定当前检索架构，请先绑定 session.elf 或写入 binary.arch 上下文"
                f"{bits_suffix}。"
            )
        return None

    def search_libc(
        self,
        *,
        arch: str | None = None,
        single_arch: bool = True,
        require_all: bool = True,
        min_match_count: int | None = None,
        limit: int = 50,
        artifact_name: str = "libc.candidates",
        index: int | None = None,
    ) -> LibcSearchResult:
        """自动扫描 registry 中的 libc 泄漏并检索候选。"""
        observations = self.registry.find_observations(
            domain=RecordDomain.LIBC,
            kind=ObservationKind.SYMBOL_LEAK,
        )
        selected: dict[str, tuple[int, float]] = {}
        for observation in observations:
            if not isinstance(observation.value, int):
                continue
            symbol_name = str(observation.metadata.get("symbol", observation.name))
            current = selected.get(symbol_name)
            if current is None or observation.confidence >= current[1]:
                selected[symbol_name] = (observation.value, observation.confidence)

        if not selected:
            raise InferenceInputError("事实层中没有找到任何可用的 LIBC symbol leak。")

        leaks = {symbol_name: value for symbol_name, (value, _) in selected.items()}
        return self.libc_candidates_from_leaks(
            leaks,
            arch=arch,
            single_arch=single_arch,
            require_all=require_all,
            min_match_count=min_match_count,
            limit=limit,
            artifact_name=artifact_name,
            index=index,
        )


__all__ = ["InferenceService"]
