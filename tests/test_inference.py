from __future__ import annotations

import json
from pathlib import Path

import chun.core.inference.service as inference_service_mod
import pytest
from chun import CHunSession
from chun.core.catalog import LibcCatalogService, build_libc_database
from chun.core.cache import CacheService
from chun.core.errors import InferenceInputError, ResolverError
from chun.core.inference import InferenceService
from chun.core.models import (
    ArtifactKind,
    FactKind,
    ObservationKind,
    RecordDomain,
    TargetSpec,
    TransportSpec,
)
from chun.core.registry import EvidenceRegistry
from chun.core.resolve import ResolveService


class DummyTransport:
    is_open = False
    raw = object()

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def reconnect(self) -> None:
        self.is_open = True


class DummyElf:
    def __init__(
        self,
        *,
        path: str = "./challenge",
        arch: str | None = "amd64",
        bits: int = 64,
        bytes_: int = 8,
        endian: str = "little",
        sym: dict[str, int] | None = None,
    ) -> None:
        self.path = path
        self.arch = arch
        self.bits = bits
        self.bytes = bytes_
        self.endian = endian
        self.sym = {} if sym is None else sym

    def search(self, needle: bytes):
        if needle != b"/bin/sh":
            return iter(())
        offset = self.sym.get("str_bin_sh")
        if offset is None:
            return iter(())
        return iter((offset,))


def build_session(*, libc_catalog: LibcCatalogService | None = None) -> CHunSession:
    return CHunSession(
        target=TargetSpec(kind="process"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyTransport(),
        libc_catalog=LibcCatalogService() if libc_catalog is None else libc_catalog,
    )


def test_libc_base_inference_creates_fact_from_symbol_leak_observation() -> None:
    registry = EvidenceRegistry()
    expected_base = 0x7F1234500000
    puts_offset = 0x080000
    registry.record_symbol_leak(
        "puts",
        expected_base + puts_offset,
        domain=RecordDomain.LIBC,
        source="got",
        confidence=0.85,
    )

    infer = InferenceService(registry)
    result = infer.libc_base_from_symbol_leak("puts", puts_offset)

    fact = registry.get_fact("libc.base")
    assert fact is not None
    assert fact.kind == FactKind.BASE_ADDRESS
    assert fact.domain == RecordDomain.LIBC
    assert fact.value == expected_base
    assert fact.metadata["symbol_offset"] == puts_offset
    assert result.raw_base == expected_base
    assert result.aligned_base == expected_base


def test_libc_base_inference_accepts_symbol_offset_as_second_argument() -> None:
    registry = EvidenceRegistry()
    expected_base = 0x7F1234500000
    atoi_offset = 0x03A950
    registry.record_symbol_leak(
        "atoi@got",
        expected_base + atoi_offset,
        domain=RecordDomain.LIBC,
        source="got",
    )

    infer = InferenceService(registry)
    result = infer.libc_base_from_symbol_leak("atoi@got", atoi_offset)

    assert result.aligned_base == expected_base
    assert registry.require_int_fact("libc.base") == expected_base


def test_libc_base_inference_warns_when_raw_base_is_not_page_aligned(
    monkeypatch,
) -> None:
    registry = EvidenceRegistry()
    leak = 0x7F123456789A
    atoi_offset = 0x03A950
    raw_base = leak - atoi_offset
    warnings: list[str] = []
    registry.record_symbol_leak(
        "atoi@got",
        leak,
        domain=RecordDomain.LIBC,
        source="got",
    )
    monkeypatch.setattr(inference_service_mod.log, "warning", warnings.append)

    infer = InferenceService(registry)
    result = infer.libc_base_from_symbol_leak("atoi@got", atoi_offset)

    assert result.raw_base == raw_base
    assert warnings == [
        f"计算 libc 为：{hex(raw_base)}，可能不是正确的 libc。"
        f"（{hex(leak)} - {hex(atoi_offset)} = {hex(raw_base)}）"
    ]


def test_libc_base_inference_does_not_warn_when_raw_base_is_page_aligned(
    monkeypatch,
) -> None:
    registry = EvidenceRegistry()
    expected_base = 0x7F1234500000
    puts_offset = 0x080000
    warnings: list[str] = []
    registry.record_symbol_leak(
        "puts",
        expected_base + puts_offset,
        domain=RecordDomain.LIBC,
        source="got",
    )
    monkeypatch.setattr(inference_service_mod.log, "warning", warnings.append)

    infer = InferenceService(registry)
    result = infer.libc_base_from_symbol_leak("puts", puts_offset)

    assert result.raw_base == expected_base
    assert warnings == []


def test_set_libc_base_records_fact_directly() -> None:
    registry = EvidenceRegistry()
    infer = InferenceService(registry)

    result = infer.set_libc_base(0x7F1234500000)

    assert result.raw_base == 0x7F1234500000
    assert result.aligned_base == 0x7F1234500000
    assert result.observation_name == ""
    fact = registry.get_fact("libc.base")
    assert fact is not None
    assert fact.value == 0x7F1234500000
    assert fact.kind is FactKind.BASE_ADDRESS
    assert fact.domain is RecordDomain.LIBC
    assert fact.source == "manual"


def test_set_libc_base_aligns_and_warns_on_unaligned_input(monkeypatch) -> None:
    registry = EvidenceRegistry()
    infer = InferenceService(registry)
    warnings: list[str] = []
    monkeypatch.setattr(inference_service_mod.log, "warning", warnings.append)

    result = infer.set_libc_base(0x7F123456789A)

    assert result.raw_base == 0x7F123456789A
    assert result.aligned_base == 0x7F1234567000
    assert registry.require_int_fact("libc.base") == 0x7F1234567000
    assert len(warnings) == 1


def test_set_libc_base_can_keep_unaligned_value(monkeypatch) -> None:
    registry = EvidenceRegistry()
    infer = InferenceService(registry)
    warnings: list[str] = []
    monkeypatch.setattr(inference_service_mod.log, "warning", warnings.append)

    result = infer.set_libc_base(0x7F123456789A, aligned=False)

    assert result.aligned_base == 0x7F123456789A
    assert registry.require_int_fact("libc.base") == 0x7F123456789A
    assert warnings == []


def test_set_libc_base_rejects_negative_value() -> None:
    infer = InferenceService(EvidenceRegistry())

    with pytest.raises(InferenceInputError):
        infer.set_libc_base(-1)


def test_session_libc_base_setter_records_fact() -> None:
    session = build_session()

    session.libc_base = 0x7F0000000000

    assert session.libc_base == 0x7F0000000000
    assert session.rec.require_int_fact("libc.base") == 0x7F0000000000


def test_libc_candidates_from_leaks_requires_catalog_dependency() -> None:
    registry = EvidenceRegistry()
    infer = InferenceService(registry)

    try:
        infer.libc_candidates_from_leaks({"puts": 0x7F0000000000 + 0x080AA0})
    except InferenceInputError:
        pass
    else:
        raise AssertionError("expected InferenceInputError")


def test_libc_candidates_from_leaks_writes_artifact_and_fact_for_unique_match(
    tmp_path: Path,
    monkeypatch,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-2.31-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {
                "puts": "0x080aa0",
                "scanf": "0x021ab0",
            },
        },
        {
            "name": "glibc-2.35-amd64",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {
                "puts": "0x080aa0",
            },
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    success_messages: list[str] = []

    class DummyLog:
        @staticmethod
        def success(message: str) -> None:
            success_messages.append(message)

        @staticmethod
        def error(message: str) -> None:
            raise AssertionError(message)

    monkeypatch.setattr(inference_service_mod, "log", DummyLog())

    result = infer.libc_candidates_from_leaks(
        {
            "puts": 0x7F0000000000 + 0x080AA0,
            "__isoc99_scanf": 0x7F0000000000 + 0x021AB0,
        },
        arch="amd64",
    )

    assert len(result.candidates) == 1

    artifact = registry.get_artifact("libc.candidates")
    assert artifact is not None
    assert artifact.kind == ArtifactKind.CATALOG_RESULT
    assert artifact.domain == RecordDomain.LIBC
    assert artifact.source == "sqlite-catalog"
    assert artifact.value is result
    assert artifact.metadata["candidate_count"] == 1
    assert artifact.metadata["query_mode"] == "strict"

    fact = registry.get_fact("libc.version")
    assert fact is not None
    assert fact.kind == FactKind.VERSION
    assert fact.domain == RecordDomain.LIBC
    assert fact.source == "sqlite-catalog"
    assert fact.value == "glibc-2.31-amd64"
    assert fact.evidence == ["puts", "__isoc99_scanf"]
    assert fact.metadata["libc_id"] == 1
    assert fact.metadata["build_id"] == "build-a"
    assert fact.metadata["arch"] == "amd64"

    base_fact = registry.get_fact("libc.base")
    assert base_fact is not None
    assert base_fact.kind == FactKind.BASE_ADDRESS
    assert base_fact.value == 0x7F0000000000
    assert base_fact.metadata["libc_id"] == 1
    assert base_fact.metadata["symbol"] == "puts"
    assert success_messages == ["libc resolved: glibc-2.31-amd64"]

    service.close()


def test_search_libc_scans_registry_and_prefers_higher_confidence_symbol_leaks(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-2.31-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {
                "puts": "0x080aa0",
                "scanf": "0x021ab0",
            },
        },
        {
            "name": "glibc-2.35-amd64",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {
                "puts": "0x090aa0",
                "scanf": "0x031bb0",
            },
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path, include_all=True)

    service = LibcCatalogService(db_path=output_path)
    session = build_session(libc_catalog=service)
    session.bind_binaries(elf=DummyElf(arch="amd64"))
    registry = session.registry
    registry.record_symbol_leak(
        "puts",
        0x7F0000000000 + 0x090AA0,
        domain=RecordDomain.LIBC,
        confidence=0.20,
        source="got-low",
    )
    registry.record_symbol_leak(
        "puts",
        0x7F0000000000 + 0x080AA0,
        domain=RecordDomain.LIBC,
        confidence=0.95,
        source="got-high",
    )
    registry.record_observation(
        "scanf.bad",
        "not-an-int",
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        metadata={"symbol": "__isoc99_scanf"},
        source="bad",
    )
    registry.record_observation(
        "scanf.good",
        0x7F0000000000 + 0x021AB0,
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        metadata={"symbol": "__isoc99_scanf"},
        confidence=0.80,
        source="good",
    )
    registry.record_symbol_leak(
        "main",
        0x555555554000,
        domain=RecordDomain.ELF,
        source="elf",
    )

    result = session.infer.search_libc()

    assert [candidate.name for candidate in result.candidates] == ["glibc-2.31-amd64"]

    artifact = registry.get_artifact("libc.candidates")
    assert artifact is not None
    assert artifact.metadata["candidate_count"] == 1

    fact = registry.get_fact("libc.version")
    assert fact is not None
    assert fact.value == "glibc-2.31-amd64"
    assert fact.evidence == ["puts", "__isoc99_scanf"]

    base_fact = registry.get_fact("libc.base")
    assert base_fact is not None
    assert base_fact.value == 0x7F0000000000

    service.close()


def test_search_libc_raises_when_no_usable_libc_symbol_leak_exists() -> None:
    registry = EvidenceRegistry()
    registry.record_observation(
        "puts",
        "not-an-int",
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        source="bad",
    )
    registry.record_symbol_leak(
        "main",
        0x555555554000,
        domain=RecordDomain.ELF,
        source="elf",
    )

    infer = InferenceService(registry)
    try:
        infer.search_libc()
    except InferenceInputError:
        pass
    else:
        raise AssertionError("expected InferenceInputError")


def test_libc_candidates_from_leaks_can_confirm_candidate_by_index_and_auto_record_base(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-b",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    result = infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
        index=1,
        arch="amd64",
    )

    assert len(result.candidates) == 2

    fact = registry.get_fact("libc.version")
    assert fact is not None
    assert fact.source == "sqlite-catalog"
    assert fact.value == "glibc-b"
    assert fact.metadata["libc_id"] == 2
    assert fact.metadata["build_id"] == "build-b"

    base_fact = registry.get_fact("libc.base")
    assert base_fact is not None
    assert base_fact.value == 0x7F0000000000
    assert base_fact.metadata["libc_id"] == 2

    service.close()


def test_libc_candidates_from_leaks_raises_when_index_is_out_of_range(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    try:
        infer.libc_candidates_from_leaks(
            {"puts": 0x7F0000000000 + 0x080AA0},
            index=99,
            arch="amd64",
        )
    except InferenceInputError:
        pass
    else:
        raise AssertionError("expected InferenceInputError")
    finally:
        service.close()


def test_libc_candidates_from_leaks_prints_candidates_when_multiple_and_unconfirmed(
    tmp_path: Path,
    capsys,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-b",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    result = infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
        arch="amd64",
    )

    captured = capsys.readouterr()
    assert len(result.candidates) == 2
    assert registry.get_fact("libc.version") is None
    assert registry.get_fact("libc.base") is None
    assert "[+] Multiple libc candidates matched current leaks:" in captured.out
    assert "  [0] glibc-a" in captured.out
    assert "      matched=1  score=10.0  arch=amd64" in captured.out
    assert "      symbols=puts" in captured.out
    assert "  [1] glibc-b" in captured.out

    service.close()


def test_libc_candidates_from_leaks_logs_error_when_no_candidate_matches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    errors: list[str] = []

    class DummyLog:
        @staticmethod
        def error(message: str) -> None:
            errors.append(message)

    monkeypatch.setattr(inference_service_mod, "log", DummyLog())

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    result = infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x180AA1},
        arch="amd64",
    )

    assert result.candidates == []
    assert errors == ["未找到符合当前条件的 libc 候选。"]

    service.close()


def test_search_libc_uses_context_binary_arch_by_default_and_can_disable_single_arch(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-i386",
            "arch": "i386",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    session = build_session(libc_catalog=service)
    session.bind_binaries(elf=DummyElf(arch="amd64"))

    narrowed = session.infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
    )
    expanded = session.infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
        single_arch=False,
    )

    assert [candidate.name for candidate in narrowed.candidates] == ["glibc-amd64"]
    assert [candidate.name for candidate in expanded.candidates] == [
        "glibc-amd64",
        "glibc-i386",
    ]

    service.close()


def test_libc_candidates_from_leaks_groups_multi_arch_output_with_global_indexes(
    tmp_path: Path,
    capsys,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-amd64-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-amd64-b",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-i386-a",
            "arch": "i386",
            "build_id": "build-c",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    session = build_session(libc_catalog=service)
    session.rec.set_context("binary.arch", "amd64", domain=RecordDomain.ELF)
    result = session.infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
        single_arch=False,
    )

    captured = capsys.readouterr()
    assert len(result.candidates) == 3
    assert "Current arch (amd64):" in captured.out
    assert "Other arch:" in captured.out
    assert "  [0] glibc-amd64-a" in captured.out
    assert "  [1] glibc-amd64-b" in captured.out
    assert "  [2] glibc-i386-a" in captured.out

    service.close()


def test_libc_candidates_from_leaks_raises_when_arch_is_required_but_unavailable(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    session = build_session(libc_catalog=service)

    with pytest.raises(InferenceInputError, match="无法确定当前检索架构"):
        session.infer.libc_candidates_from_leaks(
            {"puts": 0x7F0000000000 + 0x080AA0},
            require_all=False,
        )

    service.close()


def test_libc_candidates_from_leaks_can_infer_arch_from_bits_context(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-i386",
            "arch": "i386",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    session = build_session(libc_catalog=service)
    session.rec.set_context("binary.bits", 64, domain=RecordDomain.ELF)
    narrowed = session.infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
    )

    session = build_session(libc_catalog=service)
    session.rec.set_context("arch.bits", 64, domain=RecordDomain.ELF)
    narrowed_via_arch_bits = session.infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
    )

    assert [candidate.name for candidate in narrowed.candidates] == ["glibc-amd64"]
    assert [candidate.name for candidate in narrowed_via_arch_bits.candidates] == [
        "glibc-amd64"
    ]

    service.close()


def test_resolve_symbol_uses_catalog_offsets_and_alias_normalization(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-resolve",
            "arch": "amd64",
            "build_id": "build-r",
            "symbols": {
                "puts": "0x080aa0",
                "str_bin_sh": "0x044444",
            },
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path, include_all=True)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    registry.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    registry.record_fact(
        "libc.version",
        "glibc-resolve",
        kind=FactKind.VERSION,
        domain=RecordDomain.LIBC,
        metadata={"libc_id": 1, "build_id": "build-r", "arch": "amd64"},
    )
    resolve = ResolveService(
        registry,
        InferenceService(registry, libc_catalog=service),
        catalog_service=service,
    )

    assert resolve.symbol("puts@got") == 0x7F0000000000 + 0x080AA0
    assert resolve.symbol("str_bin_sh") == 0x7F0000000000 + 0x044444

    service.close()


def test_resolve_symbol_raises_when_required_facts_are_missing() -> None:
    registry = EvidenceRegistry()
    resolve = ResolveService(registry, InferenceService(registry))

    try:
        resolve.symbol("system")
    except ResolverError:
        pass
    else:
        raise AssertionError("expected ResolverError")


def test_resolve_symbol_prefers_bound_libc_elf_without_requiring_version_fact() -> None:
    session = build_session()
    session.bind_binaries(libc_elf=DummyElf(path="./libc.so.6", sym={"system": 0x4C490}))
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )

    assert session.resolve.symbol("system") == 0x7F0000000000 + 0x4C490


def test_resolve_symbol_uses_trusted_cached_libc_offsets_without_bound_libc(
    tmp_path: Path,
) -> None:
    libc_path = tmp_path / "libc.so.6"
    libc_path.write_bytes(b"fake-libc")

    def fake_loader(path: str, checksec: bool = False) -> DummyElf:
        _ = checksec
        assert path == str(libc_path)
        return DummyElf(path=path, sym={"system": 0x4C490, "puts": 0x080AA0})

    cache = CacheService(root=tmp_path / "cache")
    cache.ensure_libc_record(
        libc_path,
        loader=fake_loader,
        source="specified",
        trusted=True,
        usable_for_remote=True,
    )

    session = build_session()
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    session.resolve.configure_libc_cache(
        cache_service=cache,
        libc_path=str(libc_path),
        source="specified",
        trusted=True,
        usable_for_remote=True,
    )

    assert session.resolve.symbol("system") == 0x7F0000000000 + 0x4C490


def test_resolve_symbol_can_lazy_materialize_specified_libc_and_write_back_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    libc_path = tmp_path / "libc.so.6"
    libc_path.write_bytes(b"fake-libc")

    def seed_loader(path: str, checksec: bool = False) -> DummyElf:
        _ = checksec
        assert path == str(libc_path)
        return DummyElf(path=path, sym={"system": 0x4C490})

    def lazy_loader(path: str, checksec: bool = False) -> DummyElf:
        _ = checksec
        assert path == str(libc_path)
        return DummyElf(path=path, sym={"__free_hook": 0x1EEB28})

    cache = CacheService(root=tmp_path / "cache")
    cache.ensure_libc_record(
        libc_path,
        loader=seed_loader,
        source="specified",
        trusted=True,
        usable_for_remote=True,
    )

    monkeypatch.setattr("chun.core.resolve.service.PWN_ELF", lazy_loader)
    session = build_session()
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    session.resolve.configure_libc_cache(
        cache_service=cache,
        libc_path=str(libc_path),
        source="specified",
        trusted=True,
        usable_for_remote=True,
    )

    assert session.resolve.symbol("__free_hook") == 0x7F0000000000 + 0x1EEB28
    record = cache.get_libc_record(libc_path)
    assert record is not None
    assert record["extra_symbols"]["__free_hook"] == 0x1EEB28


def test_resolve_symbol_raises_clear_error_when_no_trusted_libc_source_configured() -> None:
    session = build_session()
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    with pytest.raises(ResolverError, match="No trusted libc source configured"):
        session.resolve.symbol("system")


def test_resolve_symbol_rejects_local_detected_cache_for_remote_target(
    tmp_path: Path,
) -> None:
    libc_path = tmp_path / "libc.so.6"
    libc_path.write_bytes(b"fake-libc")

    def fake_loader(path: str, checksec: bool = False) -> DummyElf:
        _ = checksec
        return DummyElf(path=path, sym={"system": 0x4C490})

    cache = CacheService(root=tmp_path / "cache")
    cache.ensure_libc_record(
        libc_path,
        loader=fake_loader,
        source="local_detected",
        trusted=True,
        usable_for_remote=False,
    )

    session = CHunSession(
        target=TargetSpec(kind="remote"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyTransport(),
    )
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    session.resolve.configure_libc_cache(
        cache_service=cache,
        libc_path=str(libc_path),
        source="local_detected",
        trusted=True,
        usable_for_remote=False,
    )

    with pytest.raises(ResolverError, match="No trusted libc source configured"):
        session.resolve.symbol("system")


def test_resolve_symbol_uses_bound_libc_search_for_str_bin_sh() -> None:
    session = build_session()
    session.bind_binaries(libc_elf=DummyElf(path="./libc.so.6", sym={"str_bin_sh": 0x1B45BD}))
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )

    assert session.resolve.symbol("str_bin_sh") == 0x7F0000000000 + 0x1B45BD


def test_resolve_uses_session_bound_libc_elf_for_base_inference() -> None:
    session = build_session()
    libc = DummyElf(path="./libc.so.6", sym={"puts": 0x80000})

    session.bind_binaries(libc_elf=libc)
    session.rec.record_symbol_leak(
        "puts",
        0x7F1234500000 + 0x80000,
        domain=RecordDomain.LIBC,
        source="got",
    )
    result = session.resolve.libc_base_from_elf_symbol("puts", symbol="puts")

    assert session.libc_elf is libc
    assert session.rec.require_context("libc.path").value == "./libc.so.6"
    assert result.value == 0x7F1234500000


def test_resolve_libc_base_from_elf_symbol_raises_without_explicit_or_session_libc() -> None:
    session = build_session()
    session.rec.record_symbol_leak(
        "puts",
        0x7F1234500000 + 0x80000,
        domain=RecordDomain.LIBC,
        source="got",
    )

    with pytest.raises(ResolverError, match="缺少可用的 libc_elf / elf"):
        session.resolve.libc_base_from_elf_symbol("puts", symbol="puts")


def test_resolve_pie_base_from_elf_symbol_raises_without_explicit_or_session_elf() -> None:
    session = build_session()
    session.rec.record_symbol_leak(
        "main",
        0x555555554000 + 0x1234,
        domain=RecordDomain.ELF,
        source="plt",
    )

    with pytest.raises(ResolverError, match="缺少可用的 elf"):
        session.resolve.pie_base_from_elf_symbol("main", symbol="main")


def test_resolve_prefers_explicit_symbol_source_over_session_binding() -> None:
    session = build_session()
    session.bind_binaries(libc_elf=DummyElf(path="./session-libc.so.6", sym={"puts": 0x90000}))
    explicit_libc = DummyElf(path="./explicit-libc.so.6", sym={"puts": 0x80000})

    session.rec.record_symbol_leak(
        "puts",
        0x7F1234500000 + 0x80000,
        domain=RecordDomain.LIBC,
        source="got",
    )
    result = session.resolve.libc_base_from_elf_symbol(
        "puts",
        libc_elf=explicit_libc,
        symbol="puts",
    )

    assert result.value == 0x7F1234500000
