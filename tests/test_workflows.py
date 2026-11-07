from __future__ import annotations

from dataclasses import dataclass

from chun import CHun, RecordDomain


def test_ret2libc_workflow_uses_session_registry_inference_and_pwntools_style_symbol_map() -> None:
    session = CHun.process("./challenge")
    expected_base = 0x7F1234500000

    @dataclass
    class DummyLibc:
        sym: dict[str, int]

    session.rec.record_symbol_leak(
        "puts",
        expected_base + 0x80000,
        domain=RecordDomain.LIBC,
        source="got",
        confidence=0.90,
    )
    result = session.resolve.libc_base_from_elf_symbol(
        "puts",
        "puts",
        libc_elf=DummyLibc(sym={"puts": 0x80000}),
    )

    fact = session.registry.get_fact("libc.base")
    assert fact is not None
    assert fact.value == expected_base
    assert result.value == expected_base
    assert result.stored_fact is fact


def test_ret2libc_workflow_can_use_session_bound_libc_elf() -> None:
    session = CHun.process("./challenge")
    expected_base = 0x7F1234500000

    @dataclass
    class DummyLibc:
        sym: dict[str, int]

    session.bind_binaries(libc_elf=DummyLibc(sym={"puts": 0x80000}))
    session.rec.record_symbol_leak(
        "puts",
        expected_base + 0x80000,
        domain=RecordDomain.LIBC,
        source="got",
        confidence=0.90,
    )
    result = session.resolve.libc_base_from_elf_symbol("puts", "puts")

    fact = session.registry.get_fact("libc.base")
    assert fact is not None
    assert fact.value == expected_base
    assert result.value == expected_base
    assert result.stored_fact is fact


def test_blind_leak_to_dynelf_workflow_resolves_symbol_and_records_leaks() -> None:
    session = CHun.blind(lambda: object())
    memory = {0x601018: b"\x10\x20\x30\x40\x50\x60\x70\x80"}

    def leak_primitive(address: int, size: int = 8) -> bytes | None:
        return memory.get(address, b"\x00" * size)[:size]

    class FakeMemLeak:
        def __init__(self, func, search_range: int = 20, reraise: bool = True, relative: bool = False) -> None:
            self.func = func

        def raw(self, address: int, size: int) -> bytes | None:
            data = self.func(address)
            if data is None:
                return None
            return bytes(data)[:size]

    class FakeDynELF:
        def __init__(self, leak, pointer=None, elf=None, libcdb=True) -> None:
            self.leak = leak
            self.pointer = pointer

        def lookup(self, symb=None, lib=None):
            self.leak.raw(self.pointer, 8)
            return 0x7F1234567890

    result = session.resolve.symbol_via_dynelf(
        "system",
        leak_primitive=leak_primitive,
        pointer=0x601018,
        lib="libc",
        memleak_cls=FakeMemLeak,
        dynelf_cls=FakeDynELF,
    )

    fact = session.registry.get_fact("resolved.libc.system")
    assert fact is not None
    assert fact.value == 0x7F1234567890
    assert result.stored_fact is fact
    assert session.registry.get_observation("resolve.leak.0x601018") is not None
