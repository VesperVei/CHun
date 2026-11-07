from __future__ import annotations

from dataclasses import dataclass

from chun import CHun, RecordDomain


def test_smoke_ret2libc_workflow_uses_public_session_entrypoints() -> None:
    session = CHun.process("./challenge")

    @dataclass
    class DummyLibc:
        sym: dict[str, int]

    session.rec.record_symbol_leak(
        "puts",
        0x7F1234580000,
        domain=RecordDomain.LIBC,
        source="got",
    )
    result = session.resolve.libc_base_from_elf_symbol(
        "puts",
        "puts",
        libc_elf=DummyLibc(sym={"puts": 0x80000}),
    )

    assert result.aligned_base == 0x7F1234500000
    assert result.value == 0x7F1234500000
    assert session.registry.get_fact("libc.base").value == 0x7F1234500000


def test_smoke_blind_dynelf_workflow_uses_public_session_entrypoints() -> None:
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

    assert result.address == 0x7F1234567890
    assert session.registry.get_fact("resolved.libc.system").value == 0x7F1234567890
    assert session.registry.get_observation("resolve.leak.0x601018") is not None


def test_smoke_corefile_workflow_uses_public_session_entrypoints() -> None:
    session = CHun.process("./challenge")

    class DummyCore:
        path = "/tmp/core.1234"
        signal = 11
        fault_addr = 0x41414141
        pc = 0x6161616C
        sp = 0x7FFFFFFFE000
        registers = {"rip": 0x6161616C, "rsp": 0x7FFFFFFFE000}
        maps = [{"start": 0x400000, "end": 0x401000, "path": "/bin/challenge"}]

    session.crash.cyclic_finder = lambda _subseq: 72
    result = session.crash.analyze(DummyCore())

    assert result.pc == 0x6161616C
    assert session.registry.get_fact("crash.pc").value == 0x6161616C
    assert session.registry.get_fact("crash.cyclic_offset").value == 72
    assert session.registry.get_context("crash.signal").value == 11
