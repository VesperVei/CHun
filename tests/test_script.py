from __future__ import annotations

from dataclasses import dataclass, field
import re
from types import SimpleNamespace
from typing import Any

import pytest

from chun import CHun
from chun.core.errors import RetryableAttemptError, RetryExhaustedError
from chun.core.models import FactKind, RecordDomain
from chun.core.replay import VerificationResult
from chun.core.registry import EvidenceRegistry
from chun.core.models import TargetSpec
from chun.script.entry import _coerce_record_domain
from chun.script.gadget import _ScriptGadgetFacade
import chun.script as script_mod


@dataclass
class DummyDbg:
    attach_calls: list[dict[str, Any]] = field(default_factory=list)
    bind_runtime_calls: list[dict[str, Any]] = field(default_factory=list)

    def attach(
        self,
        io: object | None = None,
        script: str | None = None,
        *,
        api: bool = True,
    ) -> str:
        self.attach_calls.append({"io": io, "script": script, "api": api})
        return "attached"

    def bind_runtime(
        self, *, controller: object | None = None, pid: object | None = None
    ) -> None:
        self.bind_runtime_calls.append({"controller": controller, "pid": pid})


@dataclass
class DummyIO:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = field(
        default_factory=list
    )
    recv_values: list[bytes] = field(default_factory=list)
    recvline_values: list[bytes] = field(default_factory=list)
    clean_values: list[bytes] = field(default_factory=list)
    recvregex_match: object | None = None
    _recv_buffer: bytes = b""

    def send(self, data: bytes) -> None:
        self.calls.append(("send", (data,), {}))

    def sendline(self, data: bytes) -> None:
        self.calls.append(("sendline", (data,), {}))

    def sendafter(self, delim: bytes, data: bytes) -> None:
        self.calls.append(("sendafter", (delim, data), {}))

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        self.calls.append(("sendlineafter", (delim, data), {}))

    def recv(self, n: int = 4096) -> bytes:
        self.calls.append(("recv", (n,), {}))
        if not self._recv_buffer and self.recv_values:
            self._recv_buffer = self.recv_values.pop(0)
        if self._recv_buffer:
            chunk = self._recv_buffer[:n]
            self._recv_buffer = self._recv_buffer[n:]
            return chunk
        return b""

    def unrecv(self, data: bytes) -> None:
        self.calls.append(("unrecv", (data,), {}))
        self._recv_buffer = data + self._recv_buffer

    def can_recv(self, timeout: float = 0) -> bool:
        self.calls.append(("can_recv", (), {"timeout": timeout}))
        return bool(self._recv_buffer or self.recv_values)

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        self.calls.append(("recvuntil", (delim,), {"drop": drop}))
        return b"until"

    def recvline(self, keepends: bool = True) -> bytes:
        self.calls.append(("recvline", (), {"keepends": keepends}))
        if self.recvline_values:
            return self.recvline_values.pop(0)
        return b"line\n" if keepends else b"line"

    def recvregex(self, regex: bytes | str, capture: bool = False) -> object:
        self.calls.append(("recvregex", (regex,), {"capture": capture}))
        if self.recvregex_match is not None:
            return self.recvregex_match
        pattern = re.compile(regex) if isinstance(regex, str) else re.compile(regex)
        return pattern.search(b"0xdeadbeef")

    def interactive(self) -> None:
        self.calls.append(("interactive", (), {}))

    def clean(self, timeout: float | None = None) -> bytes:
        kwargs = {} if timeout is None else {"timeout": timeout}
        self.calls.append(("clean", (), kwargs))
        if self.clean_values:
            return self.clean_values.pop(0)
        return b"clean"


@dataclass
class DummySession:
    kind: str
    io: DummyIO = field(default_factory=DummyIO)
    dbg: DummyDbg = field(default_factory=DummyDbg)
    open_calls: int = 0
    close_calls: int = 0
    reconnect_calls: int = 0
    bind_binaries_calls: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.target = type("Target", (), {"kind": self.kind})()
        self.rec = SimpleNamespace(name="rec")
        self.fmt = SimpleNamespace(name="fmt")
        self.infer = SimpleNamespace(name="infer")
        self.resolve = SimpleNamespace(name="resolve")
        self.crash = SimpleNamespace(name="crash")
        self.elf = None
        self.libc_elf = None

    def open(self) -> DummySession:
        self.open_calls += 1
        return self

    def close(self) -> None:
        self.close_calls += 1

    def reconnect(self) -> None:
        self.reconnect_calls += 1

    def bind_binaries(self, *, elf: object | None = None, libc_elf: object | None = None) -> DummySession:
        self.bind_binaries_calls.append({"elf": elf, "libc_elf": libc_elf})
        self.elf = elf
        self.libc_elf = libc_elf
        return self

    @property
    def libc_base(self) -> int:
        fact = self.rec.get_fact("libc.base")
        if fact is None or not isinstance(fact.value, int):
            raise RuntimeError("libc.base 尚未推导，可能是多候选情况，请明确指定或编写爆破逻辑。")
        return fact.value

    @property
    def libc_version(self) -> str:
        fact = self.rec.get_fact("libc.version")
        if fact is None or not isinstance(fact.value, str):
            raise RuntimeError("libc.version 尚未确认。")
        return fact.value


@dataclass
class FakeELF:
    path: str
    libc: Any = None
    bits: int = 64
    bytes: int = 8
    little_endian: bool = True
    arch: str = "amd64"


@pytest.fixture
def fake_pwntools_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> dict[str, Any]:
    loaded: list[tuple[str, bool]] = []
    auto_libc = FakeELF("/glibc/libc.so.6")

    def fake_elf(path: str, checksec: bool = False) -> FakeELF:
        loaded.append((path, checksec))
        if path == "./challenge":
            return FakeELF(path, libc=auto_libc)
        return FakeELF(path)

    monkeypatch.setattr(script_mod, "ELF", fake_elf)
    tls = getattr(script_mod.context, "_tls", None)
    if isinstance(tls, dict) and "binary" in tls:
        del tls["binary"]
    if isinstance(tls, dict):
        tls["binary"] = None
    monkeypatch.setattr(script_mod.context, "log_level", "info")
    monkeypatch.setattr(script_mod.context, "terminal", [])
    monkeypatch.setenv("CHUN_CACHE_DIR", str(tmp_path / ".chun_cache"))
    monkeypatch.delenv("CHUN_NO_CACHE", raising=False)
    monkeypatch.delenv("CHUN_CLEAR_CACHE", raising=False)
    return {"loaded": loaded, "auto_libc": auto_libc}


def test_script_initializes_target_and_runtime_defaults(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script(
        "./challenge", host="example.com", port=31337, log_level="debug", terminal=()
    )

    assert isinstance(entry.target, TargetSpec)
    assert entry.target.binary == "./challenge"
    assert entry.target.host == "example.com"
    assert entry.target.port == 31337
    assert entry.target.argv == ["./challenge"]
    assert entry.elf.path == "./challenge"
    assert entry.libc is None
    assert entry.target.libc is None
    tls = getattr(script_mod.context, "_tls", None)
    if isinstance(tls, dict):
        assert tls.get("binary") is entry.elf
    else:
        assert getattr(tls, "binary", None) is entry.elf or script_mod.context.binary is entry.elf
    assert script_mod.context.log_level in ("debug", 10)
    assert script_mod.context.terminal == ["tmux", "splitw", "-h"]
    assert fake_pwntools_env["loaded"] == []


def test_script_start_uses_process_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        calls.append({"target": target, "transport": transport})
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script(
        "./challenge",
        host="example.com",
        port=31337,
        libc="./libc.so.6",
        argv=["./challenge", "--fast"],
        env={"MODE": "1"},
        cwd="/tmp/challenge",
    )

    result = entry.start()

    assert result is entry
    assert entry.session is session
    assert entry.io is session.io
    assert len(calls) == 1
    assert calls[0]["target"].kind == "process"
    assert calls[0]["target"].binary == "./challenge"
    assert calls[0]["target"].argv == ["./challenge", "--fast"]
    assert calls[0]["target"].libc == "./libc.so.6"
    assert calls[0]["target"].env == {"MODE": "1"}
    assert calls[0]["target"].cwd == "/tmp/challenge"
    assert calls[0]["target"].metadata == {
        "log_level": "debug",
        "terminal": ["tmux", "splitw", "-h"],
    }
    assert calls[0]["transport"].kind == "pwntools-tube"
    assert calls[0]["transport"].timeout is None
    assert entry.rec is session.rec
    assert entry.infer is session.infer
    assert entry.resolve is session.resolve
    assert entry.dbg is session.dbg
    assert entry.crash is session.crash


def test_script_start_uses_remote_when_remote_flag_is_set(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="remote")
    calls: list[dict[str, Any]] = []

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        calls.append({"target": target, "transport": transport})
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", True)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script(
        "./challenge",
        host="example.com",
        port=31337,
        libc="./libc.so.6",
        timeout=1.5,
    )

    result = entry.start()

    assert result is entry
    assert len(calls) == 1
    assert calls[0]["target"].kind == "remote"
    assert calls[0]["target"].host == "example.com"
    assert calls[0]["target"].port == 31337
    assert calls[0]["target"].binary == "./challenge"
    assert calls[0]["target"].libc == "./libc.so.6"
    assert calls[0]["target"].metadata == {
        "log_level": "info",
        "terminal": ["tmux", "splitw", "-h"],
    }
    assert calls[0]["transport"].kind == "pwntools-tube"
    assert calls[0]["transport"].timeout == 1.5


def test_script_gdb_attaches_for_local_process(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        assert target.kind == "process"
        assert target.binary == "./challenge"
        assert transport.kind == "pwntools-tube"
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")
    entry.start()
    result = entry.gdb("b *main\nc")

    assert result == "attached"
    assert session.dbg.attach_calls == [
        {"io": None, "script": "b *main\nc", "api": True}
    ]


def test_script_debug_starts_process_under_gdb_without_keypress_pause(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    class FakeController:
        pass

    class FakeDebugTube(DummyIO):
        def __init__(self) -> None:
            super().__init__()
            self.gdb = FakeController()

    created: list[dict[str, Any]] = []
    debug_tube = FakeDebugTube()

    def fake_debug(
        argv: list[str],
        gdbscript: str | None = None,
        exe: str | None = None,
        env: dict[str, str] | None = None,
        api: bool = False,
        cwd: str | None = None,
    ) -> FakeDebugTube:
        created.append(
            {
                "argv": argv,
                "gdbscript": gdbscript,
                "exe": exe,
                "env": env,
                "api": api,
                "cwd": cwd,
            }
        )
        return debug_tube

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(script_mod.gdb, "debug", fake_debug)

    entry = CHun.script(
        "./challenge",
        argv=["./challenge", "--fast"],
        env={"MODE": "1"},
        cwd="/tmp/challenge",
    )
    result = entry.debug("b *main\nc")

    assert result is entry
    assert created == [
        {
            "argv": ["./challenge", "--fast"],
            "gdbscript": "b *main\nc",
            "exe": "./challenge",
            "env": {"MODE": "1"},
            "api": True,
            "cwd": "/tmp/challenge",
        }
    ]
    assert entry.dbg._controller is debug_tube.gdb
    assert entry.sendline(b"PING") is None
    assert debug_tube.calls[-1] == ("sendline", (b"PING",), {})


def test_script_debug_falls_back_to_start_when_gdb_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")

    assert entry.debug("b *main") is entry
    assert entry.session is session


def test_script_fmt_facade_forwards_to_session_and_enables_loginfo_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_find_offset(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "offset"

    session.fmt = SimpleNamespace(find_offset=fake_find_offset, marker="fmt-service")

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.marker == "fmt-service"
    assert entry.fmt.find_offset(max_slots=8) == "offset"
    assert calls == [{"max_slots": 8, "loginfo": True}]


def test_script_fmt_facade_respects_explicit_loginfo_override(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_find_offset(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "offset"

    session.fmt = SimpleNamespace(find_offset=fake_find_offset)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.find_offset(loginfo=False) == "offset"
    assert calls == [{"loginfo": False}]


def test_script_fmt_facade_exposes_set_offset_for_ide_completion(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_set_offset(offset: Any, *, overwrite: bool = True, source: str = "fmt.service") -> str:
        calls.append({"offset": offset, "overwrite": overwrite, "source": source})
        return "stored"

    session.fmt = SimpleNamespace(set_offset=fake_set_offset)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.set_offset(6, source="unit-test") == "stored"
    assert calls == [{"offset": 6, "overwrite": True, "source": "unit-test"}]


def test_script_fmt_facade_enables_compare_write_loginfo_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_compare_write(*args: Any, **kwargs: Any) -> str:
        calls.append({"args": args, "kwargs": kwargs})
        return "comparison"

    session.fmt = SimpleNamespace(compare_write=fake_compare_write)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.compare_write(0x6010A0, 0x601018) == "comparison"
    assert calls == [
        {
            "args": (0x6010A0, 0x601018),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": None,
                "task_policy": script_mod.FmtTaskPolicy.PACKED,
                "data_offset": None,
                "buflen": None,
                "end": b"\n",
                "show_hex": False,
                "loginfo": True,
            },
        }
    ]


def test_script_fmt_write_builder_reuses_arguments_for_info_and_send(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    compare_calls: list[dict[str, Any]] = []
    plan_calls: list[dict[str, Any]] = []
    execute_calls: list[dict[str, Any]] = []
    recvuntil_calls: list[tuple[bytes, bool]] = []
    plan = object()

    def fake_compare_write(*args: Any, **kwargs: Any) -> str:
        compare_calls.append({"args": args, "kwargs": kwargs})
        return "info"

    def fake_plan_write(*args: Any, **kwargs: Any) -> object:
        plan_calls.append({"args": args, "kwargs": kwargs})
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 16,
                steps=(SimpleNamespace(padding=0),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        execute_calls.append({"args": args, "kwargs": kwargs})
        return "sent"

    fake_io = SimpleNamespace(
        recvuntil=lambda delim, drop=False: recvuntil_calls.append((delim, drop)) or delim
    )
    session.fmt = SimpleNamespace(
        compare_write=fake_compare_write,
        plan_write=fake_plan_write,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=fake_io),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    action = entry.fmt.write(
        0x6010A0,
        0x601018,
        b"name: ",
        6,
        strategy="byte",
        task_policy="by_atom",
        end=b" ",
    )

    assert action.info(48, show_hex=True) == "info"
    assert action.send(48, show_hex=True) == "sent"
    assert compare_calls == [
        {
            "args": (0x6010A0, 0x601018),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_ATOM,
                "data_offset": None,
                "buflen": 48,
                "end": b" ",
                "show_hex": True,
                "loginfo": False,
            },
        }
    ]
    assert recvuntil_calls == [(b"name: ", False)]
    assert plan_calls == [
        {
            "args": (0x6010A0, 0x601018),
            "kwargs": {
                "strategy": script_mod.FmtWriteStrategy.BYTE,
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_ATOM,
                "data_offset": None,
            },
        }
    ]
    assert execute_calls == [
        {
            "args": (plan,),
            "kwargs": {
                "offset": 6,
                "data_offset": None,
                "receive": False,
                "end": b" ",
            },
        }
    ]


def test_script_fmt_facade_enables_compare_writes_loginfo_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_compare_writes(*args: Any, **kwargs: Any) -> str:
        calls.append({"args": args, "kwargs": kwargs})
        return "comparison"

    session.fmt = SimpleNamespace(compare_writes=fake_compare_writes)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    writes = {0x6010A0: 0x601018, 0x6010B0: 0x601028}
    assert entry.fmt.compare_writes(writes) == "comparison"
    assert calls == [
        {
            "args": (writes,),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": None,
                "task_policy": script_mod.FmtTaskPolicy.PACKED,
                "data_offset": None,
                "buflen": None,
                "end": b"\n",
                "show_hex": False,
                "loginfo": True,
            },
        }
    ]


def test_script_fmt_writes_builder_reuses_arguments_for_info_and_send(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    compare_calls: list[dict[str, Any]] = []
    plan_calls: list[dict[str, Any]] = []
    execute_calls: list[dict[str, Any]] = []
    recvuntil_calls: list[tuple[bytes, bool]] = []
    plan = object()

    def fake_compare_writes(*args: Any, **kwargs: Any) -> str:
        compare_calls.append({"args": args, "kwargs": kwargs})
        return "info"

    def fake_plan_writes(*args: Any, **kwargs: Any) -> object:
        plan_calls.append({"args": args, "kwargs": kwargs})
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 16,
                steps=(SimpleNamespace(padding=0),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        execute_calls.append({"args": args, "kwargs": kwargs})
        return "sent"

    fake_io = SimpleNamespace(
        recvuntil=lambda delim, drop=False: recvuntil_calls.append((delim, drop)) or delim
    )
    session.fmt = SimpleNamespace(
        compare_writes=fake_compare_writes,
        plan_writes=fake_plan_writes,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=fake_io),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    writes = {0x6010A0: 0x601018, 0x6010B0: 0x601028}
    action = entry.fmt.writes(
        writes,
        b"choice> ",
        6,
        strategy="short",
        task_policy="by_target",
        end=b" ",
    )

    assert action.info(96, show_hex=True) == "info"
    assert action.send(96, show_hex=True) == "sent"
    assert compare_calls == [
        {
            "args": (writes,),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_TARGET,
                "data_offset": None,
                "buflen": 96,
                "end": b" ",
                "show_hex": True,
                "loginfo": True,
            },
        }
    ]
    assert recvuntil_calls == [(b"choice> ", False)]
    assert plan_calls == [
        {
            "args": (writes,),
            "kwargs": {
                "strategy": script_mod.FmtWriteStrategy.SHORT,
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_TARGET,
                "data_offset": None,
            },
        }
    ]
    assert execute_calls == [
        {
            "args": (plan,),
            "kwargs": {
                "offset": 6,
                "data_offset": None,
                "receive": False,
                "end": b" ",
            },
        }
    ]


def test_script_fmt_send_logs_error_when_send_len_exceeds_buflen(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    errors: list[str] = []
    plan = SimpleNamespace(offset=6)

    def fake_plan_write(*args: Any, **kwargs: Any) -> object:
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 32,
                steps=(SimpleNamespace(padding=0),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        return "sent"

    session.fmt = SimpleNamespace(
        plan_write=fake_plan_write,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=SimpleNamespace(recvuntil=lambda *_args, **_kwargs: b"")),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    monkeypatch.setattr(script_mod.log, "error", errors.append)

    entry = CHun.script("./challenge").start()
    assert entry.fmt.write(0x6010A0, 0x601018).send(16) == "sent"
    assert errors == ["fmt 发送长度 33B 超过 buflen=16B，仍继续发送。"]


def test_script_fmt_send_logs_warning_for_high_pad_time(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    warnings: list[str] = []
    plan = SimpleNamespace(offset=6)

    def fake_plan_write(*args: Any, **kwargs: Any) -> object:
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 8,
                steps=(SimpleNamespace(padding=0x1000),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        return "sent"

    session.fmt = SimpleNamespace(
        plan_write=fake_plan_write,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=SimpleNamespace(recvuntil=lambda *_args, **_kwargs: b"")),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    assert entry.fmt.write(0x6010A0, 0x601018).send() == "sent"
    assert warnings == ["fmt 的 pad_time 为 HIGH（max_pad=4096），服务端可能变慢或超时。"]


def test_script_gdb_warns_for_remote_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="remote")
    warnings: list[str] = []

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        assert target.kind == "remote"
        assert (target.host, target.port) == ("example.com", 31337)
        assert transport.kind == "pwntools-tube"
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", True)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge", host="example.com", port=31337)
    entry.start()
    result = entry.gdb("b *main")

    assert result is None
    assert session.dbg.attach_calls == []
    assert warnings == ["当前为 REMOTE 模式，跳过 GDB attach。"]


def test_script_remote_gdb_keeps_process_log_level(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="remote")
    calls: list[dict[str, Any]] = []

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        calls.append({"target": target, "transport": transport})
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", True)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", host="example.com", port=31337)
    entry.start()

    assert calls[0]["target"].metadata["log_level"] == "debug"


def test_script_session_property_requires_start(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge")

    with pytest.raises(RuntimeError):
        _ = entry.session

    with pytest.raises(RuntimeError):
        _ = entry.rec


def test_script_uses_explicit_libc_when_provided(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge", libc="./libc.so.6")

    assert entry.libc.path == "./libc.so.6"
    assert entry.target.libc == "./libc.so.6"
    assert fake_pwntools_env["loaded"] == []


def test_script_does_not_auto_detect_local_libc_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge")

    assert entry.libc is None
    assert entry.target.libc is None


def test_script_auto_local_libc_is_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge", auto_local_libc=True)

    libc = entry.libc
    assert libc is not None
    assert libc.path == "/glibc/libc.so.6"
    assert entry.target.libc == "/glibc/libc.so.6"


def test_script_start_binds_default_elf_and_libc_to_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", libc="./libc.so.6")
    entry.start()

    assert session.bind_binaries_calls == [{"elf": entry.elf, "libc_elf": entry.libc}]


def test_script_start_links_elf_cache_to_specified_libc(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script(
        "./challenge",
        libc="./libc.so.6",
        cache_dir=str(tmp_path / "cache"),
    ).start()

    elf_record = entry._cache.get_elf_record(entry.elf.path)
    assert elf_record is not None
    assert elf_record.get("linked_libc_path") == "./libc.so.6"
    assert isinstance(elf_record.get("linked_libc_sha256"), str)
    assert elf_record.get("linked_libc_source") == "specified"


def test_script_start_is_chainable(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.session is session
    assert entry.rec is session.rec
    assert entry.resolve is session.resolve


def test_script_exposes_libc_fact_shortcuts(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    registry = EvidenceRegistry()
    registry.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    registry.record_fact(
        "libc.version",
        "glibc-test",
        kind=FactKind.VERSION,
        domain=RecordDomain.LIBC,
    )
    session.rec = registry

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.libc_base == 0x7F0000000000
    assert entry.libc_version == "glibc-test"


def test_script_libc_base_raises_when_missing(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(RuntimeError, match="libc.base 尚未推导"):
        _ = entry.libc_base


def test_script_context_manager_opens_and_closes_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    with CHun.script("./challenge") as entry:
        assert entry.session is session

    assert session.open_calls == 1
    assert session.close_calls == 1


def test_script_explicit_io_methods_and_aliases_forward_to_io(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        assert target.kind == "process"
        assert transport.kind == "pwntools-tube"
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")
    entry.start()
    session.io.recv_values = [b"recv"]

    entry.send(b"A")
    entry.sendline(b"B")
    entry.sendafter(b":", b"C")
    entry.sendlineafter(b">", b"D")
    assert entry.recv(32) == b"recv"
    assert entry.recvuntil(b"!", drop=True) == b"until"
    assert entry.recvline(keepends=False) == b"line"
    entry.interactive()

    entry.sl(b"E")
    entry.sa(b"name", b"F")
    entry.sla(b"menu", b"G")
    assert entry.ru(b"done") == b"until"
    assert entry.rl() == b"line\n"
    entry.ia()

    assert session.io.calls == [
        ("send", (b"A",), {}),
        ("sendline", (b"B",), {}),
        ("sendafter", (b":", b"C"), {}),
        ("sendlineafter", (b">", b"D"), {}),
        ("recv", (32,), {}),
        ("recvuntil", (b"!",), {"drop": True}),
        ("recvline", (), {"keepends": False}),
        ("interactive", (), {}),
        ("sendline", (b"E",), {}),
        ("sendafter", (b"name", b"F"), {}),
        ("sendlineafter", (b"menu", b"G"), {}),
        ("recvuntil", (b"done",), {"drop": False}),
        ("recvline", (), {"keepends": True}),
        ("interactive", (), {}),
    ]


def test_script_replay_sugar_uses_prefix_before_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    captured: dict[str, Any] = {}

    checkpoint_entry = SimpleNamespace(event_seq=42)

    class _RecStub:
        replay = SimpleNamespace(
            checkpoints={"io_node_1": checkpoint_entry},
            blob_store=object(),
            cursor_seq=99,
        )

        def run_replay(self, **kwargs: Any) -> VerificationResult:
            captured.update(kwargs)
            old_level = script_mod.context.log_level
            try:
                script_mod.context.log_level = "error"
                expected_error_level = script_mod.context.log_level
                assert kwargs["predicate"](b"xxokyy") is True
                assert script_mod.context.log_level == expected_error_level
            finally:
                script_mod.context.log_level = old_level
            return VerificationResult(
                run_id="run-id",
                ok=True,
                reason="predicate_pass",
            )

    session.rec = _RecStub()
    session.make_replay_session = lambda: object()  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    messages: list[str] = []
    monkeypatch.setattr(script_mod.log, "info", messages.append)

    entry = CHun.script("./challenge").start()
    result = entry.replay(
        b"7",
        checkpoint="io_node_1",
        expected=b"ok",
        show_recv=True,
        capture_replay_registry=True,
    )

    assert result.ok is True
    assert captured["probe"] == b"7"
    assert captured["end_seq_exclusive"] == 42
    assert captured["capture_replay_registry"] is True
    assert captured["session_factory"] is session.make_replay_session
    assert any(line.startswith("[replay recv] len=") for line in messages)
    assert any("00000000" in line for line in messages)


def test_script_replay_sugar_defaults_to_current_position(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    captured: dict[str, Any] = {}

    class _RecStub:
        replay = SimpleNamespace(
            checkpoints={},
            blob_store=object(),
            cursor_seq=73,
        )

        def run_replay(self, **kwargs: Any) -> VerificationResult:
            captured.update(kwargs)
            assert kwargs["predicate"](b"anything") is True
            return VerificationResult(
                run_id="run-id",
                ok=True,
                reason="predicate_pass",
            )

    session.rec = _RecStub()
    session.make_replay_session = lambda: object()  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    result = entry.replay(b"7")

    assert result.ok is True
    assert captured["probe"] == b"7"
    assert captured["end_seq_exclusive"] == 73


def test_script_replay_sugar_supports_callable_with_multi_args_and_kwargs(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    replay_session = DummySession(kind="process")
    replay_session.rec = EvidenceRegistry()
    replay_session.io.recv_values = [b"recv"]
    registry = EvidenceRegistry()
    registry.append_event("sendline", payload=b"warmup\n")
    session.rec = registry
    session.make_replay_session = lambda: replay_session  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    def _menu(choice: int) -> None:
        s.sla(b"> ", str(choice).encode())

    def _show(index: int, suffix: bytes, *, with_menu: bool = True) -> None:
        if with_menu:
            _menu(3)
        s.sla(b"Index: ", str(index).encode() + suffix)

    marker = object()
    had_global_s = "s" in globals()
    old_global_s = globals().get("s", marker)
    globals()["s"] = marker
    try:
        entry = CHun.script("./challenge").start()
        result = entry.replay(
            _show,
            7,
            b"!",
            action_kwargs={"with_menu": True},
            expected=b"recv",
            show_recv=True,
        )
    finally:
        if had_global_s:
            globals()["s"] = old_global_s
        else:
            globals().pop("s", None)

    assert result.ok is True
    assert result.reason == "predicate_pass"
    assert session.io.calls == []
    assert replay_session.io.calls == [
        ("sendline", (b"warmup\n",), {}),
        ("sendlineafter", (b"> ", b"3"), {}),
        ("sendlineafter", (b"Index: ", b"7!"), {}),
        ("recv", (4096,), {}),
    ]


def test_script_replay_sugar_raises_for_missing_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = SimpleNamespace(
        replay=SimpleNamespace(checkpoints={}, blob_store=object(), cursor_seq=0),
    )
    session.make_replay_session = lambda: object()  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    with pytest.raises(KeyError, match="replay checkpoint 不存在：io_node_1"):
        entry.replay(b"7", checkpoint="io_node_1")


def test_script_recv_leak_reads_raw_bytes_and_records_symbol_leak(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"\xa0\x0a\x58\x34\x12\x7f"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    messages: list[str] = []
    monkeypatch.setattr(script_mod.log, "success", messages.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("puts", delim=b"puts: ")

    assert value == 0x7F1234580AA0
    observation = session.rec.get_observation("puts")
    assert observation is not None
    assert observation.value == value
    assert observation.domain == RecordDomain.LIBC
    assert observation.source == "leak"
    assert messages == [f"Leak [puts] captured: {hex(value)}"]
    assert session.io.calls == [
        ("recvuntil", (b"puts: ",), {"drop": False}),
        ("recv", (6,), {}),
    ]


def test_script_recv_leak_reads_hex_and_applies_offset(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0x7f1234580aa0\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "puts",
        delim="puts: ",
        mode="hex",
        offset=0x0AA0,
        source="printf",
    )

    assert value == 0x7F1234580000
    observation = session.rec.get_observation("puts")
    assert observation is not None
    assert observation.value == value
    assert observation.source == "printf"
    assert session.io.calls[0] == ("recvuntil", ("puts: ",), {"drop": False})
    assert session.io.calls.count(("recv", (1,), {})) == 15
    assert session.io.calls[-1] == ("unrecv", (b"\n",), {})


def test_script_recv_leak_extracts_first_hex_token_from_dirty_line(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0x7f1234580aa0 saved-rbp=0x7ffe3748e060\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("puts", delim="puts: ", mode="hex")

    assert value == 0x7F1234580AA0
    assert warnings == []
    assert session.io.calls[0] == ("recvuntil", ("puts: ",), {"drop": False})
    assert session.io.calls.count(("recv", (1,), {})) == 15
    assert session.io.calls[-1] == ("unrecv", (b" ",), {})


def test_script_recv_leak_supports_hex_index_selection(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0x7f1234580aa0 0x7ffe3748e060\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("saved_rbp", delim="puts: ", mode="hex", index=1)

    assert value == 0x7FFE3748E060
    assert warnings == [
        "共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060|默认选 0x7ffe3748e060"
    ]


def test_script_recv_leak_supports_hex_delim_end_window(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()

    def fake_recvuntil(delim: bytes, drop: bool = False) -> bytes:
        session.io.calls.append(("recvuntil", (delim,), {"drop": drop}))
        if delim == b"Hello,":
            return b"Hello,"
        if delim == b" world":
            return b"0x7f1234580aa0 and 0x7ffe3748e060 world"
        return b"until"

    session.io.recvuntil = fake_recvuntil

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "saved_rbp",
        b"Hello,",
        mode="hex",
        delim_end=b" world",
        index=1,
    )

    assert value == 0x7FFE3748E060
    assert warnings == [
        "共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060|默认选 0x7ffe3748e060"
    ]
    assert session.io.calls == [
        ("recvuntil", (b"Hello,",), {"drop": False}),
        ("recvuntil", (b" world",), {"drop": True}),
    ]


def test_script_recv_leak_rejects_out_of_range_hex_index(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0x7f1234580aa0 0x7ffe3748e060\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(
        ValueError,
        match=r"共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060，index=2 越界。",
    ):
        entry.recv_leak("puts", mode="hex", index=2)


def test_script_recv_leak_rejects_delim_end_with_regex(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(ValueError, match="delim_end 和 regex 不能同时提供。"):
        entry.recv_leak("puts", delim_end=b"!", regex=rb"(0x[0-9a-f]+)", mode="hex")


def test_script_recv_leak_reads_regex_capture_and_allows_custom_domain(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvregex_match = re.search(rb"leak=(0x[0-9a-f]+)", b"leak=0x401000")
    assert session.io.recvregex_match is not None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    messages: list[str] = []
    monkeypatch.setattr(script_mod.log, "success", messages.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "main",
        regex=rb"leak=(0x[0-9a-f]+)",
        mode="hex",
        domain=RecordDomain.ELF,
    )

    assert value == 0x401000
    observation = session.rec.get_observation("main")
    assert observation is not None
    assert observation.value == value
    assert observation.domain == RecordDomain.ELF
    assert messages == [f"Leak [main] captured: {hex(value)}"]
    assert session.io.calls == [
        ("recvregex", (rb"leak=(0x[0-9a-f]+)",), {"capture": True}),
    ]


def test_script_recv_leak_accepts_string_domain_alias_without_models_import(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0x401000\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("main", mode="hex", domain="elf")

    assert value == 0x401000
    observation = session.rec.get_observation("main")
    assert observation is not None
    assert observation.domain == RecordDomain.ELF


def test_coerce_record_domain_accepts_string_aliases() -> None:
    assert _coerce_record_domain("elf") == RecordDomain.ELF
    assert _coerce_record_domain("LIBC") == RecordDomain.LIBC


def test_script_recv_leak_supports_regex_without_capture_group(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvregex_match = re.search(rb"0x[0-9a-f]{8}", b"0xdeadbeef\x12")
    assert session.io.recvregex_match is not None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("canary", regex=rb"0x[0-9a-f]{8}", mode="hex")

    assert value == 0xDEADBEEF
    assert session.io.calls == [
        ("recvregex", (rb"0x[0-9a-f]{8}",), {"capture": True}),
    ]


def test_script_recv_leak_supports_regex_with_full_capture_group(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvregex_match = re.search(rb"(0x[0-9a-f]{8})", b"0xdeadbeef\x12")
    assert session.io.recvregex_match is not None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("canary", regex=rb"(0x[0-9a-f]{8})", mode="hex")

    assert value == 0xDEADBEEF
    assert session.io.calls == [
        ("recvregex", (rb"(0x[0-9a-f]{8})",), {"capture": True}),
    ]


def test_script_recv_leak_regex_capture_remains_pure_recvregex(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvregex_match = re.search(rb"(0x[0-9a-f]+)", b"0xa")
    assert session.io.recvregex_match is not None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("canary", regex=rb"(0x[0-9a-f]+)", mode="hex")

    assert value == 0xA
    assert session.io.calls == [
        ("recvregex", (rb"(0x[0-9a-f]+)",), {"capture": True}),
    ]


def test_script_recv_leak_reports_partial_regex_capture_in_hex_mode(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvregex_match = re.search(rb"0x([0-9a-f])", b"0x5")
    assert session.io.recvregex_match is not None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(
        ValueError,
        match="regex 已命中，但其整体匹配或第一个捕获组未产出完整的 0x... 十六进制地址",
    ):
        entry.recv_leak("canary", regex=rb"0x([0-9a-f])", mode="hex")


def test_script_recv_leak_rejects_regex_index_without_recv_mode(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(
        ValueError,
        match="recv=False 且提供 regex 时，index 仅支持 0；如需多命中选择，请设置 recv=True。",
    ):
        entry.recv_leak("canary", regex=rb"0x[0-9a-f]{8}", mode="hex", index=1)


def test_script_recv_leak_supports_regex_with_explicit_recv_mode(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"canary => 0xdeadbeef\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "canary",
        regex=rb"(0x[0-9a-f]+)",
        mode="hex",
        recv=True,
    )

    assert value == 0xDEADBEEF
    assert session.io.calls[0] == ("recv", (4096,), {})
    assert ("clean", (), {"timeout": 0}) in session.io.calls


def test_script_recv_leak_supports_regex_recv_mode_with_hex_index_selection(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0x11111111.0x22222222.0x33333333\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "canary",
        regex=rb"0x[0-9a-f]{8}",
        mode="hex",
        recv=True,
        index=1,
    )

    assert value == 0x22222222
    assert warnings == [
        "共匹配到 3 个地址：0x11111111,0x22222222,0x33333333|默认选 0x22222222"
    ]
    assert session.io.calls[0] == ("recv", (4096,), {})
    assert ("clean", (), {"timeout": 0}) in session.io.calls


def test_script_recv_leak_recv_mode_collects_split_burst_and_honors_index(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0xffc177d8", b".0x5d8e4d00.0x804a010\x05$"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("canary", mode="hex", recv=True, index=1)

    assert value == 0x5D8E4D00
    assert warnings == [
        "共匹配到 3 个地址：0xffc177d8,0x5d8e4d00,0x804a010|默认选 0x5d8e4d00"
    ]
    assert session.io.calls.count(("recv", (4096,), {})) == 2
    assert ("clean", (), {"timeout": 0}) in session.io.calls


def test_script_recv_leak_streams_split_hex_without_regex(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"0xae793900\x82\x04\x08 $"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("canary", mode="hex")

    assert value == 0xAE793900
    assert session.io.calls.count(("recv", (1,), {})) == 11
    assert session.io.calls[-1] == ("unrecv", (b"\x82",), {})


def test_script_recv_leak_supports_direct_stream_read_without_delim_or_regex(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"\x78\x56\x34\x12"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    entry.elf.bits = 32
    entry.elf.bytes = 4
    value = entry.recv_leak("puts")

    assert value == 0x12345678
    observation = session.rec.get_observation("puts")
    assert observation is not None
    assert observation.value == value
    assert session.io.calls == [
        ("recv", (4,), {}),
    ]


def test_script_recv_leak_validates_delim_and_regex_exclusivity(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(ValueError):
        entry.recv_leak("puts", delim=b":", regex=rb"(.*)")


def test_script_getattr_falls_back_to_io_only(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")
    entry.start()

    assert entry.clean() == b"clean"
    assert session.io.calls == [("clean", (), {})]

    with pytest.raises(AttributeError):
        _ = entry._hidden


def test_script_gadget_sugar_parses_register_token_in_order(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[tuple[object, tuple[str, ...]]] = []

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, image: object) -> None:
            self._image = image

        def find_gadget(self, items: list[str]) -> FakeGadget:
            calls.append((self._image, tuple(items)))
            return FakeGadget(0x401234)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.gadget["rsi_r15"] == 0x401234
    assert calls == [(entry.elf.materialize_raw(), ("pop rsi", "pop r15", "ret"))]


def test_script_gadget_sugar_supports_leave_and_ret(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[tuple[str, ...]] = []

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, items: list[str]) -> FakeGadget:
            calls.append(tuple(items))
            return FakeGadget(0x401000 + len(calls))

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.gadget["ret"] == 0x401001
    assert entry.gadget["leave"] == 0x401002
    assert calls == [("ret",), ("leave", "ret")]


def test_script_elf_sym_symbol_symbols_share_cache_mapping(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    class RichFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x400000
            self.pie = False
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False
            self.entry = 0x401000
            self.symbols = {"main": 0x401080}
            self.sym = self.symbols
            self.got = {}
            self.plt = {}
            self.sections = {}

    def rich_loader(path: str, checksec: bool = False) -> RichFakeELF:
        _ = checksec
        return RichFakeELF(path)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", rich_loader)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()

    assert entry.elf.sym["main"] == 0x401080
    assert entry.elf.symbol["main"] == 0x401080
    assert entry.elf.symbols["main"] == 0x401080

    record = entry._cache.get_elf_record(entry.elf.path)
    assert record is not None
    symbols = record.get("symbols")
    assert isinstance(symbols, dict)
    assert symbols.get("main") == 0x401080


def test_script_pie_elf_lookups_use_runtime_elf_base_when_available(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.rec.record_fact("elf.base", 0x555555554000)

    class PieFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x555555554000
            self.pie = True
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False
            self.entry = 0x1000
            self.symbols = {"main": 0x1234}
            self.sym = self.symbols
            self.got = {"puts": 0x4018}
            self.plt = {"puts": 0x1030}
            self.sections = {".bss": 0x5000}

    def pie_loader(path: str, checksec: bool = False) -> PieFakeELF:
        _ = checksec
        return PieFakeELF(path)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", pie_loader)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()

    assert entry.elf.sym["main"] == 0x555555555234
    assert entry.elf.got["puts"] == 0x555555558018
    assert entry.elf.plt["puts"] == 0x555555555030
    assert entry.elf.sections[".bss"] == 0x555555559000
    assert entry.elf_base == 0x555555554000

    record = entry._cache.get_elf_record(entry.elf.path)
    assert record is not None
    assert record["address_mode"] == "offset"
    assert record["symbols"]["main"] == 0x1234
    assert record["got"]["puts"] == 0x4018
    assert record["plt"]["puts"] == 0x1030
    assert record["sections"][".bss"] == 0x5000


def test_script_pie_elf_lookups_warn_and_fallback_to_offset_without_elf_base(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    warnings: list[str] = []

    class PieFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x555555554000
            self.pie = True
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False
            self.entry = 0x1000
            self.symbols = {"main": 0x1234}
            self.sym = self.symbols
            self.got = {"puts": 0x4018}
            self.plt = {}
            self.sections = {}

    def pie_loader(path: str, checksec: bool = False) -> PieFakeELF:
        _ = checksec
        return PieFakeELF(path)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", pie_loader)
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()

    assert entry.elf.sym["main"] == 0x1234
    assert entry.elf.got["puts"] == 0x4018
    assert warnings == [
        "检测到 PIE，但尚未记录 elf.base；当前返回 symbols['main'] 的静态 offset。",
        "检测到 PIE，但尚未记录 elf.base；当前返回 got['puts'] 的静态 offset。",
    ]


def test_script_gadget_non_pie_offset_result_is_normalized_to_vaddr_and_cached(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    class BaseFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x400000
            self.pie = False
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False

    auto_libc = BaseFakeELF("/glibc/libc.so.6")

    def base_loader(path: str, checksec: bool = False) -> BaseFakeELF:
        _ = checksec
        if path == "./challenge":
            return BaseFakeELF(path, libc=auto_libc)
        return BaseFakeELF(path)

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class OffsetROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, _items: list[str]) -> FakeGadget:
            # 模拟某些场景下 ROP 返回 offset，而非 vaddr。
            return FakeGadget(0x1234)

    class BombROP:
        def __init__(self, _image: object) -> None:
            raise AssertionError("ROP should not be initialized on gadget cache hit")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", base_loader)
    monkeypatch.setattr(script_mod, "ROP", OffsetROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    assert entry.gadget["rdi"] == 0x401234

    monkeypatch.setattr(script_mod, "ROP", BombROP)
    assert entry.gadget["rdi"] == 0x401234


def test_script_gadget_sugar_supports_libc_source_and_runtime_base(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.rec.record_fact("libc.base", 0x7F1200000000)
    calls: list[object] = []

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, image: object) -> None:
            self._image = image

        def find_gadget(self, items: list[str]) -> FakeGadget:
            _ = items
            calls.append(self._image)
            return FakeGadget(0x1234)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", libc="./libc.so.6").start()

    assert entry.gadget["libc:rdi"] == 0x7F1200001234
    assert calls == [entry.libc.materialize_raw()]


def test_script_gadget_pie_uses_runtime_elf_base(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.rec.record_fact("elf.base", 0x555555554000)

    class PieFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x555555554000
            self.pie = True
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False

    def pie_loader(path: str, checksec: bool = False) -> PieFakeELF:
        _ = checksec
        return PieFakeELF(path)

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, _items: list[str]) -> FakeGadget:
            return FakeGadget(0x1234)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", pie_loader)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()

    assert entry.gadget["rdi"] == 0x555555555234


def test_script_gadget_pie_warns_and_falls_back_to_offset_without_elf_base(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    warnings: list[str] = []

    class PieFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x555555554000
            self.pie = True
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False

    def pie_loader(path: str, checksec: bool = False) -> PieFakeELF:
        _ = checksec
        return PieFakeELF(path)

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, _items: list[str]) -> FakeGadget:
            return FakeGadget(0x1234)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", pie_loader)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()

    assert entry.gadget["rdi"] == 0x1234
    assert warnings == ["检测到 PIE，但尚未记录 elf.base；当前返回 gadget 的静态 offset。"]


def test_script_gadget_sugar_rejects_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    class FakeROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, items: list[str]) -> object:
            _ = items
            return object()

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(ValueError):
        _ = entry.gadget["libc:"]


def test_script_gadget_cache_hit_skips_rop_init(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    class BombROP:
        def __init__(self, _image: object) -> None:
            raise AssertionError("ROP should not be initialized on cache hit")

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", BombROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    version = _ScriptGadgetFacade._pwntools_version()
    entry._cache.set_gadget_query(
        entry.elf.path,
        source="elf",
        token="elf:pop rdi; ret",
        arch=entry.elf.arch,
        bits=entry.elf.bits,
        pwntools_version=version,
        found=True,
        value=0x401111,
        address_mode="vaddr",
    )

    assert entry.gadget["rdi"] == 0x401111


def test_script_gadget_not_found_is_cached(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")
    init_count = {"value": 0}

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    class MissROP:
        def __init__(self, _image: object) -> None:
            init_count["value"] += 1

        def find_gadget(self, _items: list[str]) -> object | None:
            return None

    class BombROP:
        def __init__(self, _image: object) -> None:
            raise AssertionError("ROP should not be initialized after not-found cache")

        def find_gadget(self, _items: list[str]) -> object | None:
            return None

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", MissROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    with pytest.raises(LookupError):
        _ = entry.gadget["ret"]
    assert init_count["value"] == 1

    monkeypatch.setattr(script_mod, "ROP", BombROP)
    with pytest.raises(LookupError):
        _ = entry.gadget["ret"]


def test_script_gadget_not_found_suggests_compatible_pop_ret_gadgets(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    class FakeGadget:
        def __init__(self, address: int, insns: list[str]) -> None:
            self.address = address
            self.insns = insns

    class MissROP:
        def __init__(self, _image: object) -> None:
            self.gadgets = {
                0x401200: FakeGadget(0x401200, ["pop rbp", "pop r14", "pop r15", "ret"]),
                0x401100: FakeGadget(0x401100, ["pop rbp", "pop r14", "pop r12", "pop r13", "ret"]),
                0x401000: FakeGadget(0x401000, ["pop rsi", "ret"]),
                0x401300: FakeGadget(0x401300, ["pop rbp", "leave", "ret"]),
            }

        def find_gadget(self, _items: list[str]) -> object | None:
            return None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", MissROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    with pytest.raises(LookupError) as error:
        _ = entry.gadget["rbp_r14"]

    message = str(error.value)
    assert "未找到 gadget: pop rbp; pop r14; ret" in message
    assert "其他可利用的 gadget:" in message
    assert "[extra=1] 0x401200: pop rbp; pop r14; pop r15; ret" in message
    assert "[extra=2] 0x401100: pop rbp; pop r14; pop r12; pop r13; ret" in message
    assert message.index("[extra=1]") < message.index("[extra=2]")
    assert "pop rsi; ret" not in message
    assert "pop rbp; leave; ret" not in message


def _install_retry_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> list[DummySession]:
    """让 ``from_specs`` 每次返回一个全新 ``DummySession``，模拟新进程。"""
    created: list[DummySession] = []

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        session = DummySession(kind=target.kind)
        created.append(session)
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    return created


def test_script_retry_second_attempt_succeeds_and_returns_live_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    seen: list[int] = []

    def attempt(s: Any) -> bytes:
        seen.append(id(s.session))
        if len(seen) == 1:
            raise EOFError("bogus address, process died")
        return b"flag{win}"

    result = entry.retry(attempt, times=10, success=lambda r: b"flag{" in r.value)

    assert seen == [id(created[0]), id(created[1])]
    assert len(created) == 2
    assert result.success is True
    assert result.attempts == 2
    assert result.session is created[1]
    assert entry.session is created[1]
    assert created[0].close_calls == 1
    assert created[1].close_calls == 0


def test_script_retry_recreates_fresh_process_each_attempt(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    def attempt(s: Any) -> str:
        raise EOFError("retry me")

    with pytest.raises(RetryExhaustedError):
        entry.retry(attempt, times=3)

    assert len(created) == 3
    assert all(session.reconnect_calls == 0 for session in created)
    assert all(session.close_calls == 1 for session in created)
    assert created[0] is not created[1] is not created[2]


def test_script_retry_reports_exhaustion_without_returning_closed_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    def attempt(s: Any) -> None:
        raise EOFError("always dead")

    with pytest.raises(RetryExhaustedError) as error:
        entry.retry(attempt, times=4)

    assert len(created) == 4
    assert "4" in str(error.value)
    assert error.value.__cause__ is not None
    assert isinstance(error.value.__cause__, EOFError)
    assert all(session.close_calls == 1 for session in created)
    assert entry._session is None


def test_script_retry_success_callback_receives_current_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")
    observed: list[Any] = []

    def attempt(s: Any) -> int:
        return 7

    def verify(result: Any) -> bool:
        observed.append(result.session)
        return True

    result = entry.retry(attempt, times=3, success=verify)

    assert observed == [created[0]]
    assert result.session is created[0]
    assert result.value == 7
    assert created[0].close_calls == 0


def test_script_retry_lets_expected_eof_pass_but_propagates_real_errors(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    def attempt(s: Any) -> None:
        raise AttributeError("typo in exp code")

    with pytest.raises(AttributeError):
        entry.retry(attempt, times=5)


def test_script_retry_timeout_is_retryable_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")
    calls: list[int] = []

    def attempt(s: Any) -> bytes:
        calls.append(1)
        if len(calls) < 3:
            raise TimeoutError("recv timed out")
        return b"marker"

    result = entry.retry(attempt, times=5, success=lambda r: r.value == b"marker")

    assert len(calls) == 3
    assert len(created) == 3
    assert result.session is created[2]
    assert result.attempts == 3


def test_script_retry_custom_retry_on_narrows_catch_set(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    def attempt(s: Any) -> None:
        raise EOFError("not allowed to retry")

    with pytest.raises(EOFError):
        entry.retry(attempt, times=3, retry_on=(ValueError,))


def test_script_retry_user_can_raise_retryable_attempt_error(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")
    seen: list[int] = []

    def attempt(s: Any) -> bytes:
        seen.append(1)
        if len(seen) == 1:
            raise RetryableAttemptError("address high byte not zero")
        return b"ok"

    result = entry.retry(attempt, times=3, success=lambda r: r.value == b"ok")

    assert result.success is True
    assert result.session is created[1]


def test_script_retry_respects_times_and_stops_immediately_on_success(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")
    calls: list[int] = []

    def attempt(s: Any) -> bytes:
        calls.append(1)
        return b"ok"

    result = entry.retry(attempt, times=50, success=lambda r: True)

    assert len(calls) == 1
    assert len(created) == 1
    assert result.attempts == 1


def test_script_retry_rejects_invalid_arguments(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    with pytest.raises(ValueError):
        entry.retry(lambda s: None, times=0)
    with pytest.raises(TypeError):
        entry.retry("not callable")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        entry.retry(lambda s: None, success="nope")  # type: ignore[arg-type]


def test_script_retry_leaves_unstarted_entry_usable_after_success(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    created = _install_retry_sessions(monkeypatch)
    entry = CHun.script("./challenge")

    def attempt(s: Any) -> bytes:
        return b"ok"

    result = entry.retry(attempt, times=1, success=lambda r: True)

    assert entry.session is result.session is created[0]
    result.session.io.interactive()
    assert ("interactive", (), {}) in created[0].io.calls


def test_script_retry_warns_in_gdb_mode_but_still_runs(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    created = _install_retry_sessions(monkeypatch)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    entry = CHun.script("./challenge")
    calls: list[int] = []

    def attempt(s: Any) -> bytes:
        calls.append(1)
        if len(calls) == 1:
            raise EOFError("die")
        return b"ok"

    with caplog.at_level("WARNING"):
        result = entry.retry(attempt, times=5, success=lambda r: r.value == b"ok")

    assert result.success is True
    assert result.session is created[1]
    assert any("GDB 模式" in record.message for record in caplog.records)
