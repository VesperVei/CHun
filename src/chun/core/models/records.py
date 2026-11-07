"""Evidence / Registry 相关数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    """返回统一的 UTC 时间戳。"""
    return datetime.now(timezone.utc)


def clamp_confidence(value: float) -> float:
    """把置信度限制在 ``[0.0, 1.0]`` 区间。"""
    return max(0.0, min(1.0, value))


class RecordDomain(str, Enum):
    """记录所属的能力域。"""

    CORE = "core"
    SESSION = "session"
    TARGET = "target"
    TRANSPORT = "transport"
    ELF = "elf"
    LIBC = "libc"
    FMT = "fmt"
    HEAP = "heap"
    BLIND = "blind"
    CRASH = "crash"
    RESOLVE = "resolve"
    HTTP = "http"
    WEBSOCKET = "websocket"
    DEBUGGER = "debugger"
    TEMPLATE = "template"
    WORKFLOW = "workflow"


class ObservationKind(str, Enum):
    """原始观测的语义类型。"""

    SCALAR = "scalar"
    ADDRESS_LEAK = "address-leak"
    SYMBOL_LEAK = "symbol-leak"
    MEMORY_LEAK = "memory-leak"
    BASE_HINT = "base-hint"
    HTTP_RESPONSE = "http-response"
    WS_MESSAGE = "ws-message"
    BLIND_PROBE = "blind-probe"
    DEBUGGER_OUTPUT = "debugger-output"
    SNAPSHOT = "snapshot"


class FactKind(str, Enum):
    """稳定事实的语义类型。"""

    ADDRESS = "address"
    BASE_ADDRESS = "base-address"
    SYMBOL_ADDRESS = "symbol-address"
    OFFSET = "offset"
    VERSION = "version"
    CLASSIFICATION = "classification"
    DERIVED = "derived"


class ArtifactKind(str, Enum):
    """可复用产物的语义类型。"""

    GENERIC = "generic"
    CATALOG_RESULT = "catalog-result"
    PAYLOAD = "payload"
    ROP_CHAIN = "rop-chain"
    TEMPLATE_RENDER = "template-render"
    SCRIPT = "script"
    SNAPSHOT = "snapshot"


class ContextKind(str, Enum):
    """上下文条目的语义类型。"""

    SESSION = "session"
    TARGET = "target"
    TRANSPORT = "transport"
    ENVIRONMENT = "environment"
    LIBC = "libc"
    SERVICE = "service"


@dataclass(slots=True)
class Observation:
    """原始观测记录。"""

    name: str
    value: object
    kind: ObservationKind = ObservationKind.SCALAR
    domain: RecordDomain = RecordDomain.CORE
    source: str = "manual"
    confidence: float = 0.50
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    ts: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        self.confidence = clamp_confidence(self.confidence)


@dataclass(slots=True)
class Fact:
    """稳定事实记录。"""

    name: str
    value: object
    kind: FactKind = FactKind.DERIVED
    domain: RecordDomain = RecordDomain.CORE
    source: str = "derived"
    confidence: float = 0.80
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    ts: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        self.confidence = clamp_confidence(self.confidence)


@dataclass(slots=True)
class Artifact:
    """可复用产物记录。"""

    name: str
    value: object
    kind: ArtifactKind = ArtifactKind.GENERIC
    domain: RecordDomain = RecordDomain.CORE
    source: str = "manual"
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    ts: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class ContextEntry:
    """会话上下文记录。"""

    name: str
    value: object
    kind: ContextKind = ContextKind.SESSION
    domain: RecordDomain = RecordDomain.CORE
    source: str = "session"
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    ts: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class BaseInferenceResult:
    """最小 inference 闭环返回值。"""

    fact_name: str
    observation_name: str = ""
    symbol_offset: int = 0
    raw_base: int = 0
    aligned_base: int = 0
    stored_fact: Fact | None = None

    @property
    def value(self) -> int:
        """返回最常用的页对齐 base 值。"""
        return self.aligned_base


__all__ = [
    "Artifact",
    "ArtifactKind",
    "BaseInferenceResult",
    "ContextEntry",
    "ContextKind",
    "Fact",
    "FactKind",
    "Observation",
    "ObservationKind",
    "RecordDomain",
    "clamp_confidence",
    "utcnow",
]
