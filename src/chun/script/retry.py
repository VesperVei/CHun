"""脚本态自动重试语法糖。

把手写 exp 里“整段 Exploit 反复执行、直到碰撞出满足条件的随机地址”这一步
收敛到 `ScriptEntry.retry(...)`：框架负责反复创建全新会话、执行用户回调、
判定成功、清理失败会话，并在成功后保留当次会话供用户继续交互。
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Sequence

from ..core.errors import RetryableAttemptError, RetryExhaustedError, TransportError

if TYPE_CHECKING:
    from ..core.session import CHunSession

_AttemptCallable = Callable[..., Any]
_SuccessCallable = Callable[["RetryResult"], bool]


def _script_module() -> Any:
    return sys.modules[__package__ or ""]


def _default_retryable() -> tuple[type[BaseException], ...]:
    """返回默认视为“预期利用失败，可重试”的异常类型。

    只收录明确的连接级信号：
    - `EOFError`：pwntools tube 在目标退出 / 关闭后 `recv` / `send` 抛出
    - `TimeoutError`：单次接收 / 交互超时
    - `OSError`：远端连接被重置等底层 I/O 失败
    - `TransportError`：CHun transport 层显式失败
    - `RetryableAttemptError`：用户主动声明的可重试失败

    其余异常（`AttributeError` / `TypeError` / `ValueError` / `KeyError` 等）
    一律视为用户代码错误，直接向上抛出，不会被静默吞掉。
    """
    return (EOFError, TimeoutError, OSError, TransportError, RetryableAttemptError)


@dataclass(slots=True)
class RetryResult:
    """一次自动重试的最终结果。

    - `success`：是否命中成功判定
    - `attempts`：实际尝试次数（含成功那次）
    - `session`：成功时保留的、仍处于打开状态的会话；失败时为 `None`。
      会话上的交互要走 `session.io`（如 `result.session.io.sendline(...)` /
      `result.session.io.recv(...)` / `result.session.io.interactive()`），
      `CHunSession` 本身不再重复挂 tube 方法。
    - `last_error`：最后一次预期失败的原因（异常；无则 `None`）
    - `value`：成功判定调用返回的原始值，便于用户携带额外信息
    """

    success: bool
    attempts: int
    session: "CHunSession | None" = None
    last_error: BaseException | None = None
    value: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


class RetryScriptMixin:
    """为 `ScriptEntry` 提供“整段 Exploit 自动重试”能力。"""

    _session: "CHunSession | None"
    _cache: Any
    _libc_path: str | None
    _libc_source: str
    _libc_trusted: bool
    _libc_usable_for_remote: bool

    @property
    def elf(self) -> Any:
        raise NotImplementedError

    @property
    def libc(self) -> Any:
        raise NotImplementedError

    def _build_session(self) -> "CHunSession":
        raise NotImplementedError

    def _prepare_cache_records(self) -> None:
        raise NotImplementedError

    def _bind_cache_contexts(self, session: "CHunSession") -> None:
        raise NotImplementedError

    def retry(
        self,
        attempt: _AttemptCallable,
        *,
        times: int | None = 100,
        success: _SuccessCallable | None = None,
        retry_on: Sequence[type[BaseException]] | None = None,
        delay: float = 0.0,
        on_attempt: Callable[[int], None] | None = None,
        on_fail: Callable[[int, BaseException | None], None] | None = None,
        close_on_fail: bool = True,
    ) -> RetryResult:
        """反复执行完整 Exploit 回调，直到成功判定命中或用尽尝试次数。

        参数语义：

        - `attempt`：一次完整 Exploit 的可调用对象，签名为 `attempt(s)`，
          其中 `s` 是本轮全新会话对应的 `ScriptEntry`。回调可选择返回一个
          值，供 `success` 判定使用；也可以在本地目标退出 / EOF 时直接让
          pwntools 抛 `EOFError`，由框架判定为本轮预期失败并继续。
        - `times`：最大尝试次数，含首次尝试；`None` 表示不设上限（需配合
          `success`，否则永不返回）。
        - `success`：成功判定回调，接收当轮 `RetryResult`（含 `session` 与
          `value`），返回真值表示利用成功。缺省时只把“回调未抛出预期失败异常”
          视为成功，适用于回调自身已用断言 / 返回值表达成败的场景。
        - `retry_on`：自定义视为可重试的异常类型元组；缺省使用
          `EOFError` / `TimeoutError` / `OSError` / `TransportError` /
          `RetryableAttemptError`。真实编程错误不在其中，会直接抛出。
        - `delay`：失败后下一轮开始前的等待秒数，便于规避远端限速。
        - `on_attempt` / `on_fail`：观察钩子，分别在每轮开始与失败收尾时调用。
        - `close_on_fail`：失败轮是否自动 `close()` 会话；本地进程默认关闭，
          以避免僵尸进程堆积。远程 transport 仅在确认可重建时才真正重启。

        返回值：`RetryResult`。成功时 `result.session` 就是命中当轮使用的、
        未被关闭的会话，可直接 `result.session.io.interactive()`；失败时
        `session` 为 `None`，并抛出 `RetryExhaustedError` 携带最后原因。
        """
        if times is not None and times <= 0:
            raise ValueError("retry(times=...) 必须为正整数，或传 None 表示不设上限。")
        if not callable(attempt):
            raise TypeError("retry 的第一个参数必须是可调用的 Exploit 回调。")
        if success is not None and not callable(success):
            raise TypeError("retry(success=...) 必须是可调用对象。")

        retryable: tuple[type[BaseException], ...] = (
            tuple(retry_on) if retry_on is not None else _default_retryable()
        )

        log = _script_module().log
        self._warn_if_debugging_under_retry(times, log)
        attempt_index = 0
        last_error: BaseException | None = None

        while times is None or attempt_index < times:
            attempt_index += 1
            if on_attempt is not None:
                on_attempt(attempt_index)

            session = self._spawn_retry_session()
            self._session = session
            value: Any = None
            succeeded = False
            try:
                value = attempt(self)
                result = RetryResult(
                    success=True,
                    attempts=attempt_index,
                    session=session,
                    value=value,
                )
                if success is None:
                    succeeded = True
                else:
                    succeeded = bool(success(result))
            except retryable as exc:
                last_error = exc
                log.warning(f"[retry] 第 {attempt_index} 次尝试失败（可重试）：{exc!r}")
            except BaseException:
                self._close_retry_session(session, close_on_fail)
                self._session = None
                raise

            if succeeded:
                log.success(f"[retry] 第 {attempt_index} 次尝试命中成功判定。")
                return RetryResult(
                    success=True,
                    attempts=attempt_index,
                    session=session,
                    value=value,
                )

            if on_fail is not None:
                on_fail(attempt_index, last_error)
            self._close_retry_session(session, close_on_fail)
            self._session = None

            if delay > 0 and (times is None or attempt_index < times):
                time.sleep(delay)

        log.failure(f"[retry] 已达最大尝试次数 {attempt_index}，仍未成功。")
        raise RetryExhaustedError(
            f"自动重试已达到最大尝试次数 {attempt_index}，仍未命中成功判定。"
        ) from last_error

    @staticmethod
    def _warn_if_debugging_under_retry(times: int | None, log: Any) -> None:
        """在 GDB 模式下提示：自动重试会在每轮重新拉起调试器。"""
        if not getattr(_script_module().args, "GDB", False):
            return
        if times == 1:
            return
        log.warning(
            "[retry] 当前处于 GDB 模式：每一轮尝试都会重新启动调试器，"
            "可能反复命中断点并阻塞自动重试。建议爆破阶段关闭 GDB，"
            "命中成功后再对该会话单独 attach。"
        )

    def _spawn_retry_session(self) -> "CHunSession":
        """构建并完整装配一轮全新的会话（本地即全新进程）。"""
        session = self._build_session()
        self._prepare_cache_records()
        session.bind_binaries(elf=self.elf, libc_elf=self.libc)
        self._bind_cache_contexts(session)
        if hasattr(session.resolve, "configure_libc_cache"):
            session.resolve.configure_libc_cache(
                cache_service=self._cache,
                libc_path=self._libc_path,
                source=self._libc_source,
                trusted=self._libc_trusted,
                usable_for_remote=self._libc_usable_for_remote,
            )
        return session

    @staticmethod
    def _close_retry_session(session: "CHunSession", close: bool) -> None:
        if not close:
            return
        try:
            session.close()
        except Exception as exc:  # pragma: no cover - 清理阶段的防御性分支
            _script_module().log.debug(f"[retry] 关闭失败会话时忽略异常：{exc!r}")


__all__ = ["RetryResult", "RetryScriptMixin"]
