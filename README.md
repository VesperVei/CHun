# CHun

CHun: a lightweight and evolving Pwn toolkit by Chenhun.

CHun 当前已进入第三轮收口阶段：在前两轮的 transport + registry/session 地基之上，已经固定了 pwntools / GDB bridge、DynELF 解析链路和 core dump 分析入口的公开用法。

## 核心特性

- 会话入口：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()`
- 脚本模式入口：`CHun.script()`，保留人工写 exp 时的快速切换手感
- 脚本态 leak 语法糖：`recv_leak()`，支持 `raw` / `hex` / `regex` / `recv=True`
- fmt 偏移管理：`session.fmt.set_offset(...)` 与脚本态 `t.fmt.set_offset(...)`
- Web 方向 transport：`CHun.http()` / `CHun.websocket()`
- Blind transport：`CHun.blind()` + `BlindReconnectTransport`
- 会话内统一事实层：`session.registry` / `session.rec`
- 最小 inference 入口：`session.infer`
- 调试与解析入口：`session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`

## 当前稳定公开接口

- 顶层工厂：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()` / `CHun.http()` / `CHun.websocket()` / `CHun.blind()`
- 脚本 facade：`CHun.script()`
- 会话入口：`session.io` / `session.registry` / `session.rec` / `session.infer`
- 调试与解析：`session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`
- 脚本态高频语法糖：`recv_leak()` / `replay()` / `fmt.find_offset()` / `fmt.set_offset()`
- Web 方向 transport：`CHun.http()` / `CHun.websocket()`
- Blind transport：`CHun.blind()` + `BlindReconnectTransport`
- 第一阶段主力 transport：`PwntoolsTubeTransport` / `HttpxTransport` / `WebSocketTransport`
- `PwnRegistry` 仍保留为独立状态中心，后续阶段再接回完整 session

## 安装

```bash
python -m pip install -e .
```

## 最小使用示例

```python
from chun import CHun

p = CHun.process("./challenge")
p.rec.record_symbol_leak("puts", 0x7F1234580000, source="got")
result = p.infer.libc_base_from_symbol_leak("puts", 0x80000)
print(hex(result.aligned_base))
```

## 多种连接方式

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("127.0.0.1", 31337, binary="./challenge")
http = CHun.http("http://127.0.0.1:8000")
ws = CHun.websocket("ws://127.0.0.1:9001")

resp = http.io.request("GET", "/health")
print(resp)

ws.io.send_message("ping")
print(ws.io.recv_message())
```

## 脚本模式 facade

显式工厂适合自动化、模板和 agent；`CHun.script()` 只给人工写 exp 时保留快速切换手感。

初始化时会顺手完成：

- `context.log_level` / `context.terminal`
- `t.elf = context.binary = ELF(binary, checksec=False)`
- `t.libc` 默认仅在显式传 `libc=...` 时绑定；如需自动探测本机 libc，需显式 `auto_local_libc=True`
- `t.rec` / `t.resolve` / `t.dbg` 等 session 核心能力会作为显式 facade 暴露
- `t.sla()` / `t.rl()` / `t.ia()` 等高频 tube 方法和 alias 可直接调用
- 低频 tube 方法仍可通过 fallback 使用，例如 `t.clean()`
- `t.recv_leak(..., mode="hex")` 默认按流式 `0x...` token 解析，可配合 `index=` 选第几个地址
- `t.recv_leak(..., regex=..., recv=True)` 会先主动抓取当前 burst，再对完整缓冲做 Python `re.finditer(...)`；适合分片输出、无换行地址、或希望获得更接近 `re` 的手感
- `t.fmt.set_offset(...)` 在脚本态已显式暴露，IDE 可直接补全

```python
from chun import CHun
from pwn import *

t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6")
t.start()

t.gdb("""
b *main
c
""")

t.sla(b"menu> ", b"1")
puts = t.recv_leak("puts", delim=b"puts: ", mode="hex")
t.resolve.libc_base_from_elf_symbol("puts", "puts")
print(hex(puts), hex(t.libc_base))

t.fmt.set_offset(6, source="manual")
canary = t.recv_leak(
    "canary",
    regex=rb"0x[0-9a-f]{8}",
    mode="hex",
    recv=True,
    index=1,
)
print(hex(canary))
```

`recv_leak()` 当前推荐心智模型：

- 默认 `mode="raw"`，适合固定字节数原始泄漏
- `mode="hex"` 适合 `%p` / 文本地址泄漏，默认按流式 `0x...` token 解析
- `regex=..., recv=False` 继续走底层 `recvregex(...)` 的流式语义
- `regex=..., recv=True` 改走“抓当前 burst + full-buffer regex”语义；若再配合 `mode="hex"`，则支持 `index=` 选中第几个 regex 命中地址

命令行切换方式：

```bash
python exp.py
python exp.py GDB
python exp.py REMOTE
python exp.py REMOTE GDB
```

## Blind reconnect 示例

```python
from chun import CHun

blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
response = blind.io.exchange(
    b"%7$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
print(response)
```

## Session + Registry 示例

```python
from chun import CHun, RecordDomain

session = CHun.process("./challenge")
session.rec.set_context("libc.path", "/glibc/libc.so.6", domain=RecordDomain.LIBC)
session.rec.record_artifact("payload.stage1", b"AAAA", tags=["payload"])
```

## 最小 workflow 示例

```python
from chun import CHun

session = CHun.process("./challenge")

# ret2libc
session.rec.record_symbol_leak("puts", 0x7F1234580000, source="got")
# session.resolve.libc_base_from_elf_symbol("puts", "puts", libc_elf=libc)

# 交互式 GDB attach
# session.dbg.attach(script="b *main\nc")

# blind leak -> DynELF
result = session.resolve.symbol_via_dynelf(
    "system",
    0x601018,
    leak_primitive=lambda addr, size=8: b"\x00" * size,
    lib="libc",
)
print(hex(result.address))
```

## 文档入口

- 文档首页：[`docs/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/index.md)
- MkDocs 配置：[`mkdocs.yml`](/Users/zaochuan/Documents/code/python/CHun_pwn/mkdocs.yml)
- API 总览：[`docs/api/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/index.md)

文档主维护位置在 `docs/`，README 只保留项目入口、安装与最小示例。

## 当前模块概览

- `src/chun/facade.py`：`CHun` 顶层工厂入口
- `src/chun/core`：`session.py`、`models/`、`errors.py`、`registry/`、`inference/`、`resolve/`、`analysis/`
- `src/chun/bridges`：GDB / pwntools 相关 bridge
- `src/chun/transports`：transport 实现与组装工厂
- `src/chun/plugins`：后续 blind/fmt/heap 插件骨架
- `src/chun/utils`：`display.py`、`misc.py`

当前阶段刻意未做 fmt / heap / template 主体，以及 pwngdb / pwndbg 深集成。
