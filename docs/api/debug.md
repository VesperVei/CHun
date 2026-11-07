# Debug & Resolve API

## `session.dbg`

`session.dbg` 是 `PwntoolsGdbBridge`，偏交互式调试：

- `attach(io=None, script=None, api=True)`
- `execute(command)`
- `breakpoint(location)`
- `snapshot_regs()`
- `snapshot_maps()`

设计目标：

- 适合当前 pwntools process / tube attach
- 允许发基本 gdbscript
- 关键调试上下文回写 registry

## `session.gdb_mi`

`session.gdb_mi` 是 `GdbMiBridge`，偏机器可解析与自动化：

- `start()`
- `execute(command)`
- `snapshot_regs()`
- `snapshot_maps()`
- `backtrace()`

设计目标：

- 与交互式 GDB 分离
- 返回结构化结果
- 为后续自动分析保留稳定接口

## `session.resolve`

`session.resolve` 是围绕 pwntools 能力封装的解析入口：

- `memleak(leak_primitive, ...)`
- `symbol_via_dynelf(symbol, pointer, *, leak_primitive=... | memleak=..., ...)`
- `symbol(name)`
- `libc_base_from_elf_symbol(observation_name, symbol, *, libc_elf=None, fact_name=...)`
- `pie_base_from_elf_symbol(observation_name, symbol, *, elf=None, fact_name=...)`

它负责把：

- leak primitive
- `MemLeak`
- `DynELF`
- session.registry

收敛到同一条工作流里。

如果当前会话已经显式绑定了默认 `elf` / `libc_elf`，后续 `libc_base_from_elf_symbol()` 与 `pie_base_from_elf_symbol()` 可省略对应对象参数。标准绑定入口是 `session.bind_binaries(elf=..., libc_elf=...)`；`CHun.script().start()` 也会走同一条 session 绑定链。

这里要区分两类状态：

- 运行时富对象：只挂在 `session.elf` / `session.libc_elf`
- registry context：只保存规范化标量，例如 `binary.path` / `binary.arch` / `arch.bits` / `libc.path`

`symbol(name)` 走的是另一条离线链路：

- 从 registry 读取 `libc.base`
- 从 `libc.version` 的 metadata 提取 `libc_id`
- 通过本地 `LibcCatalogService` 查询符号 offset
- 返回绝对地址

它支持服务层归一化，因此 `puts@got`、`write_plt`、`str_bin_sh` 这类常见 EXP 写法可以直接使用。

## `session.crash`

`session.crash` 是 `CorefileAnalyzer`：

- `analyze(core, offset_subseq=None)`

分析后会把结果写回 registry，包括：

- crash registers
- fault address
- PC / SP
- maps
- cyclic offset
- core path / signal 等 context

## 三条最小 workflow

### ret2libc

```python
session.rec.record_symbol_leak("puts", leak, source="got")
result = session.resolve.libc_base_from_elf_symbol("puts", "puts", libc_elf=libc)

# script 场景：
# t = CHun.script("./challenge", libc="./libc.so.6")
# t.start()
# result = t.resolve.libc_base_from_elf_symbol("puts", "puts")
```

### blind leak -> DynELF

```python
resolved = session.resolve.symbol_via_dynelf(
    "system",
    0x601018,
    leak_primitive=leak_func,
    lib="libc",
)
```

### 离线 libc 符号解析

```python
result = session.infer.search_libc(require_all=False)
result = session.infer.search_libc(
    require_all=False,
    index=0,
)

system_addr = session.resolve.symbol("system")
bin_sh_addr = session.resolve.symbol("str_bin_sh")
```

如果候选唯一，上面的 `index` 可以省略；`search_libc()` 会直接写回 `libc.version` 和 `libc.base`。若 session 已经绑定了题目给定的 `libc_elf`，`resolve.symbol()` 也可以只依赖 `libc.base` 直接工作，并在缺符号时再回退到 catalog。

### core dump analysis

```python
report = session.crash.analyze("/tmp/core")
print(report.pc, report.cyclic_offset)
```

这些 workflow 在当前仓库里都有独立 smoke test，并且都只走 `CHun` + `CHunSession` 的公开入口。
