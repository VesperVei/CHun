# Base 推导流程

## 目标

通过“泄漏地址 + 已知 symbol offset”得到 base candidate，并理解评分与 reasons。

## 示例

```python
from chun import CHun, RecordDomain

session = CHun.process("./challenge")

puts_leak = 0x7F1234580000
puts_offset = 0x080000

session.rec.record_symbol_leak(
    "puts",
    puts_leak,
    domain=RecordDomain.LIBC,
    source="got",
)
result = session.infer.libc_base_from_symbol_leak("puts", puts_offset)

print(hex(result.raw_base))
print(hex(result.aligned_base))
print(hex(result.value))
print(session.registry.get_fact("libc.base"))
```

`libc_base_from_symbol_leak(leak_name, symbol_offset, *, fact_name="libc.base")` 的参数含义：

- `leak_name`：已经记录到 registry 的 libc 泄漏 observation 名称，例如 `puts`、`atoi@got`
- `symbol_offset`：该符号在目标 libc 文件里的偏移，通常来自 `session.libc_elf.sym["puts"]` 或脚本态 `s.libc.sym["puts"]`
- `fact_name`：写回的 fact 名称，默认写入 `libc.base`

它会读取 `leak_name` 对应的泄漏地址，计算 `leak - symbol_offset`，页对齐后写回 `libc.base`，并返回包含 `raw_base`、`aligned_base`、`stored_fact` 的结果对象。若 `raw_base` 低 12 位非 0，会通过 `log.warning(...)` 提醒该 libc base 可能不正确，并输出完整算式，例如 `计算 libc 为：0x...，可能不是正确的 libc。（0xleak - 0xoffset = 0xraw_base）`。

如果只想直接读取事实层，可以改用：

```python
fact = session.registry.get_fact("libc.base")
print(fact.value if fact else None)
```

如果想看这次推导和哪条 observation 关联：

```python
result = session.infer.libc_base_from_symbol_leak("puts", puts_offset)
print(result.observation_name, hex(result.aligned_base))
```

## 如何解读结果

- `aligned_base`：页对齐后的候选值，通常作为后续基址
- `raw_base`：按 observation 减去 offset 后得到的原始结果
- `stored_fact`：已经写回 registry 的 `Fact`
- `value`：`aligned_base` 的别名，适合直接参与后续地址计算

当前阶段的 inference 目标是打通最小闭环，不是提前实现完整评分系统。

## Libc Catalog 候选检索

当 `InferenceService` 注入 `libc_catalog` 后，可以直接把多条泄漏送入 catalog：

```python
from chun import CHun, LibcCatalogService

session = CHun.process("./challenge")
session.infer.libc_catalog = LibcCatalogService()

result = session.infer.libc_candidates_from_leaks(
    {
        "puts": 0x7F1234580AA0,
        "__isoc99_scanf": 0x7F1234521AB0,
    }
)

print(result.candidates)
print(session.registry.get_artifact("libc.candidates"))
print(session.registry.get_fact("libc.version"))
print(session.registry.get_fact("libc.base"))
```

若候选唯一，`libc.version` 和 `libc.base` 都会自动写回 registry；若候选不唯一，只保留 artifact，不强行确认事实。

catalog 服务层会在查询前自动做名称归一化：

- 先剥离常见后缀，如 `puts@got`、`write_plt`
- 再把 alias 映射到规范名，如 `scanf -> __isoc99_scanf`、`str_bin_sh -> /bin/sh`

如果不想在脚本里自己拼 `dict[str, int]`，可以直接让 inference 扫描事实层：

```python
session.rec.record_symbol_leak("puts", 0x7F1234580AA0, source="got")
session.rec.record_symbol_leak("read", 0x7F123457B250, source="got")

result = session.infer.search_libc()
print(result.candidates)
print(session.registry.get_fact("libc.version"))
print(session.registry.get_fact("libc.base"))
```

`search_libc()` 只会读取 `RecordDomain.LIBC + ObservationKind.SYMBOL_LEAK` 的整数 observation；同名 symbol 若出现多次，会优先采用置信度更高的记录。默认 `single_arch=True`，若没有显式传 `arch`，系统会优先从 `session.elf`，否则从 registry context 中的规范化标量（如 `binary.arch`，不足时回退到 `binary.bits` / `arch.bits`）推断单架构来收窄候选。若版本被唯一确认，或显式传入 `index`，它会继续自动推导并写回 `libc.base`。

如果你想临时放开全架构搜索，也可以显式关闭这个收窄逻辑：

```python
result = session.infer.search_libc(
    require_all=False,
    single_arch=False,
)
```

在这种模式下，如果当前上下文仍然能识别主架构，终端候选输出会分成 `Current arch (...)` 和 `Other arch` 两段，但 `index` 仍然保持全局统一编号，不会因为分组而重排或重编号。

如果存在多个候选，可以先查看结构化结果，再按排名确认目标版本：

```python
result = session.infer.search_libc(require_all=False)
for idx, candidate in enumerate(result.candidates):
    print(idx, candidate.name, candidate.matched_symbols)

result = session.infer.search_libc(
    require_all=False,
    index=0,
)
print(session.registry.get_fact("libc.version"))
print(session.registry.get_fact("libc.base"))
```

确认过 `libc.base` 后，就可以直接通过 resolve façade 取绝对地址；若当前 session 已经绑定了题目给定的 `libc`，`resolve.symbol()` 会优先直接使用这个本地 `libc_elf`，不再强依赖 `search_libc()` 先确认版本：

```python
system_addr = session.resolve.symbol("system")
bin_sh_addr = session.resolve.symbol("str_bin_sh")
puts_addr = session.resolve.symbol("puts@got")

print(hex(system_addr))
print(hex(bin_sh_addr))
print(hex(puts_addr))
```

`resolve.symbol()` 至少依赖一条事实：

- `libc.base`

随后按 mix 优先级解析：

- 若 session 已绑定 `libc_elf`，优先读取本地符号表（`str_bin_sh` 额外支持 `/bin/sh` 搜索）
- 若本地 `libc_elf` 不可用或缺符号，再读取 `libc.version.metadata["libc_id"]` 并回退到 catalog

脚本态可以进一步简写为：

```python
t = CHun.script("./challenge").start()
t.resolve.libc_base_from_elf_symbol("puts", "puts")
print(hex(t.libc_base))
print(hex(t.resolve.symbol("str_bin_sh")))
```
