# Registry API

## `EvidenceRegistry` 的职责

`EvidenceRegistry` 是 CHun 第二阶段正式落地的统一事实层，负责：

- 记录原始观测（`observations`）
- 记录稳定事实（`facts`）
- 记录可复用产物（`artifacts`）
- 记录会话上下文（`context`）

## 四类记录分别是什么

- `observations`
  - 原始观测，不保证已经被证明
  - 例如 symbol leak、HTTP 响应、blind 探测结果
- `facts`
  - 已确认或经过归纳的稳定结论
  - 例如 `libc.base`、`fmt.offset`
- `artifacts`
  - 可复用产物
  - 例如 payload、脚本、模板渲染结果、libc catalog 检索结果
- `context`
  - 会话背景信息
  - 例如 target kind、transport kind、libc path

## 记录 API

主入口是显式 typed API，而不是万能 `add_log()`：

- `record_observation()`
- `record_symbol_leak()`
- `record_fact()`
- `record_artifact()`
- `set_context()`

所有记录都显式携带语义字段：

- `kind`
- `domain`
- `source`
- `confidence`
- `tags`
- `metadata`

## 查询与读取

- `get_observation(name)`
- `get_fact(name)`
- `get_artifact(name)`
- `get_context(name)`
- `find_observations(...)`
- `find_facts(...)`
- `find_artifacts(...)`
- `find_context(...)`

查询维度目前支持：

- `domain`
- `kind`
- `tag`
- `source`

## Replay Trace（热路径）

`EvidenceRegistry` 现在内置一套 compact replay recorder，用于低开销记录“可重放最小前缀”，而不是 full workflow。

默认只记录外部 effect 事件：

- `spawn`
- `send`
- `sendline`
- `expect`（`recvuntil` 同步锚点）
- `checkpoint`

对应 API：

- `append_event(...)`
- `checkpoint(name, ...)`
- `slice_to_here(from_checkpoint=...)`
- `render_replay(...)` / `show_replay(...)`
- `run_replay(...)`

这里的大 payload 不直接内联到 event 里，而是通过 blob ref 去重引用。

详细方法级说明（事件模型、切片语义、重放顺序、日志恢复、边界约束）见：[Replay API](replay.md)。

注意：`show()` 目前只展示 `context / observations / facts / artifacts` 四层，不会把 replay events 混在这四层输出里。

如果你要查看 replay 记录，使用：

```python
events = list(session.rec.replay.iter_events())
checkpoints = session.rec.replay.checkpoints
snapshot = session.rec.to_dict()["replay"]
session.rec.show_replay(include_payload=True, limit=20)
```

### Observation 验证与晋升

新增最小闭环：

- `validate_observation(...)`
  - 基于 replay slice + probe + predicate 做独立会话验证
  - 会回写 observation metadata：
    - `verification_status`
    - `verified_by`
    - `verification_reason`
  - 可选 `capture_replay_registry=True`，把 replay 子会话的 `rec.show(...)` 文本放进 `VerificationResult.metadata["replay_registry_lines"]`
- `promote_observation_to_fact(...)`
  - 把 observation 显式晋升为 fact

推荐语义是：

1. 先写 observation（例如 `fmt.offset.candidate`）
2. 按需触发验证
3. 验证通过后再晋升 `fmt.offset` fact

## 快照与打印

`EvidenceRegistry` 现在还提供一组面向调试和运行期观测的公共接口：

- `snapshot(...)`
- `render(...)`
- `show(...)`

推荐分工：

- `snapshot(...)`
  - 返回结构化快照
  - 适合 CLI / workflow / 业务逻辑二次处理
- `render(...)`
  - 返回可直接展示的文本行
  - 适合测试、dry-run、上层自定义输出
- `show(...)`
  - 直接通过 `log.debug/info/warning` 输出
  - 适合 `session.rec.show(...)` 这种会话期排障入口

### 分层筛选优先于日志等级

这组接口的主筛选维度是 `layers`，而不是日志等级。

可选层固定为四类：

- `context`
- `observations`
- `facts`
- `artifacts`

默认顺序也是：

1. `context`
2. `observations`
3. `facts`
4. `artifacts`

这表示：

- 先决定“看哪几层”
- 再决定“展开到多详细”
- 最后才决定“以什么日志级别打出去”

### 关键参数

- `layers=...`
  - 选择输出哪些层
  - 支持单个字符串或元组，例如 `layers="facts"`、`layers=("context", "facts")`
- `detail=...`
  - 控制详细度
  - 可选：`compact` / `standard` / `verbose`
- `emit=...`
  - 只影响 `show(...)` 用什么日志级别输出
  - 可选：`debug` / `info` / `warning`
- `artifact_mode=...`
  - 控制 artifact 的值如何展示
  - 可选：`summary` / `repr` / `skip`
- `domain=...` / `source=...` / `tag=...`
  - 复用 registry 现有过滤语义
- `limit=...`
  - 按层裁剪记录数，而不是全局裁剪

### 推荐用法

快速查看当前会话最关键的上下文和事实：

```python
session.rec.show(
    layers=("context", "facts"),
    detail="standard",
)
```

只看 workflow 相关事实，并用 `debug` 级别打出：

```python
session.rec.show(
    layers=("context", "observations", "facts"),
    domain=RecordDomain.WORKFLOW,
    emit="debug",
)
```

只取结构化快照，不立即打印：

```python
snapshot = session.rec.snapshot(
    layers=("facts", "artifacts"),
    domain=RecordDomain.LIBC,
    limit=5,
)
```

### 输出示例

`detail="standard"`：

```text
[Registry] ctx=1 obs=1 facts=2 arts=0 total=4
[Context]
workflow.current_checkpoint      pwn3.menu kind=session domain=workflow src=session
[Observations]
__malloc_hook                    0x7f3a2c8f4be0 kind=symbol-leak domain=libc src=leak conf=0.70
[Facts]
libc.base                        0x7f3a2c875000 kind=base-address domain=libc src=infer conf=0.95
resolved.system                  0x7f3a2c8c1490 kind=symbol-address domain=resolve src=resolve conf=0.90
```

`detail="verbose"`：

```text
[Registry] ctx=0 obs=0 facts=1 arts=0 total=1
[Facts]
name        libc.base
value       0x7f3a2c875000
kind        base-address
domain      libc
source      infer.libc_base_from_symbol_leak
confidence  0.95
evidence    __malloc_hook
metadata    {'symbol_offset': 0x1ebb70}
ts          2026-04-22T12:34:56+00:00
```

如果 `artifact_mode="skip"`，artifact 只参与原始 registry 存储，不参与本次展示。

如果你希望在业务侧拿到“不可空且值类型明确”的结果，而不是自己手写 `None` 判断和 `isinstance(...)`，可以使用严格读取 helper：

- `require_observation(name)`
- `require_fact(name)`
- `require_artifact(name)`
- `require_context(name)`
- `require_int_observation(name)`
- `require_int_fact(name)`
- `require_str_fact(name)`

这些 helper 在记录缺失时抛 `KeyError`，在值类型不匹配时抛 `TypeError`，适合脚本层和类型检查较严格的调用点。

## 覆盖与更新规则

所有写接口都支持 `overwrite=`。

- `overwrite=True`
  - 用新记录覆盖旧记录
- `overwrite=False`
  - 若记录已存在则抛出 `RegistryConflictError`

这让“更新”和“防止误覆盖”变成显式行为。

## 与 `CHunSession` 的关系

每个 session 都会稳定持有一个 registry：

- `session.registry`
- `session.rec`

并在创建时自动写入最小上下文：

- `session.target`
- `session.target.kind`
- `session.transport`
- `session.transport.kind`
- `session.transport.is_open`

运行期补充：

- 首次访问 `session.io`（触发 lazy open）后，会刷新 `session.transport.is_open`
- 若 transport 暴露 `raw`，还会写入 `session.transport.raw_type`

## 最小 inference 闭环

`session.infer.libc_base_from_symbol_leak()` 会：

1. 从 observation 读取 symbol leak
2. 按给定 `symbol_offset` 推导 base
3. 把结果写回 fact，例如 `libc.base`

函数签名为 `libc_base_from_symbol_leak(leak_name, symbol_offset, *, fact_name="libc.base")`。`symbol_offset` 是必需参数，表示该泄漏符号在 libc 文件中的静态偏移；典型脚本写法是 `s.infer.libc_base_from_symbol_leak("atoi@got", s.libc.sym["atoi"])`。

如果 `leak - symbol_offset` 得到的原始 libc base 低 12 位非 0，说明结果没有页对齐，系统会通过 `log.warning(...)` 输出提醒并附带计算式，例如 `计算 libc 为：0x...，可能不是正确的 libc。（0xleak - 0xoffset = 0xraw_base）`。提醒不会中断流程，仍会按页对齐后的 `aligned_base` 写回 `libc.base`。

这证明新的 registry 不是纯存储壳，而是能承接 session + inference 的最小工作流闭环。

若 libc base 是自己计算得到、并非来自 `recv_leak()` 记录，可直接确认：

```python
s.infer.set_libc_base(0x7f3a2c875000)          # 直接写回 libc.base
s.libc_base = 0x7f3a2c875000                    # 脚本态属性写入语法糖
s.set_libc_base(0x7f3a2c875000, aligned=False)  # 保留未对齐原值
```

`set_libc_base(base, *, fact_name="libc.base", source="manual", aligned=True)` 默认按 `page_size` 页对齐并在未对齐时 `log.warning`，返回 `BaseInferenceResult`。`session.libc_base = ...` 与 `session.infer.set_libc_base(...)` 等价。

`session.infer.libc_candidates_from_leaks()` 在注入 `libc_catalog` 后还会：

1. 调用 SQLite catalog 检索候选
2. 把完整 `LibcSearchResult` 写入 artifact，默认名为 `libc.candidates`
3. 若候选唯一，或显式传入 `index` 命中候选，则自动写入 `libc.version` fact
4. 一旦版本被确认，会立刻基于任一 leak 自动写入 `libc.base` fact

`session.infer.search_libc()` 进一步把“扫描 registry -> 组装 leaks -> 调 catalog”这一层也封装起来：

1. 只扫描 `domain=LIBC` 且 `kind=SYMBOL_LEAK` 的 observation
2. 跳过非整数地址
3. 同名 symbol 出现多次时，优先采用更高 `confidence` 的记录
4. 支持 `single_arch=True`：若调用方未显式传 `arch`，则优先从 `session.elf`，否则从 registry context 中的规范化标量（例如 `binary.arch`，不足时回退到 `binary.bits` / `arch.bits`）推断单一架构收窄候选
5. 支持 `index=...`，用于多候选场景下按排名静默确认目标版本
6. 若没有可用 leak，则抛 `InferenceInputError`

若命中多个候选且没有传 `index`，系统会保留 `libc.candidates` artifact，并按 `index + matched + score + arch + symbols` 的格式输出候选列表供外部爆破逻辑使用，但不会写入 `libc.version` / `libc.base`。

当 `single_arch=False` 且当前上下文仍然能推断出主架构时，候选展示会分为两段：

- `Current arch (...)`
- `Other arch`

这里的分组只影响显示，不影响底层候选顺序；`index` 始终是全局统一编号，因此 `index=0/1/2...` 仍然稳定命中对应候选。

若命中唯一候选，系统会自动确认并通过 `log.success(...)` 输出一条简短成功消息，例如 `libc resolved: libc6_2.39-0ubuntu8.6_amd64`。

`session.resolve.symbol(name)` 则会继续消费事实层：

1. 读取 `libc.base`
2. 若 session 已绑定 `libc_elf`，优先直接从本地 `libc` 解析 offset
3. 若本地 `libc_elf` 不可用或缺符号，再读取 `libc.version.metadata["libc_id"]`
4. 通过本地 SQLite catalog 查询 offset
5. 返回 `libc.base + offset`

这里的 `name` 支持服务层归一化，因此 `puts@got`、`write_plt`、`str_bin_sh` 这类常见写法都可以直接传入，不需要污染底层 catalog 表结构。

脚本态还提供两个只读快捷属性：

- `t.libc_base`
- `t.libc_version`

会话态也提供同名快捷属性：

- `session.libc_base`
- `session.libc_version`

另外，registry context 只用于保存环境标量，不保存运行时 ELF / libc ELF 富对象；后者应始终挂在 `session.elf` / `session.libc_elf`。

## 当前推荐入口

- 类型名使用 `EvidenceRegistry`
- 会话内访问优先使用 `session.registry`
- 需要短写时使用 `session.rec`
- 需要快速查看当前记录时，优先使用 `session.rec.show(...)`

不再把额外别名当作长期公开接口。
