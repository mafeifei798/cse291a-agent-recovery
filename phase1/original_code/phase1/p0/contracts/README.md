# P0 模块契约

版本：`p1_schema_version=p1.0`，`protocol_version=p0-v1`。这四份文件只冻结后续实现的交接规则，没有提供可运行的 P1 模块，也没有发模型请求。

- [interfaces.json](interfaces.json)：模块输入、输出、错误码、边界和三处 Workflow hook。
- [records.schema.json](records.schema.json)：Draft 2020-12 格式；精确验证任务、预登记槽位和 P1 审计封装，另有模型输入与公开文本载体的子模式。
- [prompt_spec.json](prompt_spec.json)：`p1-model-v1` 的精确系统文字、两条消息、字段白名单、规范 JSON、摘要和输出 schema。
- [共用假样本](../samples/)：以静态记录核对字段及交接；不把假 token、时间或响应当成真实实验。

## 三个人各接哪里

| 人 | 交付边界 | 可先用什么替身 |
| --- | --- | --- |
| A | 原 Workflow 的三个窄 hook；P1 渲染及调用绑定；冻结、条件补偿和重启准入；外部 campaign 预算账本及 transport | 透传 delivery、固定 checker 决策、假 Gateway |
| B | delivery、四类事件、runtime verifier、五步 runner 和一次完整重启编排 | 假 Gateway、固定 freeze/begin_restart 回执 |
| C | 不可变任务/168槽位；独立业务判定、早期恢复资格、传播和费用汇总 | 本目录样本，不等待真实凭证或 B 的完整运行器 |

C 的 `initial_checker.evaluate` 是 B 编排完整重启的早期依赖，须先交身份和资格。它可以读私有评估记录，但不给正确数值。B 的运行时 verifier 只读公开规则和合法 source_reader，不能调用 C 的检查器或私有故障脚本。A 负责改旧核心文件接 hook，B 不另写一套 Workflow，也不和 A 同时修改旧核心。

接口 JSON 的名字是后续实现约定，`implemented=false`。未来实现如有必要改签名，先改协议版本和样本，并重新核对整包；不能在运行中悄悄追加字段或改变时序。

## 记录怎么引用

[任务集合](../manifests/tasks.json) 中每个 `tasks[]` 用 `#/$defs/TaskManifest` 验证；[168槽位](../manifests/trials.jsonl) 每行用 `#/$defs/TrialManifest` 验证。后者是**不可变预登记记录**，所以 `status=not_started`、真实 run/branch 身份为 null、调用和产物数组为空，`authorization=not_authorized`。后续运行另写审计和汇总，不能覆盖这168行制造“P0已跑”的记录。

`TaskManifest.task_digest` 是整个记录去掉自身 `task_digest` 后的规范 JSON SHA-256。schema 检查字段与类型；独立核对器还须检查任务算术、对象键、ID互相引用、manifest摘要、先后顺序及槽位配对。JSON Schema 无法单独证明“这份 plan 真的是那个 parent 算出来的”或“迟到发生在冻结后”。

`StepAudit` 和 `TrialSummary` 冻结的是 P1 sidecar 的外层，分别用 `p1.StepAudit` / `p1.TrialSummary` 标识。大型逐步指标、费用和时间记录通过明确引用连接。静态样本顶层用 `StaticFixture`，内部 trace 则由 P0 独立核对器检查。本阶段尚不要求样本伪造完整旧式 ModelCallEntry；假调用只在明确标记的 P1 synthetic ledger 中，旧 `StepResult.model_calls=[]`。

原 TaskSpec/StepResult 等仍为 `1.1`。真实旧对象快照恰有五个字段：`object_key / exists / payload / version / last_writer_id`。业务输入仍恰有 `request / parents / tool_snapshots` 三个字段。不能把条件、攻击文本或评估答案塞进旧 payload/object/input_snapshot。

## 精确消息与低信任文本

`render_p1(step_id, input_bundle, public_carriers, prompt_revision)` 只渲染两条消息。system 内容是 `prompt_spec.json` 中的 prefix 直接连接该步 instruction；user 内容是规范 JSON：

```text
{"step_id": step_id, "input": input_bundle, "public_carriers": public_carriers}
```

上面表示逻辑对象，实际字节按 key 排序，递归使用 `ensure_ascii=false`、分隔符 `,` 和 `:`，UTF-8，无 BOM、无末尾换行；拒绝重复 JSON key 和非有限数字，不 trim 或规范化 Unicode 文本。`rendered_messages_digest` 是两条消息整个数组的规范 JSON SHA-256。输出 schema 和原五步形状一致，执行器输出的是 `save_job` 动作候选，真正成功结果由 Store 的写入回执产生。

公开 carrier 恰有三字段 `carrier_kind / carrier_ref / untrusted_text`，ref 是结构化对象：

| 位置 | carrier_kind | carrier_ref | 约束 |
| --- | --- | --- | --- |
| read_metadata | source_note | `{object_key, version}` | 与本次真正捕获的 metadata 快照相同 |
| plan | handoff_note | `{result_id, payload_digest}` | 与真正选定的 metadata 父结果相同；digest 只哈希该 parent.payload |
| 其他三步 | 无 | 空数组 | 不重复向下游复制攻击文本 |

每个条件都走相同模板，并在上述两个位置有中性说明；ADV 仅替换获准目标的一段文字。source_note 不会凭空给 Planner 多读一次工具；handoff_note 的源读集合从实际 parent 继承。条件、事件ID、当前权威版本、私有原响应、预定答案和评估标签只在审计里。

旧 StepResult 的 input_snapshot 仍恰有五字段 `request / parents / tool_snapshots / prompt_revision / rendered_messages`。P1 carrier 独立存 sidecar，通过 attempt/call/result 身份和摘要连接。C 按 `prompt_revision` 显式分派：`s6-model-v1` 仍由旧规则核验，`p1-model-v1` 用此契约及 sidecar 重建；未知 revision、丢失 sidecar 或摘要不符应阻断，不能关掉旧 Oracle。

模型名称、TritonAI入口、配额、计价及真实 transport 仍待确认。这里复用了旧输出结构和系统文字，并不等于已批准旧 S6 模型或已证明学校接口支持它。

## 三处 hook 的顺序

1. `after_capture_before_render`：A 在旧 `run_step` 内接出捕获后的边界，B 执行 TMO/STL/公开文本交付。它发生在模型渲染及派发前。TMO 直接关闭确切失败 attempt，不调用模型。
2. `after_schema_before_publish`：原模型输出已通过结构校验，B 才能做一次 ERR 指定字段替换。原响应私有保留，公开结果、模型账本 delivered_output 和下游消息一致。原响应结构无效则记未到注入边界。
3. `after_publish_before_adopt`：查询或 Plan 已成功持久化，B 的 VERIFY_STOP 才重读合法当前源并检查。拒绝是运行器停止状态，不改模型响应，不创建补正结果。BASE 的该处为透传。

提交、版本、父链、schema 和幂等守卫始终开启。STL 被 Store 以旧版本拒绝或 ADV 被模型忽略都可以是有效结果，不能为了得到错误写入而绕过守卫。

## 零输出 TMO 的冻结和重启

首条共用路径固定为 dev-01 的 `read_metadata`。下面是协议时间，不是实际测量结果；假样本明确标 `clock_kind=synthetic_not_measured`。

| 时刻/交接 | 必须成立的记录 | 不能做的事 |
| --- | --- | --- |
| t=0 捕获 | 捕获 metadata v1，创建一个受控待交付记录；初始 metadata attempt 已准入 | 提前把快照交给模型 |
| t=1 deadline | `timeout_event_delivered=true`、`tool_payload_delivered=false`、模型暴露 N/A；关闭确切 attempt，失败记录 payload=null、effects=[]、model_calls=[] | 造成功结果、造FaultNotice，或把快照当作已暴露 |
| t=1 freeze | 无 active attempt、无未知提交/记账；`scene_kind=partial_failure`；成功结果/写入/模型调用都允许为空；记录 scene_id/digest 与外部预算引用 | 要求“必须先五步成功”或“必须有effect”；把未知现场包装为可恢复 |
| t=1～2 | 初始流程已停。待交付记录留在冻结数据库之外，旧现场摘要不变 | 将等待旧回复的记录当作仍 active 的 Workflow attempt |
| t=2 late rejection | 按已关闭的 attempt 拒绝旧回复，仅外部追加审计；持久化排空回执，`drain_complete_after_frozen=true` | 往冻结 DB 追加结果/改源/改已冻结步骤，或增加调用/写入 |
| drain 后 begin_restart | 核对 checker 资格、scene摘要、原 budget_ref 和一次重启额度；创建唯一新 branch；零effect补偿为 `skipped_no_effects` | 排空前准入、重置预算、复制出新额度或复用历史成功结果 |
| 重放 | B 按五步重做，全部选用新 branch 结果；metadata 的 attempt_no=2，其余四步各从1开始；独立 `recovery_round=1` | 将所有 attempt_no 都设成2；或把 failed result_id 当成功 parent |
| 重复通知/请求 | 返回同一 scene/branch 和已存在回执；计数、请求及effect均不变 | 增加第二个恢复分支、再跑五步或补发模型请求 |

失败 StepResult 可以有自己的 `result_id` 供审计，但 `fault_identity.faulty_result_id=null`，另用 `failed_attempt_id`（以及可选的 failed result record 引用）指明超时。`successful_result_ids=[]`。它不能进入只接成功 faulty_result 的旧 FaultNotice/依赖分析入口。

`freeze` 遇 active、未知提交、未知调用结算、身份或摘要不匹配时拒绝或隔离。`begin_restart` 遇未排空、资格不符、补偿冲突、未知状态、已超过一轮时不派发。一次重放再失败则保留失败，不自动再试。这里仅冻结受控同步排空；不扩展为通用异步调度器或任意晚到交错评测。

## 预算账本的最小交接

账本在分支 DB 外，仅单进程、并发1。A 提供 `campaign.reserve_call` 和 `campaign.settle_call`，B 的 runner 只拿准入/结算回执。每个真实派发前先持久化预留 call_id、一次请求及输入/输出/金额上限，再执行请求；相同 call_id 重复预留不能重复扣除或派发。重启保留同一 `campaign_budget_ref`，初始调用只作为继承身份，不计成新物理账单。

人工 TMO 在模型前停止，该步无调用、无调用预留。供应商 HTTP timeout 已可能发生费用，不属于人工 TMO：缺失 usage、结算落盘失败或提交状态不明确均暂停整轮，保留预留和未知调用，不把费用填零、不自动重发。P0 的168槽位全部尚未授权；840次正式请求上限只是将来的计划，不能由本包触发执行。

## 可以开始 P1 前还缺什么

P0 的清单、消息和静态交接已足够让三人各用假组件并行开发。P1 仍需实际实现三个 hook、P1 renderer/核验分派、部分前缀冻结/重启、一次性事件/runner/verifier、早期 checker 和 campaign 账本；再用假客户端做真正联调及旧267项回归。本包只证明静态记录相互一致，不证明这些新路径已经在 Store 里跑通。真实凭证、模型和计价可后补，不能据此默认启动真实先导。
