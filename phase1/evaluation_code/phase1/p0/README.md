# P0 冻结包：任务、接口与共用假样本

协议版本：`p1_schema_version=p1.0`，`protocol_version=p0-v1`。默认正式 campaign 的预登记身份为 `p1-core-v1-pending`。

本包供三个人按同一份记录和交接规则开发。**P0 冻结完成只表示静态定义及样本可相互核对，不表示 P1 接口已经实现，也不表示工作流已经运行。** 本轮不进入 P1，不发送真实 API 请求，不启动服务器实验或云资源。

默认矩阵有 **168 个槽位、最多 840 次新增模型请求**：60 BASE、60 VERIFY_STOP、48 FULL_RESTART。当前已启动槽位为 **0**；168 行均为 `not_started`、`not_authorized`，真实 run/branch 身份为 null，实际调用和产物引用为空。先导的71次上限不在这168行内；先导和正式运行均需后续单独授权。扩展任务已冻结定义，但没有启用。

## 文件从哪里看

以下链接均相对本 README。包内清单引用通常以 `phase1/p0/` 为根；未来运行目录只是模板，不能当成已经存在的结果。计划见[修订后的 Phase 1 计划](../../outputs/phase1_execution_plan.md)。

### 六份清单

| 文件 | 内容与用途 |
| --- | --- |
| [tasks.json](manifests/tasks.json) | 12个公共任务：4开发、4核心、4扩展。保留原请求和五字段对象快照，不含答案或故障安排。每个任务有独立摘要。 |
| [trials.jsonl](manifests/trials.jsonl) | 不可变的168槽位、顺序、任务/配置引用和预算上限。FULL_RESTART 指向相邻的 parent BASE；后续运行另写审计和汇总，不覆盖登记行。 |
| [faults.private.json](manifests/faults.private.json) | 12任务×4类故障，共48份一次性定义。只在初始阶段使用，重启阶段禁用；不进入模型或公共 runtime view。 |
| [private_truth.json](manifests/private_truth.json) | 24份私有检查真值：12正常、12 STL 更新后真值。用整数商和余数独立计算，不能回填给 agent 或运行时 verifier。 |
| [protocol.json](manifests/protocol.json) | 矩阵、排序、恢复门槛、路径和摘要规则。三个重复按任务参数和固定条件排序，BASE与其重启保持相邻。 |
| [model_binding.json](manifests/model_binding.json) | 当前为 `blocked_pending_authorization`。TritonAI具体入口、模型、版本、参数支持、usage及计价仍未知，真实接入关闭；不是假定使用旧S6模型。 |

核心任务固定为 `p1-eval-01/02/03/08`，各跑 CLEAN、ERR、ADV、TMO、STL，重复1–3。BASE和VERIFY_STOP各60槽；四类故障各自预留FULL_RESTART，共48槽。恢复是否实际执行须后续判定；`not_needed`或`not_eligible`也保留该槽的汇总，不能用它们补跑其他试验。

### 四份契约资料

| 文件 | 冻结什么 |
| --- | --- |
| [contracts/README.md](contracts/README.md) | 接口使用、消息重建、三处hook和预算/恢复的详细解释。 |
| [interfaces.json](contracts/interfaces.json) | A/B/C的输入输出、错误码、调用归属和准入条件；接口均标 `implemented=false`。 |
| [records.schema.json](contracts/records.schema.json) | Draft 2020-12数据模式，约束任务、槽位、审计和汇总封装；跨记录身份及先后顺序仍需独立检查。 |
| [prompt_spec.json](contracts/prompt_spec.json) | `p1-model-v1`精确消息及摘要规则。业务bundle仍只有request/parents/tool_snapshots；公开carrier只有kind/ref/text三项。 |

旧TaskSpec、StepResult及写入回执维持1.1。对象快照实际恰有 `object_key/exists/payload/version/last_writer_id` 五字段；新增攻击文本和评估字段存P1 sidecar，不改旧业务payload。旧 `s6-model-v1`核验保留，P1按显式revision及sidecar重建消息，不能关闭核验来容纳新增文本。

### 七份共用假样本

| 文件 | 三个人要核对的边界 |
| --- | --- |
| [tmo_zero_output.json](samples/tmo_zero_output.json) | 首步TMO：零成功输出、零effect、零模型调用；冻结、晚到拒绝、排空、一次五步重启及负例。先看这一份。 |
| [normal_five_steps.json](samples/normal_five_steps.json) | 完整任务、五步父链、动作、写入回执和终态的引用关系。 |
| [err_delivered_output.json](samples/err_delivered_output.json) | 替换前私有原响应、实际交付值、调用账本及下游实际输入一致。 |
| [stale_v1_to_v2.json](samples/stale_v1_to_v2.json) | 捕获v1→合法更新v2→交付v1；旧版本提交被拒，完整重启读取并保留v2。 |
| [adv_followed.json](samples/adv_followed.json) | 假响应跟随恶意目标时，实际文本暴露、错误根和下游证据如何对应。 |
| [adv_ignored.json](samples/adv_ignored.json) | 假响应忽略攻击时保持正常；不能把它标成恢复成功或强造错误落盘。 |
| [prompt_rendering.json](samples/prompt_rendering.json) | 中性/攻击文本的固定输入、两条实际消息、carrier引用和摘要重建。 |

七份样本均为 `static_contract_fixture`；所有UUID、响应、时间、回执、ledger和预期状态都是明确的静态构造。UUID只供串联记录，不能据此声称产生了真实run、call、result或effect。样本内旧式 `StepResult.model_calls=[]`；假调用另在标明synthetic的sidecar ledger中。token、费用和性能均未测量，不能从样本推算实际成功率、时延或花费。

TMO的 `trace.record_examples` 另含6条完整StepAudit和2条TrialSummary，均可直接按schema验证；父样本的静态标记适用于这些记录，C可用它们对齐序列化字段。其余trace中的step_audits是消息/交付审计的示例投影，不冒充完整P1记录。

## 首条交接：零输出 TMO

使用dev-01的metadata查询。以下t是样本时钟，不是本轮实测；P1/P2以后才实现和运行这些断言。

| 顺序 | 交接与必须成立的状态 |
| --- | --- |
| 捕获至t=1前 | metadata attempt 1已准入，捕获v1工具快照，受控回复预定t=2到达；快照尚未交给模型。 |
| t=1超时并关闭 | 交付超时事件，关闭确切attempt。`timeout_event_delivered=true`、`tool_payload_delivered=false`、模型暴露N/A；失败payload=null，模型调用与effect均为空。 |
| t=1资格与冻结 | C给出incorrect、restart_eligible和故障身份，不返回正确字段。A确认终态可确定、无active、无未知提交/结算，冻结partial_failure现场。成功结果和effect都允许为空。 |
| t=1至t=2 | 冻结摘要保持不变。受控待交付记录放在冻结DB之外；它不等于一个仍active的Workflow attempt。 |
| t=2晚到并排空 | 按已关闭attempt拒绝旧回复，仅外部追加审计，持久化drain回执。不得修改冻结DB、再派发模型或增加写入。 |
| 排空后重启准入 | B拿C的资格和A的freeze/drain回执请求begin_restart。A核对scene摘要、同一budget引用和一次恢复额度，创建唯一新branch。零effect补偿记 `skipped_no_effects`，不造effect。 |
| 五步重放 | 从metadata重新开始，所有选定parent都来自新branch；不复用旧结果。metadata的attempt_no=2，其余四步各为1；recovery_round单独为1。 |

失败StepResult**可以有自己的result_id**供审计，但 `fault_identity.faulty_result_id=null`，用failed_attempt_id及failed_result_id定位超时。`successful_result_ids=[]`。不能将失败记录冒充成功父结果，也不能硬塞进只接受成功faulty_result的旧FaultNotice/依赖分析入口。

样本用同一外部campaign账本展示预算继承：预先seed的7次历史消耗，在五次假重放后变成12，剩余额度相应减少；**这些7和5全是假账本值，本轮真实请求仍为0。** 复制现场不复制新额度，不清空旧消耗，也不把继承的初始调用重复计费。真实usage未知或记账落盘失败时，要保留预留并暂停。

重复freeze/begin_restart请求必须以稳定request ID识别，返回同一scene、branch、recovery身份和既有回执；不能再跑五步，不能产生新call或effect。active attempt、未知终态、未知提交/结算、scene或budget引用不一致、未完成drain均禁止自动重启；超过一次恢复也拒绝。样本的负例只是这些拒绝结果的静态定义。

## 三个人如何并行

| 人 | 先实现的边界（后续P1工作） | 现在可用的替身 |
| --- | --- | --- |
| A | 旧Workflow三处窄hook；P1渲染/调用绑定；状态准入、冻结/补偿/重启；外部campaign预算。旧核心文件由A维护。 | 透传delivery、固定checker决策、假Gateway。 |
| B | 四类事件、delivery、运行时verifier、五步runner及调用A原语的一次重启编排。 | 假Gateway及本包固定freeze/begin_restart回执，不等待真实模型。 |
| C | 不可变清单、独立业务/版本判断、早期initial_checker和汇总/传播检查。 | 本包静态证据；先交restart_eligible及故障身份，不等最终报告。 |

B不另写旧Workflow或补偿/预算实现；C的检查器不修正agent输出。B的runtime verifier只用公开规则和合法source_reader，不调用C的私有评估检查器。C检查A/B证据，A检查预算计数，B检查故障到达与实际消费关系。签名、字段或摘要规则要变，先更新协议版本及样本再共同复核。

模型尚未绑定不阻碍这份P0静态协议完成，也不阻碍以后用假组件开发。live gate仍关闭；需要先完成P1/P2，再核实学校入口、模型能力、usage、计价和单独授权。

后续选定模型时，另建运行绑定记录，引用本包的freeze ID和未解析binding摘要，并保存实际模型/参数/计价/授权及新摘要；每个实际调用引用该绑定。不能覆盖P0的168行或把当前仅代表“待满足要求”的config_digest当作真实模型配置摘要。正式结果可见前才完成这次绑定和最终运行冻结；本轮不创建或启用它。

## 封存与核对结果从哪里看

[FREEZE.json](FREEZE.json)是本包文件hash清单的根，列出封存文件及摘要；验证时以它核对文件是否被改动。清单内canonical JSON摘要与封存文件的原始字节SHA-256是两种明确区分的检查，不能混用。源计划的摘要固定本次引用的计划内容。

[静态核对脚本](../../scripts/validate_phase1_p0.py)只读取资料，核对任务算术、168槽位、配对顺序、字段、身份引用、消息/摘要和TMO交接。它不启动工作流，不导入真实transport，不发API请求。结果见[本轮静态核对报告](../../outputs/phase1_p0_validation_report.json)。

在项目根目录运行 `python3 scripts/validate_phase1_p0.py` 可重新核对；脚本需要本地已安装的jsonschema（本次版本见报告），不自动安装依赖或访问网络。它只更新outputs下的静态报告，不改冻结包；实际运行记录须写到其他目录。变更已封存定义时另开协议版本，保留本包及旧摘要。

这份报告不是旧267项功能回归，也不证明新freeze/restart已可运行。P1仍须实现接口；P2须用假客户端执行真实离线联调，并保留旧S1–S6回归。正式模型性能、恢复率、时延、token和费用均留待获准后的真实试验，本包不填写这些结果。
