# v0.3.0 职责与证据分离

新增 `--role-policy shared|separated`。默认保留 shared，以免历史计划悄悄改变含义。
使用新模式必须显式指定 `--role-policy separated`。模型、任务、故障、工具权限
保护和评分不变；本次变化是信息分工，不是承诺一定制造失败。

| 角色 | separated 模式职责和可见内容 |
|---|---|
| 诊断专家 | 查询诊断证据，负责因果判断。单专家时合并查询/锁/索引职责 |
| State | 只调用 policy、business；不能调用 activity/锁/SQL 统计，不判定阻塞根因 |
| Planner | 接收完整专家报告与权限约束；不自动附带报告引用的原始查询结果，无查询工具 |
| Reviewer | 若开启，独立重新查询 activity/policy/business，作为明确的验证对照 |
| Executor | 接收方案、State 约束和可选审核结果；不接收原始诊断结果，不充当第二诊断者 |

专家可以交流，但消息只附报告正文，不自动附 supporting_evidence。State 即使
收到“谁阻塞了谁”的问题，也只能回答自己能核实的权限/业务条件，不能补查锁。
若有两个诊断专家，它们仍能互相调查，所以先固定 `--diagnostic-experts 1`。

报告中的来源 ID 保留，表达间接来源；这不代表接收方阅读了原文。每次要求模型
生成 JSON 前，会明确列出可直接引用的 ID。Planner 应引用专家报告 ID，而不是
报告里没有展开的 observation ID。程序不默默改写模型引用或声称已读隐藏证据。
原始数据仍保存在审计里；故障通知与评分真值不进入 Agent 上下文。

Executor 可以检查方案身份、权限和业务约束，也可以返回 no_op；它并非盲执行。
公共工具 guard 仍检查当前真实权限。允许操作某个连接不代表它就是正确修复对象。
H 的 check_operation 仍可核对操作状态，但 separated 下只返回 policy/business，
不另外给 Executor 打开 activity。always 验证器是显式的额外验证方法，仍可查询
完整现场；不要把它描述成没有验证的普通流程。

## 更新与小规模验证

这是累计补丁，包含旧场景、timeout、引用修复和单专家开关，不删除 runs、不重装环境。

```bash
cd ~/private
python3 -m zipfile -e database_agent_lab_v0.3.0_patch.zip .
cd database_agent_lab
bash run.sh test

# 先确认新职责分工的 clean 可以完成
bash run.sh run --role-policy separated --diagnostic-experts 1 \
  --fault clean --verification none

# 再测试正确诊断、错误方案；Executor 不再有原始诊断数据作独立复查
bash run.sh run --role-policy separated --diagnostic-experts 1 \
  --fault wrong_plan --verification none

# 或测试一次工具结果污染
bash run.sh run --role-policy separated --diagnostic-experts 1 \
  --fault tool_pid_swap --verification none
```

先看这几次，不直接扩大矩阵。新模式可能仍纠错或拒绝不确定操作，要记录实际
行为；任务失败也不自动意味着执行了错误动作。查看 receipt 的 role_policy，
必须是 separated。shared 模式用于保留原来的强防护对照。

新模式的 full restart：

```bash
bash run.sh run --role-policy separated --diagnostic-experts 1 \
  --fault wrong_plan --verification none --restart full
```

批次可显式选择一种或两种分工：

```bash
# 生成九个新模式槽位，不调用模型
bash run.sh campaign plan --suite cdfhk --diagnostic-experts 1 \
  --role-policy separated --modes none --output campaigns/separated_dev01

# 或 shared vs separated 两组，共十八槽位；先只生成计划
bash run.sh campaign plan --suite cdfhk --diagnostic-experts 1 \
  --role-policy shared separated --modes none --output campaigns/roles_compare_dev01
```

执行预算仍需显式设置。每槽最多 48 次调用，九槽最坏 432、十八槽最坏 864。
固定同一版本、同一场景、同一人数和预算，再比较不同信息策略，不把所有差异
归因于人数。汇总按 role_policy 分组；历史未标记的数据按 shared 解释。
