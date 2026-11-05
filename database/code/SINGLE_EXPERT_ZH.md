# v0.2.1 单诊断专家对照

新增 `--diagnostic-experts 1|2`，默认仍是 2。旧结果不删除、不重新解释。

单专家模式只运行 diagnostic_b，将原 A 的查询/负载/索引职责合并给它，开放原
两个诊断角色可用视图的并集（最多一次读取五种视图）。diagnostic_a 不执行，
也不能被通信重新启动；诊断专家仍可向状态调查角色提问。

使用 Reviewer 时共五个角色；`verification none` 时共四个角色：

```text
单一综合诊断专家 + 状态调查 → Planner → Executor
```

这不是“没有交叉验证”的条件：状态调查仍可查询现场，Planner/Executor 仍收到
引用的原始证据、可拒绝错误方案，权限保护也不变。目的是比较一位和两位诊断者，
不同时修改证据策略、工具权限或 H 的核对协议。总调用/时间上限不变，但实际
调用和读次数会变化，必须一起报告。无追问时，none 常见 6 次，plan 常见 8 次。
少专家不保证任务失败，也不要求执行错误操作。

上传累计补丁后：

```bash
cd ~/private
python3 -m zipfile -e database_agent_lab_v0.2.1_patch.zip .
cd database_agent_lab
bash run.sh test

# 同模式 clean
bash run.sh run --diagnostic-experts 1 --fault clean --verification none
# 只污染这位专家的一次工具结果，仍保留其他真实观察
bash run.sh run --diagnostic-experts 1 --fault tool_pid_swap --verification none
```

不需要重新安装或重复数据库 smoke，数据库程序没有变化。若实例重启，按原方法
先启动 stage1 PostgreSQL。其他故障只需加相同参数，例如：

```bash
bash run.sh run --diagnostic-experts 1 --fault wrong_plan --verification none --restart full
bash run.sh run --diagnostic-experts 1 --fault stale_blocker --verification none
```

批次支持一个或两个数量条件，计划和汇总都会记录并分组：

```bash
# 单诊断专家：原九个槽位；只生成计划，不调用 API
bash run.sh campaign plan --suite cdfhk --diagnostic-experts 1 --modes none \
  --output campaigns/cdfhk_single_dev01

# 同一版代码比较 1 vs 2，共十八槽位；生成计划仍不调用 API
bash run.sh campaign plan --suite cdfhk --diagnostic-experts 1 2 --modes none \
  --output campaigns/cdfhk_counts_dev01
```

执行仍需显式的 campaign execute。九槽位最坏 432 次调用，十八槽位最坏 864 次；
预算相应设定，先通过单次开发验证再运行批次，不因看到成功或失败选择性补跑。
历史计划若没有人数标记，按原默认 2 人解释；新计划明确写入人数。
