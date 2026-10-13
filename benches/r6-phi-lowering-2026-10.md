# R6 — Phi 降级（2026-10）

在 R4 循环归一化之后、R3 区域树 walk 之前销毁 SSA phi。不包装 JADX。私有 APK 不入库。

## 行为

- 前驱边拷贝 + 关键边拆分。新增块预算默认 32，与循环归一化共用剩余额度。
- 拆分碰到异常保护块或 handler 时拒绝本次降级，方法保持 `unsupported_control_flow` 或既有异常回退。
- 降级或区域树失败：整方法 legacy，文本与 `--mode legacy` 相同。

## 合成矩阵

| 形状 | 结果 |
| --- | --- |
| 菱形汇合 phi | 区域树，轨迹一致 |
| 循环携带 phi | 区域树，`while (true)`，轨迹一致 |
| 被使用的汇合 phi | 区域树，前驱边出现 `vN = vM` |
| 多入口循环带 phi | 区域树，`nodes_split >= 2` |
| 关键边 phi，预算充足 | 区域树 |
| 关键边 phi，拆分预算 0 | 不改写，保留 phi |
| try 跨过循环回边 | R6 时回退 `cross_region_edge`。R7 把这一行改成区域树，见 [R7 报告](r7-handler-structure-2026-10.md) |
| SCC 大于拆分预算 32 | 仍回退 `budget_exceeded` |

普查 schema 为 6。`phi_lower_methods` 统计区域路径上真正销毁过 phi 的方法。回退方法的 `nodes_split` 与 `phi_lowered` 为 0。

## 未复跑的私有语料

R3 用过的 `/tmp/revx-dex-corpus/classes.dex`（SHA-256 `656331a8…`）不在仓库中。R6 不以那次 28,903 方法的数字作为新基线。
