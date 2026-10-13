# R5 — v1 DEX 发布验收（2026-10）

## 验收范围

R4 把无 phi 的多入口循环归一化后交给 R3 区域树。R5 把这条路径和已知降级冻结成 CI 可重复的合成矩阵。私有 APK 不入库。

## 冻结矩阵

测试 `crates/revx-dex/tests/r5_acceptance.rs` 与 `crates/revx-dex/tests/loop_norm.rs`。

| 形状 | 结果 |
| --- | --- |
| 嵌套自然循环 | 区域树，`nodes_split = 0`，CFG 轨迹与区域树轨迹一致 |
| 两入口循环 | 区域树，`nodes_split >= 2`，拆分后的调用轨迹与原 CFG 一致 |
| SCC 大于默认新增块预算 32 | 不拆分，回退 `budget_exceeded`，文本与 legacy 相同 |
| 多入口 SCC 含受保护块 | 不拆分，回退 `loop_exception_intersection`，文本与 legacy 相同 |
| try 跨过循环回边 | 回退 `cross_region_edge`，文本与 legacy 相同 |
| 多入口循环带 phi | incoming 按新前驱重映射；区域树仍拒绝 phi，回退 `unsupported_control_flow`，文本与 legacy 相同 |

普查 schema 为 5。`nodes_split` 与 `loop_norm_methods` 只统计真正走区域树的拆分，回退方法计 0。`unknown_methods` 统计带结构化 unknown 的方法。final goto 的 `by_reason.unknown` 仍等于最终 goto 数。

矩阵在 debug 测试进程里的墙上时间上限是 5 秒。这只约束这组合成图，不替代 R3 报告里的私有语料 RSS。

## 未复跑的私有语料

R3 用过的 `/tmp/revx-dex-corpus/classes.dex`（SHA-256 `656331a8ee0c11dc6df090ad3b29d0126ed868c0b674a0e32d84c0fbccb0bb57`）不在仓库中，验收时本机也没有这份文件。R5 不以那次 28,903 方法的 goto 数作为本版本的新基线。R3 报告保留为那一次本地观测。

## v1 到此停止

格式能力仍按文件种类分别计算：DEX 结构化只覆盖上面矩阵里标成区域树的形状。x64、ARM64、DWARF、PDB、il2cpp 不因这次 DEX 验收被记成已完成。协程、phi 降级渲染、共享 handler 恢复不进入 R1–R5。
