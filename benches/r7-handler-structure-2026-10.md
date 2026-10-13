# R7 — handler 结构（2026-10）

在 R6 phi 降级之后、R3 区域树 walk 之前处理共享 handler 和普通入口可达 handler；循环内 try 在 walk 里把回边收成 `continue`。不包装 JADX。私有 APK 不入库。

## 行为

- 普通入口落入 handler 块：把 `__exception`（及紧随其后的拷贝）留在异常入口，普通前驱改接到后续块。
- 多个 try 共用同一 handler 块：克隆异常-only 前缀，每个 catch 独占一份。
- 新增块预算默认 32，与循环归一化、phi 降级共用剩余额度。预处理失败时不改写 CFG，方法回到原来的 `shared_handler` / `ordinary_reachable_handler` 等元数据回退。
- 循环内 try：保护块指向循环头的后继不算第二出口；join 是循环出口。不把异常边并进普通 CFG。
- 降级或区域树失败：整方法 legacy，文本与 `--mode legacy` 相同。

## 合成矩阵

| 形状 | 结果 |
| --- | --- |
| 相邻 try 共用 handler 地址 | 区域树，`structured_try_count = 2`，两段 `catch` |
| 普通入口落入 `move-exception` | 区域树，`try` / `catch`，`__exception` 只在 catch 入口 |
| try 在循环体、回边指向循环头 | 区域树，`try` 在 `while (true)` 内，普通轨迹一致 |
| 重叠 try | 仍回退 `cross_region_edge`，文本与 legacy 相同 |
| 多入口 SCC 含受保护块 | 仍回退 `loop_exception_intersection` |

普查 schema 仍为 6。回退方法的 `nodes_split` 为 0。

## 未复跑的私有语料

R3 用过的 `/tmp/revx-dex-corpus/classes.dex`（SHA-256 `656331a8…`）不在仓库中。R7 不以那次 28,903 方法的数字作为新基线。
