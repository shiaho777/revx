# R10 — Native SSA 区域树默认打开（2026-10）

自研 `named_layered` 路径用后支配汇合结构化 if/else 与 while。不包装 Ghidra。私有 APK 不入库。不关闭 #59。

## 行为

- 默认走 `emit_ssa_region_tree`。walk 失败或块数 > 96 时整函数回退线性块发射。
- 两臂 join 是反向 CFG 后支配交点，不是前向支配的 NCD。
- 循环头存在被自身支配的前驱时，有 latch 的一侧成为 `while` 体。
- 一端直接落到 join 的 early-exit 发射 `if`，主路径调用仍在，cleanup 只出现一次。
- `REVX_REGION_TREE=0` 关闭区域 walk。

## 合成矩阵

| 形状 | 结果 |
| --- | --- |
| 四块菱形 then/else/join | `if` / `else` 大括号，join 调用一次，无 `goto bb` |
| 头/latch while | `while (` 包住体调用，无 `goto bb` |
| 空 then 的两级 early-exit | 主路径两次调用 + cleanup 一次，无 `goto bb` |
| 97 个返回块 | 线性 `// bb` 标签 |

## 未做

NativeCrypto_decrypt 的 A2 目标（goto ≤ 4、标签 ≤ 8）仍在 #59。本阶段不复跑私有 `.so`。
