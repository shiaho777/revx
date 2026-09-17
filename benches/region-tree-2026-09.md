# R3 — Region 树结构化 A/B 报告（2026-09）

## 输入与构建

- 语料：`/tmp/revx-dex-corpus/classes.dex`，5,461,076 字节，SHA-256 `656331a8ee0c11dc6df090ad3b29d0126ed868c0b674a0e32d84c0fbccb0bb57`（来自 esp-overlay app-release.apk）。本地文件，未上传。
- 源码：分支 `codex/dex-region-tree`，提交 `817baee`（feat(dex): add validated region structuring with whole-method fallback）。基线 main 为 `5e198b12`。
- 构建：`cargo build -p revx-engine --release`（profile `release`）。
- 命令：`revx-engine dex goto-census /tmp/revx-dex-corpus/classes.dex --json --mode {auto|legacy}`，全量 30,261 个定义方法，无 limit。每模式 3 次独立进程观测。

## 结构化采用（三轮一致）

| 指标 | legacy | auto |
| --- | --- | --- |
| 完成方法 | 28,903 | 28,903 |
| 处理失败 | 0 | 0 |
| region 路径方法 | 0 | 5,121（17.7%） |
| legacy 回退方法 | 28,903 | 23,782 |
| 区域树结构化 try | 0 | 7 |
| 最终 goto | 2,982 | 2,976 |

auto 回退分布（三轮一致）：`unsupported_control_flow` 23,310、`cross_region_edge` 190、`shared_handler` 229、`ordinary_reachable_handler` 52、`invalid_exception_metadata` 1。

两种模式均无悬空 goto 目标、无截断。异常总量与 R2 报告一致（1,731 try、4,421 保守边、2 条诊断），不随模式变化。

## 性能（/usr/bin/time -l，三次观测）

| 模式 | real（s） | 峰值 RSS（MB） |
| --- | --- | --- |
| legacy | 13.03 / 12.05 / 11.54 | 544 / 542 / 553 |
| auto | 12.70 / 12.11 / 11.34 | 550 / 560 / 572 |

auto 与 legacy 在观测波动范围内不可区分；区域树构建预算（块 ≤256、work ≤4096、深度 ≤48）阻止了病态输入上的额外开销。单语料单机观测，不外推为普遍性能承诺。

## 口径变化（重要）

switch 默认边与 payload 边界修复合入本分支后，legacy 基线从 R1 报告的 2,924 变为 2,982（默认落点块被正确识别为 leader，raw 发射从 4,508 变为 4,727）。因此本报告不与 R1 的 2,924 直接比较降幅；同版本内比较为 legacy 2,982 vs auto 2,976。

## 未覆盖范围（如实报告）

- 99.9% 的 try 区域仍未走区域树结构化（structured_try_count=7 / 1,731）。主因是共享 handler（278 个地址）与普通入口可达 handler（156 个块）被保守拒绝，属既定边界，不在 R3 强行恢复。
- `unsupported_control_flow` 23,310 个方法：phi 节点、多出口区域、switch 嵌套循环等形状尚不支持，全部整方法回退 legacy。
- goto 降幅（6 个）不是本阶段验收指标；R3 的量化终点是"新路径被实际启用并验证"，已达成 5,121 个方法 + 7 个结构化 try + 0 处理失败。
- 已知限制继续有效：跨进程反编译文本漂移未修复；final goto 归因仍为 unknown。

## 验证

- `cargo test --workspace --all-targets`：全绿（含 19 lib + 8 exception_flow + 14 goto_census + 4 parse + 5 region_structure + 3 region_semantics + 1 switch_lift）。
- `cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all -- --check`、`cargo check --workspace --all-targets`：退出码 0。
- 合成测试覆盖：菱形分支/循环 break/continue 的 CFG-vs-Region 有界执行轨迹等价、异常注入（typed 优先、catch-all 兜底、try 外调用不进保护体、move-exception 绑定）、真实 DEX packed-switch（共享 case 目标 + default 落点）、预算回退、四种异常回退原因精确断言。
