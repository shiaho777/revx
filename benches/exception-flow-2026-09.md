# R2 异常流模型 — 本地语料观测(2026-09-17)

R2 交付 DEX 保守异常流模型与普查接入(PR Fixes #80)。本报告记录验证运行。
所有计数是**保守模型的结构事实**,不构成运行时调度证明,也不是质量结论。

## 输入标识

| 项 | 值 |
|---|---|
| 文件 | classes.dex(自 esp-overlay/app/release/app-release.apk 解包) |
| 大小 | 5,461,076 字节 |
| SHA-256 | 656331a8ee0c11dc6df090ad3b29d0126ed868c0b674a0e32d84c0fbccb0bb57 |
| 代码版本 | main 10eabea 之上的 codex/dex-exception-flow(合并前 HEAD 记录于 PR) |
| 工具链 | rustc 1.98.0,debug 构建,默认配置 |
| 命令 | `revx-engine dex goto-census <dex> --json`(全方法,无 limit) |

APK/DEX 不入库;以上哈希用于本地复跑对账。R1 运行未记录哈希,不可反推两次输入相同。

## 汇总(schema v2)

| 指标 | 值 |
|---|---:|
| try 区间 / 有效区间 | 1,731 / 1,730 |
| typed handler 引用 | 870 |
| catch-all handler 引用 | 1,110 |
| 受保护块(去重) | 3,814 |
| handler 块(去重) | 1,529 |
| 其中普通入口可达 | 156 |
| 共享 handler 地址(≥2 条 handler 引用，可来自同一 try) | 278 |
| 保守块→handler 边 | 4,419 |
| 模型诊断 | 2 |
| goto 汇总(与 R1 相同输入口径) | final 2,924 / raw 4,508 |
| 方法选择 | 30,261 定义 / 28,903 completed / 0 failed / 1,358 无代码 |

## 诊断明细(唯一含诊断的方法)

method_idx 20856,try_index 0:
- `range_not_instruction_boundary`(区间边界不在指令起始)
- `handler_not_instruction_boundary`(handler 0 地址不在指令起始)

该方法的区间与 handler 均被排除在边之外，census 仍报告方法处理完成并保留诊断。
诊断表示边界与当前解码结果不一致；可能涉及解码器或输入，尚未定位根因，不能据此断言样本损坏或加固。

## 边界与含义(不得过度解读)

- 保守边 = 每个受保护块 → 每个匹配 handler,**不论该指令是否可能抛出**;
  4,419 是上界,不是真实异常转移次数。
- `ordinary_entry_reachable_handler_blocks` 156 是普通 CFG 可达的结构事实;
  **不能**据此宣称对应方法的所有 goto 由 handler 交错导致。final goto 归因
  保持 unknown。
- shared_handlers 278 只说明 ≥2 个 try 引用同一 handler 地址,不说明文本
  渲染已正确区域化。
- goto 数字与 R1 相同(2,924/4,508)是**设计结果**(R2 不改渲染文本),
  不是不变性证明;同一份 IR 的普通/诊断渲染一致性由单元测试保证,跨进程
  文本漂移仍存在(见 R1 报告)。

## 测试与验证

- 全 workspace:317 passed / 0 failed / 6 ignored(cargo test --workspace --all-targets,exit 0)
- cargo fmt --check / clippy -D warnings / check --all-targets 全过(真实退出码)
- 新增 exception_flow.rs 8 项(含无 try 快速返回路径)+ goto_census.rs 扩展:typed/catch-all 保序、
  共享引用、普通可达、越界与非指令边界诊断、CFG 不变、同 IR 渲染相等、
  奇数 padding/非零 handler_off/size=0 编码
