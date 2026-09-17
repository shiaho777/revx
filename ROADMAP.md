# ReVX 终局路线图 v1 — DEX 反编译质量收官战

> 目标:世界上最好的全文件逆向工具。native 赛道(ELF/PE/Mach-O + il2cpp)已是独走赛道,
> 本路线图只解决最后一块:DEX 结构化质量追平并超越 jadx,然后**封版**,不再无限推进。
> 每阶段 = 1 Issue + 1 PR + 1 个可量化的验收数字,数字不动 = 阶段未完成,不得开下一阶段。

## 0. 终局定义(满足即封版)

| # | 胜利条件 | 度量方式 |
|---|---|---|
| V1 | 黄金语料上 goto 仅剩"不可归约"残留,且每条带机器可读原因标注 | `dex-goto-census` 分类计数 |
| V2 | 反编译成功率 ≥ jadx(以 jadx 自身 21% WARN 率为对标线) | 语料批处理 WARN 率 |
| V3 | while/for/do-while/switch/try-catch-finally 全部语法化,无文本降级注释 | 语料扫描降级计数 = 0 |
| V4 | 性能红线不破:lean 档 8MB、native 吞吐 ~2,700 函数/s 无回退 | `scripts/bench.sh` CSV 对比 |
| V5 | 全文件矩阵成立:DEX ∥ native × {x64, arm64} × {DWARF/PDB, il2cpp, Kotlin @Metadata} 单工具覆盖 | vs-jadx 基准表复测 |

封版后新想法进 `benches/backlog-v2.md`,不进主线。

## 1. 现状快照(2026-09-17)

- ~~分支止血~~ **已完成**:44 个提交经 PR #75/#76/#77(Issue #72/#73/#74)全部合入 main,`codex/dex-decompile` 已删除。
- 结构化引擎现状:CFG 上的递归文本 walk(`revx-dex/src/structure.rs`),靠 ~20 个文本后处理 pass 修补;**无 Region 树、无多入口循环拆分、handler 区域化只有受限雏形**(`render.rs:3593-3633` 要求孤立子图+地址连续)。
- `ssa.rs` 存在实验性 dominance region tree(`REVX_REGION_TREE` opt-in,分支 `codex/a2-region-tree-experimental`),**DEX 调用链未接入**。
- 已知问题(记录,不属于单阶段):dex decompile 输出跨进程存在非确定性(语句顺序/临时变量编号漂移,同一二进制重复运行即可复现);修复需排序 IR 收集,进 backlog-v2。

## 2. 第 0 步 — 分支止血(半天,先于一切)

44 个未合提交违背 AGENTS.md 自身流程,一旦本地丢失无法恢复。
动作:开 Issue(DEX 反编译质量线落地)→ 按 plan 分主题拆 2-3 个 PR → CI 绿 → merge。
此后所有工作恢复 Issue + PR + CI 节奏,这是"有计划"的形式保障。

## 3. 主线五阶段(每阶段独立 Issue+PR,顺序执行)

### R1 — 权威度量:goto 普查 ✅(2026-09-17 落地,PR Fixes #78)

已交付:`revx dex goto-census <path> --json [--limit N]`(crates/revx-dex/src/census.rs +
revx-engine 子命令)。最终输出计数(token 级扫描,跳过字符串/注释,只认语句位置的
`goto L<n>;`)与结构期发射诊断(revisit / forward-revisit + bailed)**分开报告**,
不做虚假归因(每条 final goto 的 provenance 显式为 unknown)。

首个真实基线(esp-overlay classes.dex,30,261 方法):
- completed 28,903 / failed 0 / skipped_codeless 1,358
- **最终输出 goto = 2,924(1,527 个方法)**;raw 发射 = 4,508(revisit 2,633 + fwd 1,875)
- 用户口中"3,280"已被此可复现数字取代(见 benches/goto-census-2026-09.md)
- 后续各阶段验收一律用此命令复跑对比。

### R2 — 异常感知 CFG(handler 的地基)

`revx-analysis::ssa::Cfg`(ssa.rs:2093)增加异常边;DEX lift 构图时把 try/handler
建模为 CFG 实体而非后处理文本标记。try/catch 组装从 `render.rs:2076` 的文本标记搬运
改为区域节点构造;`render.rs:2249` 的"失败降级为注释"路径仅在 V3 验收时允许 0 次触发。
**验收:census (b) 类 goto → 0;语料 try/catch 降级注释 = 0。**

### R3 — Region 树成为 DEX 结构化底座(架构换血,最大 PR)

把实验 region tree 从 ssa.rs opt-in 移植为 DEX 主路径:structure.rs 的文本 walk 改为
Region AST 构建再渲染。E→U 的 ~20 个文本修复 pass 逐个重新落位:能表达为区域变换的
收编为 pass,被区域语义覆盖的退役。handler 区域(try/catch/finally/共享 handler)
成为一等 Region 节点。文本路径保留一个 release 的 fallback 开关用于 A/B 回归。
**验收:渲染主路径为 AST 驱动;census (a)(b) 之外的 goto 较 R1 基线 -50%。**

### R4 — 多入口循环拆分(最难的算法攻坚)

SCC 归一化 + 节点拆分 + phi 重映射(jadx FixMultiEntryLoops 思想,clean-room 重实现)。
拆分结果落回 R3 的 Region 树,phi 修复走已有的两轮 lift 管线。
**验收:census (a) 类 goto → 0(真不可归约的按 V1 标注保留);语料循环恢复率 ≥ 95%。**

### R5 — 收敛与终局复测(关机动作)

结构化 pass 收敛式迭代到不动点(借鉴 jadx CodeShrink 多次穿插思想),清掉 (c)(d) 长尾;
跑全套 V1-V5 终局复测,数字写入 `benches/vs-jadx-2026-09.md` 增补节,发封版说明。
**验收:V1-V5 全绿 → 路线图 v1 封版,DEX 质量线关闭。**

## 4. 贯穿红线(每个 PR 必查,违反即打回)

1. `cargo test --workspace` + clippy + fmt 全绿,CI(`ci / test`)是唯一合并门。
2. `scripts/bench.sh` CSV 无回退;lean 档 8MB 预算与 native 吞吐是产品承诺,不为质量让路。
3. 141/141 语料稳定性不回退;新优化必须带 golden 输出对比。
4. 不再开字母计划散修:任何不属于 R1-R5 的新想法写入 backlog-v2,主线只认路线图。
5. jadx 是 GPL-3.0:只做行为观察与思想级 clean-room,无代码移植,保持进程隔离。

## 5. 明确不做(v1 封版前)

- 100% goto 归零:不可归约控制流保留带原因标注的 goto,这是诚实而非失败。
- 协程/续体的完整语法恢复:进 backlog-v2。
- DEX 之外的容器格式扩展(APK 签名分析、资源表):进 backlog-v2。
- 逐函数并行化(原 M4 遗留):随 R1 重测后决定是否值得。

## 6. 为什么这条线能赢

jadx 在 DEX 赛道有十年积累,正面硬拼每个语法糖不现实。revx 的取胜组合是:
**结构化质量追到第一梯队(R1-R5 做到 goto 近零、语法化完整)** + jadx 没有的维度——
native 独走、il2cpp/metadata 深度、8MB 轻量档、全文件单工具、MCP 证据链。
"超越 jadx"的落点是:**在它停下的地方继续向前(native+metadata),在它的主场做到无可指摘(V1-V5)。**
