# ReVX v1 — 有边界的 DEX 质量路线

长期目标是全面、轻量、高性能的逆向工具，并在明确的专项上超越现有工具。
这不是当前已经实现的结论。R1–R5 只覆盖 DEX 质量主线，不代表“全文件工具”已经完成。
每阶段一个 Issue/PR，以可重复的正确性测试和明确交付物验收；阶段结束后停止，不自动扩展范围。

## 发布验收原则

- 正确性优先：减少 goto、没有警告或能生成文本，都不等于语义正确。
- 与 JADX 比较必须固定同一语料、版本、配置和任务。历史单次 WARN 率不能直接等同反编译失败率。
- 性能必须同时报告分析覆盖范围、耗时、峰值内存及构建配置。8 MB 是既有 lean 配置的预算设置，不是所有 DEX 分析的内存保证；历史 native 吞吐不是当前全任务性能承诺。
- 各文件格式、架构和元数据能力分别验收，不把 DEX 与 x64/ARM64、DWARF/PDB 等拼成未经验证的全覆盖矩阵。
- 所有无法可靠结构化的情况保留明确诊断和降级输出，不以删代码或错误内联换取 goto 归零。

## 第 0 步 — 既有提交落地：完成

44 个提交通过 PR #75、#76、#77 合入 main，Issue #72、#73、#74 已关闭。
本地旧分支已删除。缺少 upstream 跟踪本身并不能证明代码没有其他备份；这里的成果是集成与 CI 验证，不是对备份状态的断言。

## R1 — 最终输出 goto 普查：测量工具已交付

PR #79 / Issue #78。

`revx dex goto-census <path> --json [--limit N]` 分别报告最终文本 goto 和结构化阶段发射诊断。
最终计数跳过字符串/注释，不按目标标签去重。后处理可能删除、转换或复制文本，因此 final 不保证小于 raw。
最终 goto 的根因在 R1 交付时为 `unknown`；五类根因分类见 R9。

单个本地 DEX 的历史观测为：30,261 个定义方法，28,903 个有代码方法处理完成、0 个处理失败、1,358 个无代码方法；最终 goto 2,924，raw 4,508。
它不能替代来源未核实的 3,280，也不证明比其他语料或工具更优。见 [R1 报告](benches/goto-census-2026-09.md)。

## R2 — DEX 异常流模型与诊断

Issue #80。边界：独立的异常流模型与普查接入，不改变普通 CFG 或渲染文本。

- 从已解析的 try 区间与 ordered typed/catch-all handlers 构造保守潜在异常连接。
- 模型挂在 LiftOutput，记录保护块、handler BlockId、共享引用、普通入口可达性和无效地址/区间诊断。
- 不把异常边混入共享 `ssa::Cfg.succs/preds`，不改变支配树、phi 或 native 分析。
- 普查复用同一次 lift，schema v2 报告模型和统计，final goto 归因仍是 unknown。
- 用合成 DEX 与 CFG 测试验证编码、顺序、共享关系、无效输入以及正常图和同一 IR 的渲染保持不变。

完成标准：上述精确测试、CLI 和最新 PR CI 通过，附输入哈希标识的本地统计报告。
R2 不以 goto 削减或 try/catch 降级归零验收；这些属于 R3 的结构化工作。

## R3 — Region 树与 handler 区域化：首版已交付

Issue #82。边界：独立 try 区域的区域树路径 + 整方法回退；共享 handler、普通入口可达 handler、多入口循环、finally 不在本阶段强行恢复。

- `revx-dex/src/region.rs`：Region AST（Sequence/Block/If/Loop/Break/Continue/Switch/TryCatch），由 CFG walk 构建，校验所有块唯一归属、所有普通边被表达、handler 顺序与元数据一致；任何校验失败整方法回退 legacy 并带机器可读原因。
- 默认入口走 Auto（区域树→回退 legacy）；`--mode legacy` 保留旧路径；诊断 API 与默认 API 已统一走同一结构化路径。
- 普查 schema v3 报告 region/legacy 采用、结构化 try 数和回退原因分布；switch 默认边、payload 边界与共享 case 目标的 lift 修复随本阶段交付。
- 本地语料（SHA-256 656331a8…）实测：region 路径 5,121/28,903 方法（17.7%）、结构化 try 7、0 处理失败；legacy 2,982 vs auto 2,976 goto。见 [R3 报告](benches/region-tree-2026-09.md)。

验收重点已达成首版：合成 CFG-vs-Region 执行轨迹等价（菱形、循环、异常注入）、真实 DEX switch 回归、四种异常回退原因精确断言、预算回退。
共享/入口可达 handler、嵌套 try/catch 的完整结构化仍未攻克（structured_try_count=7/1,731），其主因分布见报告；具体数值目标在后续阶段冻结。

## R4 — 多入口循环归一化：已交付

SCC 检测、预算受限的整分量节点拆分，以及拆分后的 phi incoming 重映射。归一化结果只在区域树校验通过时进入 R3 渲染；失败则整方法回退 legacy，伪代码与 legacy 路径一致。

- 无 phi 的多入口循环拆成两个单入口循环，CFG 轨迹与区域树轨迹一致。
- 嵌套自然循环不拆分，内外层副作用顺序保持。
- 默认新增块预算 32。放不下的 SCC 不拆，回退原因 `budget_exceeded`。
- SCC 含受保护块或 handler 时不拆，回退原因 `loop_exception_intersection`。
- try 区间跨过循环回边时，R7 走区域树；仍不把异常边并进普通 CFG。
- 带 phi 的不可约循环会重映射 incoming，但区域树仍拒绝 phi，整方法回退 `unsupported_control_flow`。
- 不承诺任意输入 goto 归零。

验收见 `crates/revx-dex/tests/loop_norm.rs` 与 [R5 报告](benches/r5-acceptance-2026-10.md)。

## R5 — 固定范围的发布验收：已交付

CI 门禁是仓内冻结的合成能力矩阵，不是未入库的私有 DEX。

- 矩阵：`crates/revx-dex/tests/r5_acceptance.rs`。嵌套循环、多入口循环、扩张预算、循环与异常相交、跨循环 try、phi 不可约循环，各自有固定采用或回退原因。回退路径的文本与 legacy 相同。
- 普查 schema v4 增加 `nodes_split` 与 `loop_norm_methods`。final goto 归因仍是 `unknown`。
- 同配置性能：该矩阵在 debug 测试里 5 秒内跑完。这不是 R3 那份私有语料的 RSS 数字，也不外推成全文件性能承诺。
- 私有语料 SHA-256 `656331a8…` 不在仓库里，本机也没有 `/tmp/revx-dex-corpus/classes.dex`，所以 R5 没有复跑那份 APK。R3 报告里的数字继续只描述那一次本地观测。

R1–R5 到此结束。新格式和协程不在这条主线上追加。

Agent 表面（DEX evidence / skill）见 [DEX agent surface](benches/dex-agent-surface-2026-10.md)。它把区域树结果交给 MCP，不扩大结构化范围。

## R6 — Phi 降级：已交付

Issue #89。边界：在区域树 walk 之前销毁 SSA phi；失败则整方法回退 legacy，文本与 `--mode legacy` 相同。

- 前驱边上插入拷贝；关键边拆分消耗与循环归一化共用的新增块预算（默认 32 的剩余额度）。
- Auto 路径：循环归一化 → phi 降级 → 区域树。只有树校验通过才采用降级后的 CFG。
- 菱形汇合 phi、循环携带 phi、带 phi 的多入口循环走区域树；CFG 轨迹与区域树轨迹一致。
- 跨回边 try、共享 handler、普通入口可达 handler 的区域化见 R7。多出口、循环内 switch 见 R8。
- 普查 schema v6 增加 `phi_lower_methods`。final goto 归因仍是 `unknown`。

验收见 `crates/revx-dex/tests/phi_lower.rs`、`crates/revx-dex/tests/r5_acceptance.rs` 与 [R6 报告](benches/r6-phi-lowering-2026-10.md)。

## R7 — 共享 handler、入口可达 handler、循环内 try：已交付

Issue #91。边界：在 phi 降级之后、区域树 walk 之前给每个 try 独占的 catch 入口；循环内 try 把回边收成 `continue`。失败则整方法回退 legacy，文本与 `--mode legacy` 相同。不包装 JADX。

- Auto 路径：循环归一化 → phi 降级 → handler 预处理 → 区域树。预处理消耗与前两步共用的新增块预算剩余额度。
- 普通入口落入 `move-exception` 时拆出 `__exception` 入口，普通前驱改接到后续块。
- 多个 try 引用同一 handler 块时，按异常-only 前缀克隆，catch 体各自独占。
- 循环内 try：保护块的回边不算第二出口；join 仍是循环出口，catch 在 join 处停下。
- 重叠 try、循环与异常相交保持既有回退。多出口、循环内 switch 见 R8。普查 schema 仍为 6。

验收见 `crates/revx-dex/tests/handler_structure.rs`、`crates/revx-dex/tests/r5_acceptance.rs` 与 [R7 报告](benches/r7-handler-structure-2026-10.md)。

## R8 — 多出口区域与循环内 switch：已交付

Issue #93。边界：循环只吸收「前驱全在循环内」的出口；switch 臂在汇合点停下；循环内 switch 允许 continue / switch-break / 带标号的 loop-break。失败则整方法回退 legacy，文本与 `--mode legacy` 相同。不包装 JADX。

- 两条只从循环出来的 return 尾巴走区域树，CFG 轨迹与区域树轨迹一致。
- switch 臂在 join 处汇合时，join 代码只发射一次。
- 循环内 switch 走区域树；从 case 里跳出循环时给 `while` 加标号。
- 两个出口都与循环外代码汇合时仍回退 `unsupported_control_flow`。
- 重叠 try、循环与异常相交、预算行保持既有回退。普查 schema 仍为 6。

验收见 `crates/revx-dex/tests/multi_exit.rs`、`crates/revx-dex/tests/switch_lift.rs` 与 [R8 报告](benches/r8-multi-exit-2026-10.md)。

## R9 — 最终 goto 根因分类：已交付

Issue #95。边界：只给最终文本里剩下的 `goto L<n>;` 标根因，不改变区域/legacy 文本。raw 的 revisit / forward-revisit 仍是发射路径名称。普查 schema 7。不包装 JADX。私有 APK 不入库。

- `irreducible_loop`：目标在多入口循环 SCC 里。
- `handler`：目标是 handler 块。
- `switch`：目标是 switch case 目标。
- `unstructured`：其余仍在 CFG 内的跳转。
- `unknown`：悬空或无法解析的标签。
- `final_goto_count` 等于五类计数之和。

验收见 `crates/revx-dex/tests/goto_provenance.rs` 与 [R9 报告](benches/r9-goto-provenance-2026-10.md)。

## 已知降级（v1 冻结）

- 两个循环出口都与循环外代码汇合：`unsupported_control_flow`，整方法 legacy。
- 重叠 try：`cross_region_edge`。
- 多入口循环碰到异常元数据：`loop_exception_intersection`。
- 拆分预算不够：`budget_exceeded`。
- 悬空 `goto` 标签：`unknown`。
- 跨进程反编译文本漂移仍然存在。

## 已知限制与工程规则

- main 上已有跨进程反编译文本漂移（临时变量编号、语句顺序）。原因尚未确证；排序输出或统一变量名不能证明语义等价。R2 用同一份 IR 检验诊断路径，不掩盖跨进程验收的限制。
- 每个 PR：fmt、clippy、check、workspace tests 及最新 CI 全绿才合并。保留命令真实退出码，不用截断输出推断成功。
- 不上传本地 APK/DEX、完整私有分析结果、缓存或凭证。默认 CI 运行合成测试，不依赖未提供的外部语料。
- 算法实现遵守依赖与源代码许可证；不复制未经许可的代码。路线图不以对第三方工具的未经核实评价作为技术依据。
