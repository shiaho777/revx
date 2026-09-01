# 方案 A(Plan A): jadx 结构化思想的 clean-room 学习与重实现路线

> **合规边界(必读)**:本文档是**行为观察 + 算法思想记录**,不是代码移植。
> 我们没有复制 jadx 的任何源码/GPL 资产进 revx;所有结论来自对公开文档、
> 架构布局、pass 名称与输出行为的分析。jadx 是 GPL-3.0,revx 是 Apache-2.0,
> 两者必须保持进程隔离(jadx 作为外部 provider 接入)或思想级借鉴(clean-room)。
> 本文档描述后者。

## 1. jadx 为什么强:一个 53-pass 的固定管线

jadx 的核心不是某个绝妙的单点算法,而是**把反编译拆成 53 个有序 visitor pass**,
每一步只做一件小事,反复迭代直到收敛。我们从 pass 名单(公开信息)归纳出的
架构事实:

| 阶段 | 代表 pass(名称即语义) | 对应 revx 现状 |
|---|---|---|
| 元数据/符号 | OverrideMethod, Rename, UsageInfo | il2cpp metadata(已有,独家优势) |
| 指令预处理 | ProcessInstructions, AttachTryCatch, MoveInline, Constructor | 无 —— **缺口 #1** |
| 常量/内联 | ConstInline, MarkFinally(synchronized/finally 恢复) | 无 —— **缺口 #2** |
| 类型推断 | TypeInference, FixTypes, GenericTypes, ShadowField | fast 档没有;full 档只有 il2cpp 注入 —— **缺口 #3(最大)** |
| 块级结构 | BlockSplitter → BlockProcessor → DominatorTree/PostDominatorTree → FixMultiEntryLoops → BlockExceptionHandler → BlockFinisher | revx 有基本块 + 支配树(部分) |
| 区域结构化 | RegionMaker(If/Loop/Switch/Try/Sync 四个 maker)+ RegionStack | 无 —— **缺口 #4** |
| 区域后处理 | IfRegion, LoopRegion, SwitchBreak, Return, Simplify, CodeShrink(×2 次穿插) | 无 |
| 特殊语法 | EnumVisitor, SwitchOverString, ReplaceNewArray, ProcessAnonymous | 无 |
| 命名落地 | ApplyVariableNames, PrepareForCodeGen | 无 —— 即 3/10 分的直接原因 |

两个关键的**架构级思想**(思想不受版权保护):

1. **块层与区域层分离**:先把指令流整理成干净的块图(Block* 系列),
   再在块图上做区域结构化(RegionMaker 系列),最后在区域树上做后处理。
   任何一层失败都不污染其他层。revx 现在把伪代码生成直接建立在指令层,
   缺了中间两层。
2. **收敛式迭代**:同一个 pass(CodeShrink)在管线里出现多次,类型修复
   (FixTypes)与结构化交替执行直到不动点。反编译不是单趟编译,是约束求解。

## 2. revx 的重实现路线(Rust,Apache-2.0,零 jadx 代码)

按投入产出排序,每步都有 #53 基准可量化:

### Phase A1:指令整理层(对应"指令预处理")
- 常量传播 + 寄存器→SSA 化(revx 已有 SSA 雏形)
- 标准库调用识别:`GetStringChars`/`malloc`/`operator new` 等已有调用名
  (revx 的 import 识别已做到),把**调用点值域**接入表达式
- 验收:NativeCrypto.decrypt 输出中 `func_0x0000e350(6,...)` 变成
  `log_print(ANDROID_LOG_ERROR, tag, msg)` 形态

### Phase A2:区域结构化层(最大缺口)
- 实现三件套:`IfRegion`(支配树→if/else)、`LoopRegion`(后支配→
  while/for,天然支持 continue/break)、`SwitchRegion`(跳转表/比较链→
  switch-case)
- ARM64 特有:ADRP+ADD/GOT 页寻址的常量池引用折叠(PIC warning 的根因)
- 验收:控制流评分 4→7(benches/vs-jadx 同表复测)

### Phase A3:变量语义层(得分差距最大项)
- 堆栈槽→变量:revx 输出里 `*(sp - 0x60) = x29` 全是栈槽算术;引入
  StackSlot 抽象,prologue/epilogue 模式识别后整槽消除
- 寄存器生命周期→局部变量命名(`uVar1` 风格 + 类型驱动命名)
- 公共子表达式消除:`func_0x00007440(arg_0)` 同点重复展开 3 次是当前
  最刺眼的缺陷
- 验收:命名评分 3→6

### Phase A4:与 Ghidra 引擎的分工
- Phase A1-A3 覆盖日常 triage(8MB 档仍可用)
- 深度阅读用 `--engine ghidra`(vendor 已就位,质量天花板)
- 对比驱动:两个引擎跑同一函数,diff 输出作为回归测试资产

## 3. 里程碑与度量

| 里程碑 | 基准动作 | 目标 |
|---|---|---|
| M1 (A1 完成) | decrypt 函数调用语义化 | 命名 3→4,长度误差 <2× |
| M2 (A2 完成) | while/switch 出现在 decrypt | 控制流 4→7 |
| M3 (A3 完成) | 局部变量命名 + CSE | 命名 3→6,总体追 Ghidra -2 |
| M4 (持续) | libGameCore 语料 65k 函数批处理回归 | 无 panic,伪代码率不回退 |

每个里程碑独立走 Issue → PR → CI, benches/vs-jadx 复测数字写进 PR 描述。
