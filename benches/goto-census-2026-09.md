# dex goto 普查 — 首个权威基线(2026-09-17)

取代无出处的"3,280":本文件数字由 `revx dex goto-census --json` 产出,可复现。

## 口径(先读这个)

- **final_goto_count**:最终伪代码文本中的 `goto L<n>;` 语句数。token 级扫描,
  跳过字符串/注释,只认语句位置;逐条计数,不按目标去重。
- **raw_emission_count**:结构化 walk 中 emit_goto 的调用次数(revisit / forward-revisit)。
  文本后处理 pass 只消灭/转换 goto 不新增,但 break/continue/删除都会使 final < raw,
  **两者是不同指标,不得混用**。
- **provenance**:每条 final goto 的成因显式标为 unknown。raw 分类是发射路径的启发式
  标签,不构成"多入口循环"或"handler 交错"的证明——那些归因要等 R2/R3 的结构化
  诊断落地。当前诚实口径:final 计数是事实,成因是假设。

## 基线:esp-overlay app-release.apk 的 classes.dex(5.4MB)

复跑:
```bash
unzip -o app-release.apk classes.dex -d /tmp/revx-dex-corpus
revx-engine dex goto-census /tmp/revx-dex-corpus/classes.dex --json
```

| 指标 | 值 |
|---|---|
| 定义方法总数 | 30,261 |
| completed / failed | 28,903 / **0** |
| skipped_codeless | 1,358(抽象/native 方法) |
| **最终输出 goto** | **2,924**(2,924 行,1,527 个方法) |
| raw 发射 | 4,508(revisit 2,633 + forward-revisit 1,875) |
| bailed 方法 | 0 |

final/raw = 65%:35% 的发射被现有文本 pass 消灭或转换(break/continue/内联/删除)。

## Top 方法(goto 数)

| goto | 方法 |
|---|---|
| 34 | FragmentManager.moveToState |
| 27 | BundleKt.bundleOf |
| 27 | ArraysKt.contentDeepEquals |
| 22 | FragmentTransition.addToFirstInFirstOut |
| 15 | PathParser$PathDataNode.addCommand |
| 14 | BitmapCompat.createScaledBitmap / DurationKt.parseDuration / NestedScrollView.onTouchEvent |
| 12 | UriCompat.toSafeString |
| 11 | FindAddress.attemptMatch |

特征:重灾区和 jadx 相同——状态机(moveToState)、深度嵌套 equals/解析器、
多出口工具函数。没有游戏专属样本;王者语料的 .so 走 native 赛道,DEX 普查
后续补 ToolTrove-73 与 2 个开源 APK(语料就位即跑,命令同上)。

## 后续阶段验收基线

| 阶段 | 目标 |
|---|---|
| R2(异常感知 CFG) | final goto 中 handler 交错类可归因;try/catch 降级注释 = 0 |
| R3(Region 树) | final goto ≤ 1,462(基线 -50%) |
| R4(多入口循环拆分) | 多入口循环类 final goto = 0 |
| R5(收敛) | 剩余全部带机器可读成因标注 → V1 |

## 已知非确定性问题(不归本 PR 修)

`dex decompile` 输出跨进程非确定:同一二进制重复运行,语句顺序与临时变量编号
(v23/v24)、变量名(i2/i3)漂移。根因疑似 HashMap 迭代序参与命名/排序。普查命令
只输出计数与站点,数字稳定可复现;输出确定性修复进 backlog-v2。
