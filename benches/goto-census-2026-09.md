# DEX goto 普查 — R1 单样本观测（2026-09-17）

本报告记录 R1 命令的本地运行结果，不是多语料质量排名。
用户提到的 3,280 尚无可核实的语料、版本或统计口径；不能与本报告的 2,924 比较或据此声称削减。

## 统计口径

- `final_goto_count`：最终伪代码的 `goto L<n>;` 次数；跳过字符串和注释，同目标的多个 goto 分别计数。
- `raw_emission_count`：结构化 walk 实际输出 goto 的次数。已经变为 break/continue 的分支不计入该数。
- 后处理可能删除、转换或复制文本，所以 final 与 raw 没有保证的大小关系。不能从二者差值推断每条发射的去向或删除比例。
- 最终 goto 的 provenance 是 `unknown`。raw 的 revisit/forward-revisit 是发射路径名称，不是多入口循环或 handler 交错的根因证据。
- `completed` 仅表示方法处理返回结果，不代表伪代码可编译或语义正确。

## 本地输入与历史结果

输入：本地 esp-overlay app-release.apk 的 classes.dex，5,461,076 字节。
R1 时未记录提交绑定和输入哈希；R2 报告会对其实际输入重新记录，不能反向保证两次文件相同。
APK/DEX 不随仓库发布。

```bash
revx-engine dex goto-census /path/to/classes.dex --json
```

| 指标 | R1 观测值 |
|---|---:|
| 定义方法 | 30,261 |
| completed | 28,903 |
| failed | 0 |
| skipped_codeless | 1,358 |
| 最终 goto / 含 goto 的方法 | 2,924 / 1,527 |
| raw 发射 | 4,508 |
| raw revisit / forward-revisit | 2,633 / 1,875 |
| bailed 方法 | 0 |

这是同一个样本上的两项不同计数，不是“35% 的发射已消除”的逐跳转追踪证据。

## 较多 goto 的方法

| goto | 方法 |
|---|---|
| 34 | FragmentManager.moveToState |
| 27 | BundleKt.bundleOf |
| 27 | ArraysKt.contentDeepEquals |
| 22 | FragmentTransition.addToFirstInLastOut |
| 15 | PathParser$PathDataNode.addCommand |
| 14 | BitmapCompat.createScaledBitmap / DurationKt.parseDuration / NestedScrollView.onTouchEvent |
| 12 | UriCompat.toSafeString |
| 11 | FindAddress.attemptMatch |

未在此样本上运行同配置 JADX 对照，不能断言两者的失败模式或质量相同。

## 后续验收

R2 验证保守异常流模型、共享/正常可达 handler 诊断和正常 CFG 不变；不负责降低 goto。
R3 才实现区域树与 handler 区域化，数值目标需与固定语料、正确性测试一起确定。
R4 处理多入口循环；R5 做固定版本验收。详见 [ROADMAP](../ROADMAP.md)。

## 输出确定性限制

R1 检查发现基线二进制自身的跨进程输出也存在语句顺序、临时变量编号漂移，因此跨版本字节一致性检查没有通过。
HashMap 迭代序只是候选原因，未定位确认。少数重复运行的汇总计数相同不保证所有输出或未来运行确定。
对语句排序、统一变量名或只比较计数不能证明语义等价；同一份 IR 的普通/诊断路径一致性需独立测试。
