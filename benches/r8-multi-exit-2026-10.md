# R8 — 多出口区域与循环内 switch（2026-10）

区域树 walk 吸收只属于循环的出口，并让 switch 臂在汇合点停下。循环内 switch 不再整方法拒绝。不包装 JADX。私有 APK 不入库。

## 行为

- 循环出口的前驱都在循环内时，把该出口收进循环成员。剩下的 follow 节点至多一个。零出口（每条路径都 return）允许。
- 两个出口都还有循环外前驱：仍回退 `unsupported_control_flow`。
- switch 多个目标：对非 loop-control 目标求 join，各臂走到 join 后在 switch 之后继续。
- 循环内 switch：指向循环头的臂是 `continue`，指向循环出口的臂是 loop-break（需要时给 `while` 加标号），其余臂按上面的 join 规则。
- 每个 case 体末尾发射 `break;`（switch-break）。失败则整方法 legacy，文本与 `--mode legacy` 相同。

## 合成矩阵

| 形状 | 结果 |
| --- | --- |
| 循环两条 return 尾巴 | 区域树，轨迹一致 |
| switch 臂在 join 汇合 | 区域树，`Trace.join()` 一次 |
| 循环内 switch（continue / body / break） | 区域树，轨迹一致 |
| 两个循环出口都与外代码汇合 | 仍回退 `unsupported_control_flow` |
| 重叠 try | 仍回退 `cross_region_edge` |

普查 schema 仍为 6。回退方法的 `nodes_split` 为 0。

## 未复跑的私有语料

R3 用过的 `/tmp/revx-dex-corpus/classes.dex`（SHA-256 `656331a8…`）不在仓库中。R8 不以那次 28,903 方法的数字作为新基线。
