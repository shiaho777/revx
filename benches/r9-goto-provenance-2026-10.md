# R9 — 最终 goto 根因分类（2026-10）

最终伪代码里剩下的 `goto L<n>;` 按目标块对照 CFG 与异常元数据分类。不包装 JADX。私有 APK 不入库。不改变区域树或 legacy 文本。

## 行为

- 普查 schema 7。JSON `by_reason` 与每条 `final_goto_sites[].provenance` 使用同一组键。
- `irreducible_loop`：目标落在入口数大于 1 的循环 SCC。
- `handler`：目标是 handler 块（含 shared handler）。
- `switch`：目标出现在 `switch_cases` 里。
- `unstructured`：目标是普通 CFG 块，结构化 walk 没吸收。
- `unknown`：标签悬空或解析失败。
- raw `revisit` / `forward-revisit` 仍只描述发射路径，不抄到 final。

## 合成矩阵

| 形状 | 结果 |
| --- | --- |
| 两个循环出口与外代码汇合 | 剩余 goto 为 `unstructured` |
| 多入口 SCC 与异常相交 | 剩余 goto 为 `irreducible_loop` |
| 目标为 handler 块 | `handler` |
| 目标为 switch case | `switch` |
| `goto L99;` | `unknown` |
| 区域树成功的方法 | 无 final goto |

## 未复跑的私有语料

R3 用过的 `/tmp/revx-dex-corpus/classes.dex`（SHA-256 `656331a8…`）不在仓库中。R9 不以那次 2,924 条 final goto 作为新基线。
