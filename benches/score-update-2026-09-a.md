# Plan A 阶段性复测 — 2026-09 (PR #57–#66 后)

对照 [vs-jadx-2026-09.md](vs-jadx-2026-09.md) 的首次实测。样本不变:
NativeCrypto_decrypt(libcrypto_engine, JNI 解密函数),默认路径(无任何 opt-in 环境变量)。

## 量化指标(实测)

| 指标 | 基线(#54 时) | 现在 | 变化 |
|---|---|---|---|
| 渲染行数 | 88 | **63** | -28% |
| goto 行 | 16 | 12 | -25%(剩余为真实清理汇合) |
| 块标签 | 26 | 23(其中 3 个已语义化为 cleanup_N/fail_N) | |
| `arg_N` 引用 | 32 | **0** | 签名 `JNIEnv * env, jobject thiz` |
| 溢出 store 行 | 14 | **0** | |
| 同点调用重复展开 | 3 次 | **0** | CSE |

## 输出对比(同一函数开头)

基线:
```
*((sp - 0x160) + 0x100) = x29;      // ×13 行寄存器簿记
r_GetStringChars = GetStringChars(arg_0, arg_3, 0);
if (GetStringChars(arg_0, arg_3, 0) == 0) goto bb13;
r_strlen = strlen(GetStringChars(arg_0, arg_3, 0));
```

现在:
```
jchars = GetStringChars(env, a2, 0);
if (jchars == 0) goto bb13;
len = strlen(jchars);
if (len >= 0x17) goto bb16;
```

## #54 四维评分更新(自评,同标尺)

| 维度 | 基线 | 现在 | 依据 |
|---|---|---|---|
| 变量/符号命名 | 3/10 | **5/10** | API 语义命名落地(jchars/len/env/thiz + r_<callee>);类型传播与数据流命名仍缺 |
| 控制流还原 | 4/10 | **4.5/10** | goto -25%,语义标签;if/else 语法化仍在线性路径之外 |
| 类型信息 | 6/10 | **6.5/10** | JNI 签名类型确立;局部变量类型仍是 unknown_t |
| 完成率/鲁棒 | 5/10 | **5.5/10** | lean stub 未动,但伪代码率与语料稳定性保持 141/141 |

jadx 对照(DEX 赛道)不适用变化;native 赛道 revx 独走。

## 剩余差距(按投入产出)

1. 数据流驱动的局部变量命名(x23/x24 → src/dst 指针)→ 命名 5→6
2. 区域树转默认(标签已语义化,差不可归约模式处理)→ 控制流 4.5→6
3. GetStringChars 返回类型 → `const jchar *` 传播 → 类型 6.5→7
