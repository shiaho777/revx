//! Dalvik bytecode decoding and smali-style rendering.
//!
//! The decoder walks 16-bit code units; every instruction renders one line
//! of smali-style text. Payload pseudo-instructions (switch tables, array
//! data) are decoded when referenced and rendered as labeled blocks.

use crate::DexFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21cString,
    F21cType,
    F21cField,
    F21cMethod,
    F21cProto,
    F23x,
    F22b,
    F22t,
    F22s,
    F22cType,
    F22cField,
    F30t,
    F32x,
    F31i,
    F31t,
    F31cString,
    F35cMethod,
    F35cType,
    F35cCallsite,
    F3rcMethod,
    F3rcType,
    F3rcCallsite,
    F45cc,
    F4rcc,
    F51l,
}

struct OpInfo {
    mnemonic: &'static str,
    format: Format,
}

static OPS: [OpInfo; 256] = [
    OpInfo {
        mnemonic: "nop",
        format: Format::F10x,
    }, // 00
    OpInfo {
        mnemonic: "move",
        format: Format::F12x,
    }, // 01
    OpInfo {
        mnemonic: "move/from16",
        format: Format::F22x,
    }, // 02
    OpInfo {
        mnemonic: "move/16",
        format: Format::F32x,
    }, // 03
    OpInfo {
        mnemonic: "move-wide",
        format: Format::F12x,
    }, // 04
    OpInfo {
        mnemonic: "move-wide/from16",
        format: Format::F22x,
    }, // 05
    OpInfo {
        mnemonic: "move-wide/16",
        format: Format::F32x,
    }, // 06
    OpInfo {
        mnemonic: "move-object",
        format: Format::F12x,
    }, // 07
    OpInfo {
        mnemonic: "move-object/from16",
        format: Format::F22x,
    }, // 08
    OpInfo {
        mnemonic: "move-object/16",
        format: Format::F32x,
    }, // 09
    OpInfo {
        mnemonic: "move-result",
        format: Format::F11x,
    }, // 0a
    OpInfo {
        mnemonic: "move-result-wide",
        format: Format::F11x,
    }, // 0b
    OpInfo {
        mnemonic: "move-result-object",
        format: Format::F11x,
    }, // 0c
    OpInfo {
        mnemonic: "move-exception",
        format: Format::F11x,
    }, // 0d
    OpInfo {
        mnemonic: "return-void",
        format: Format::F10x,
    }, // 0e
    OpInfo {
        mnemonic: "return",
        format: Format::F11x,
    }, // 0f
    OpInfo {
        mnemonic: "return-wide",
        format: Format::F11x,
    }, // 10
    OpInfo {
        mnemonic: "return-object",
        format: Format::F11x,
    }, // 11
    OpInfo {
        mnemonic: "const/4",
        format: Format::F11n,
    }, // 12
    OpInfo {
        mnemonic: "const/16",
        format: Format::F21s,
    }, // 13
    OpInfo {
        mnemonic: "const",
        format: Format::F31i,
    }, // 14
    OpInfo {
        mnemonic: "const/high16",
        format: Format::F21h,
    }, // 15
    OpInfo {
        mnemonic: "const-wide/16",
        format: Format::F21s,
    }, // 16
    OpInfo {
        mnemonic: "const-wide/32",
        format: Format::F31i,
    }, // 17
    OpInfo {
        mnemonic: "const-wide",
        format: Format::F51l,
    }, // 18
    OpInfo {
        mnemonic: "const-wide/high16",
        format: Format::F21h,
    }, // 19
    OpInfo {
        mnemonic: "const-string",
        format: Format::F21cString,
    }, // 1a
    OpInfo {
        mnemonic: "const-string/jumbo",
        format: Format::F31cString,
    }, // 1b
    OpInfo {
        mnemonic: "const-class",
        format: Format::F21cType,
    }, // 1c
    OpInfo {
        mnemonic: "monitor-enter",
        format: Format::F11x,
    }, // 1d
    OpInfo {
        mnemonic: "monitor-exit",
        format: Format::F11x,
    }, // 1e
    OpInfo {
        mnemonic: "check-cast",
        format: Format::F21cType,
    }, // 1f
    OpInfo {
        mnemonic: "instance-of",
        format: Format::F22cType,
    }, // 20
    OpInfo {
        mnemonic: "array-length",
        format: Format::F12x,
    }, // 21
    OpInfo {
        mnemonic: "new-instance",
        format: Format::F21cType,
    }, // 22
    OpInfo {
        mnemonic: "new-array",
        format: Format::F22cType,
    }, // 23
    OpInfo {
        mnemonic: "filled-new-array",
        format: Format::F35cType,
    }, // 24
    OpInfo {
        mnemonic: "filled-new-array/range",
        format: Format::F3rcType,
    }, // 25
    OpInfo {
        mnemonic: "fill-array-data",
        format: Format::F31t,
    }, // 26
    OpInfo {
        mnemonic: "throw",
        format: Format::F11x,
    }, // 27
    OpInfo {
        mnemonic: "goto",
        format: Format::F10t,
    }, // 28
    OpInfo {
        mnemonic: "goto/16",
        format: Format::F20t,
    }, // 29
    OpInfo {
        mnemonic: "goto/32",
        format: Format::F30t,
    }, // 2a
    OpInfo {
        mnemonic: "packed-switch",
        format: Format::F31t,
    }, // 2b
    OpInfo {
        mnemonic: "sparse-switch",
        format: Format::F31t,
    }, // 2c
    OpInfo {
        mnemonic: "cmpl-float",
        format: Format::F23x,
    }, // 2d
    OpInfo {
        mnemonic: "cmpg-float",
        format: Format::F23x,
    }, // 2e
    OpInfo {
        mnemonic: "cmpl-double",
        format: Format::F23x,
    }, // 2f
    OpInfo {
        mnemonic: "cmpg-double",
        format: Format::F23x,
    }, // 30
    OpInfo {
        mnemonic: "cmp-long",
        format: Format::F23x,
    }, // 31
    OpInfo {
        mnemonic: "if-eq",
        format: Format::F22t,
    }, // 32
    OpInfo {
        mnemonic: "if-ne",
        format: Format::F22t,
    }, // 33
    OpInfo {
        mnemonic: "if-lt",
        format: Format::F22t,
    }, // 34
    OpInfo {
        mnemonic: "if-ge",
        format: Format::F22t,
    }, // 35
    OpInfo {
        mnemonic: "if-gt",
        format: Format::F22t,
    }, // 36
    OpInfo {
        mnemonic: "if-le",
        format: Format::F22t,
    }, // 37
    OpInfo {
        mnemonic: "if-eqz",
        format: Format::F21t,
    }, // 38
    OpInfo {
        mnemonic: "if-nez",
        format: Format::F21t,
    }, // 39
    OpInfo {
        mnemonic: "if-ltz",
        format: Format::F21t,
    }, // 3a
    OpInfo {
        mnemonic: "if-gez",
        format: Format::F21t,
    }, // 3b
    OpInfo {
        mnemonic: "if-gtz",
        format: Format::F21t,
    }, // 3c
    OpInfo {
        mnemonic: "if-lez",
        format: Format::F21t,
    }, // 3d
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 3e
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 3f
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 40
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 41
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 42
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 43
    OpInfo {
        mnemonic: "aget",
        format: Format::F23x,
    }, // 44
    OpInfo {
        mnemonic: "aget-wide",
        format: Format::F23x,
    }, // 45
    OpInfo {
        mnemonic: "aget-object",
        format: Format::F23x,
    }, // 46
    OpInfo {
        mnemonic: "aget-boolean",
        format: Format::F23x,
    }, // 47
    OpInfo {
        mnemonic: "aget-byte",
        format: Format::F23x,
    }, // 48
    OpInfo {
        mnemonic: "aget-char",
        format: Format::F23x,
    }, // 49
    OpInfo {
        mnemonic: "aget-short",
        format: Format::F23x,
    }, // 4a
    OpInfo {
        mnemonic: "aput",
        format: Format::F23x,
    }, // 4b
    OpInfo {
        mnemonic: "aput-wide",
        format: Format::F23x,
    }, // 4c
    OpInfo {
        mnemonic: "aput-object",
        format: Format::F23x,
    }, // 4d
    OpInfo {
        mnemonic: "aput-boolean",
        format: Format::F23x,
    }, // 4e
    OpInfo {
        mnemonic: "aput-byte",
        format: Format::F23x,
    }, // 4f
    OpInfo {
        mnemonic: "aput-char",
        format: Format::F23x,
    }, // 50
    OpInfo {
        mnemonic: "aput-short",
        format: Format::F23x,
    }, // 51
    OpInfo {
        mnemonic: "iget",
        format: Format::F22cField,
    }, // 52
    OpInfo {
        mnemonic: "iget-wide",
        format: Format::F22cField,
    }, // 53
    OpInfo {
        mnemonic: "iget-object",
        format: Format::F22cField,
    }, // 54
    OpInfo {
        mnemonic: "iget-boolean",
        format: Format::F22cField,
    }, // 55
    OpInfo {
        mnemonic: "iget-byte",
        format: Format::F22cField,
    }, // 56
    OpInfo {
        mnemonic: "iget-char",
        format: Format::F22cField,
    }, // 57
    OpInfo {
        mnemonic: "iget-short",
        format: Format::F22cField,
    }, // 58
    OpInfo {
        mnemonic: "iput",
        format: Format::F22cField,
    }, // 59
    OpInfo {
        mnemonic: "iput-wide",
        format: Format::F22cField,
    }, // 5a
    OpInfo {
        mnemonic: "iput-object",
        format: Format::F22cField,
    }, // 5b
    OpInfo {
        mnemonic: "iput-boolean",
        format: Format::F22cField,
    }, // 5c
    OpInfo {
        mnemonic: "iput-byte",
        format: Format::F22cField,
    }, // 5d
    OpInfo {
        mnemonic: "iput-char",
        format: Format::F22cField,
    }, // 5e
    OpInfo {
        mnemonic: "iput-short",
        format: Format::F22cField,
    }, // 5f
    OpInfo {
        mnemonic: "sget",
        format: Format::F21cField,
    }, // 60
    OpInfo {
        mnemonic: "sget-wide",
        format: Format::F21cField,
    }, // 61
    OpInfo {
        mnemonic: "sget-object",
        format: Format::F21cField,
    }, // 62
    OpInfo {
        mnemonic: "sget-boolean",
        format: Format::F21cField,
    }, // 63
    OpInfo {
        mnemonic: "sget-byte",
        format: Format::F21cField,
    }, // 64
    OpInfo {
        mnemonic: "sget-char",
        format: Format::F21cField,
    }, // 65
    OpInfo {
        mnemonic: "sget-short",
        format: Format::F21cField,
    }, // 66
    OpInfo {
        mnemonic: "sput",
        format: Format::F21cField,
    }, // 67
    OpInfo {
        mnemonic: "sput-wide",
        format: Format::F21cField,
    }, // 68
    OpInfo {
        mnemonic: "sput-object",
        format: Format::F21cField,
    }, // 69
    OpInfo {
        mnemonic: "sput-boolean",
        format: Format::F21cField,
    }, // 6a
    OpInfo {
        mnemonic: "sput-byte",
        format: Format::F21cField,
    }, // 6b
    OpInfo {
        mnemonic: "sput-char",
        format: Format::F21cField,
    }, // 6c
    OpInfo {
        mnemonic: "sput-short",
        format: Format::F21cField,
    }, // 6d
    OpInfo {
        mnemonic: "invoke-virtual",
        format: Format::F35cMethod,
    }, // 6e
    OpInfo {
        mnemonic: "invoke-super",
        format: Format::F35cMethod,
    }, // 6f
    OpInfo {
        mnemonic: "invoke-direct",
        format: Format::F35cMethod,
    }, // 70
    OpInfo {
        mnemonic: "invoke-static",
        format: Format::F35cMethod,
    }, // 71
    OpInfo {
        mnemonic: "invoke-interface",
        format: Format::F35cMethod,
    }, // 72
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 73
    OpInfo {
        mnemonic: "invoke-virtual/range",
        format: Format::F3rcMethod,
    }, // 74
    OpInfo {
        mnemonic: "invoke-super/range",
        format: Format::F3rcMethod,
    }, // 75
    OpInfo {
        mnemonic: "invoke-direct/range",
        format: Format::F3rcMethod,
    }, // 76
    OpInfo {
        mnemonic: "invoke-static/range",
        format: Format::F3rcMethod,
    }, // 77
    OpInfo {
        mnemonic: "invoke-interface/range",
        format: Format::F3rcMethod,
    }, // 78
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 79
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // 7a
    OpInfo {
        mnemonic: "neg-int",
        format: Format::F12x,
    }, // 7b
    OpInfo {
        mnemonic: "not-int",
        format: Format::F12x,
    }, // 7c
    OpInfo {
        mnemonic: "neg-long",
        format: Format::F12x,
    }, // 7d
    OpInfo {
        mnemonic: "not-long",
        format: Format::F12x,
    }, // 7e
    OpInfo {
        mnemonic: "neg-float",
        format: Format::F12x,
    }, // 7f
    OpInfo {
        mnemonic: "neg-double",
        format: Format::F12x,
    }, // 80
    OpInfo {
        mnemonic: "int-to-long",
        format: Format::F12x,
    }, // 81
    OpInfo {
        mnemonic: "int-to-float",
        format: Format::F12x,
    }, // 82
    OpInfo {
        mnemonic: "int-to-double",
        format: Format::F12x,
    }, // 83
    OpInfo {
        mnemonic: "long-to-int",
        format: Format::F12x,
    }, // 84
    OpInfo {
        mnemonic: "long-to-float",
        format: Format::F12x,
    }, // 85
    OpInfo {
        mnemonic: "long-to-double",
        format: Format::F12x,
    }, // 86
    OpInfo {
        mnemonic: "float-to-int",
        format: Format::F12x,
    }, // 87
    OpInfo {
        mnemonic: "float-to-long",
        format: Format::F12x,
    }, // 88
    OpInfo {
        mnemonic: "float-to-double",
        format: Format::F12x,
    }, // 89
    OpInfo {
        mnemonic: "double-to-int",
        format: Format::F12x,
    }, // 8a
    OpInfo {
        mnemonic: "double-to-long",
        format: Format::F12x,
    }, // 8b
    OpInfo {
        mnemonic: "double-to-float",
        format: Format::F12x,
    }, // 8c
    OpInfo {
        mnemonic: "int-to-byte",
        format: Format::F12x,
    }, // 8d
    OpInfo {
        mnemonic: "int-to-char",
        format: Format::F12x,
    }, // 8e
    OpInfo {
        mnemonic: "int-to-short",
        format: Format::F12x,
    }, // 8f
    OpInfo {
        mnemonic: "add-int",
        format: Format::F23x,
    }, // 90
    OpInfo {
        mnemonic: "sub-int",
        format: Format::F23x,
    }, // 91
    OpInfo {
        mnemonic: "mul-int",
        format: Format::F23x,
    }, // 92
    OpInfo {
        mnemonic: "div-int",
        format: Format::F23x,
    }, // 93
    OpInfo {
        mnemonic: "rem-int",
        format: Format::F23x,
    }, // 94
    OpInfo {
        mnemonic: "and-int",
        format: Format::F23x,
    }, // 95
    OpInfo {
        mnemonic: "or-int",
        format: Format::F23x,
    }, // 96
    OpInfo {
        mnemonic: "xor-int",
        format: Format::F23x,
    }, // 97
    OpInfo {
        mnemonic: "shl-int",
        format: Format::F23x,
    }, // 98
    OpInfo {
        mnemonic: "shr-int",
        format: Format::F23x,
    }, // 99
    OpInfo {
        mnemonic: "ushr-int",
        format: Format::F23x,
    }, // 9a
    OpInfo {
        mnemonic: "add-long",
        format: Format::F23x,
    }, // 9b
    OpInfo {
        mnemonic: "sub-long",
        format: Format::F23x,
    }, // 9c
    OpInfo {
        mnemonic: "mul-long",
        format: Format::F23x,
    }, // 9d
    OpInfo {
        mnemonic: "div-long",
        format: Format::F23x,
    }, // 9e
    OpInfo {
        mnemonic: "rem-long",
        format: Format::F23x,
    }, // 9f
    OpInfo {
        mnemonic: "and-long",
        format: Format::F23x,
    }, // a0
    OpInfo {
        mnemonic: "or-long",
        format: Format::F23x,
    }, // a1
    OpInfo {
        mnemonic: "xor-long",
        format: Format::F23x,
    }, // a2
    OpInfo {
        mnemonic: "shl-long",
        format: Format::F23x,
    }, // a3
    OpInfo {
        mnemonic: "shr-long",
        format: Format::F23x,
    }, // a4
    OpInfo {
        mnemonic: "ushr-long",
        format: Format::F23x,
    }, // a5
    OpInfo {
        mnemonic: "add-float",
        format: Format::F23x,
    }, // a6
    OpInfo {
        mnemonic: "sub-float",
        format: Format::F23x,
    }, // a7
    OpInfo {
        mnemonic: "mul-float",
        format: Format::F23x,
    }, // a8
    OpInfo {
        mnemonic: "div-float",
        format: Format::F23x,
    }, // a9
    OpInfo {
        mnemonic: "rem-float",
        format: Format::F23x,
    }, // aa
    OpInfo {
        mnemonic: "add-double",
        format: Format::F23x,
    }, // ab
    OpInfo {
        mnemonic: "sub-double",
        format: Format::F23x,
    }, // ac
    OpInfo {
        mnemonic: "mul-double",
        format: Format::F23x,
    }, // ad
    OpInfo {
        mnemonic: "div-double",
        format: Format::F23x,
    }, // ae
    OpInfo {
        mnemonic: "rem-double",
        format: Format::F23x,
    }, // af
    OpInfo {
        mnemonic: "add-int/2addr",
        format: Format::F12x,
    }, // b0
    OpInfo {
        mnemonic: "sub-int/2addr",
        format: Format::F12x,
    }, // b1
    OpInfo {
        mnemonic: "mul-int/2addr",
        format: Format::F12x,
    }, // b2
    OpInfo {
        mnemonic: "div-int/2addr",
        format: Format::F12x,
    }, // b3
    OpInfo {
        mnemonic: "rem-int/2addr",
        format: Format::F12x,
    }, // b4
    OpInfo {
        mnemonic: "and-int/2addr",
        format: Format::F12x,
    }, // b5
    OpInfo {
        mnemonic: "or-int/2addr",
        format: Format::F12x,
    }, // b6
    OpInfo {
        mnemonic: "xor-int/2addr",
        format: Format::F12x,
    }, // b7
    OpInfo {
        mnemonic: "shl-int/2addr",
        format: Format::F12x,
    }, // b8
    OpInfo {
        mnemonic: "shr-int/2addr",
        format: Format::F12x,
    }, // b9
    OpInfo {
        mnemonic: "ushr-int/2addr",
        format: Format::F12x,
    }, // ba
    OpInfo {
        mnemonic: "add-long/2addr",
        format: Format::F12x,
    }, // bb
    OpInfo {
        mnemonic: "sub-long/2addr",
        format: Format::F12x,
    }, // bc
    OpInfo {
        mnemonic: "mul-long/2addr",
        format: Format::F12x,
    }, // bd
    OpInfo {
        mnemonic: "div-long/2addr",
        format: Format::F12x,
    }, // be
    OpInfo {
        mnemonic: "rem-long/2addr",
        format: Format::F12x,
    }, // bf
    OpInfo {
        mnemonic: "and-long/2addr",
        format: Format::F12x,
    }, // c0
    OpInfo {
        mnemonic: "or-long/2addr",
        format: Format::F12x,
    }, // c1
    OpInfo {
        mnemonic: "xor-long/2addr",
        format: Format::F12x,
    }, // c2
    OpInfo {
        mnemonic: "shl-long/2addr",
        format: Format::F12x,
    }, // c3
    OpInfo {
        mnemonic: "shr-long/2addr",
        format: Format::F12x,
    }, // c4
    OpInfo {
        mnemonic: "ushr-long/2addr",
        format: Format::F12x,
    }, // c5
    OpInfo {
        mnemonic: "add-float/2addr",
        format: Format::F12x,
    }, // c6
    OpInfo {
        mnemonic: "sub-float/2addr",
        format: Format::F12x,
    }, // c7
    OpInfo {
        mnemonic: "mul-float/2addr",
        format: Format::F12x,
    }, // c8
    OpInfo {
        mnemonic: "div-float/2addr",
        format: Format::F12x,
    }, // c9
    OpInfo {
        mnemonic: "rem-float/2addr",
        format: Format::F12x,
    }, // ca
    OpInfo {
        mnemonic: "add-double/2addr",
        format: Format::F12x,
    }, // cb
    OpInfo {
        mnemonic: "sub-double/2addr",
        format: Format::F12x,
    }, // cc
    OpInfo {
        mnemonic: "mul-double/2addr",
        format: Format::F12x,
    }, // cd
    OpInfo {
        mnemonic: "div-double/2addr",
        format: Format::F12x,
    }, // ce
    OpInfo {
        mnemonic: "rem-double/2addr",
        format: Format::F12x,
    }, // cf
    OpInfo {
        mnemonic: "add-int/lit16",
        format: Format::F22s,
    }, // d0
    OpInfo {
        mnemonic: "rsub-int",
        format: Format::F22s,
    }, // d1
    OpInfo {
        mnemonic: "mul-int/lit16",
        format: Format::F22s,
    }, // d2
    OpInfo {
        mnemonic: "div-int/lit16",
        format: Format::F22s,
    }, // d3
    OpInfo {
        mnemonic: "rem-int/lit16",
        format: Format::F22s,
    }, // d4
    OpInfo {
        mnemonic: "and-int/lit16",
        format: Format::F22s,
    }, // d5
    OpInfo {
        mnemonic: "or-int/lit16",
        format: Format::F22s,
    }, // d6
    OpInfo {
        mnemonic: "xor-int/lit16",
        format: Format::F22s,
    }, // d7
    OpInfo {
        mnemonic: "add-int/lit8",
        format: Format::F22b,
    }, // d8
    OpInfo {
        mnemonic: "rsub-int/lit8",
        format: Format::F22b,
    }, // d9
    OpInfo {
        mnemonic: "mul-int/lit8",
        format: Format::F22b,
    }, // da
    OpInfo {
        mnemonic: "div-int/lit8",
        format: Format::F22b,
    }, // db
    OpInfo {
        mnemonic: "rem-int/lit8",
        format: Format::F22b,
    }, // dc
    OpInfo {
        mnemonic: "and-int/lit8",
        format: Format::F22b,
    }, // dd
    OpInfo {
        mnemonic: "or-int/lit8",
        format: Format::F22b,
    }, // de
    OpInfo {
        mnemonic: "xor-int/lit8",
        format: Format::F22b,
    }, // df
    OpInfo {
        mnemonic: "shl-int/lit8",
        format: Format::F22b,
    }, // e0
    OpInfo {
        mnemonic: "shr-int/lit8",
        format: Format::F22b,
    }, // e1
    OpInfo {
        mnemonic: "ushr-int/lit8",
        format: Format::F22b,
    }, // e2
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e3
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e4
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e5
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e6
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e7
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e8
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // e9
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // ea
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // eb
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // ec
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // ed
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // ee
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // ef
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f0
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f1
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f2
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f3
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f4
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f5
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f6
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f7
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f8
    OpInfo {
        mnemonic: "unused",
        format: Format::F10x,
    }, // f9
    OpInfo {
        mnemonic: "invoke-polymorphic",
        format: Format::F45cc,
    }, // fa
    OpInfo {
        mnemonic: "invoke-polymorphic/range",
        format: Format::F4rcc,
    }, // fb
    OpInfo {
        mnemonic: "invoke-custom",
        format: Format::F35cCallsite,
    }, // fc
    OpInfo {
        mnemonic: "invoke-custom/range",
        format: Format::F3rcCallsite,
    }, // fd
    OpInfo {
        mnemonic: "const-method-handle",
        format: Format::F21cMethod,
    }, // fe
    OpInfo {
        mnemonic: "const-method-type",
        format: Format::F21cProto,
    }, // ff
];

pub struct DecodedInsn {
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub size_units: usize,
    pub text: String,
    pub branch_target: Option<u32>,
}

fn u16_at(units: &[u16], i: usize) -> u16 {
    units.get(i).copied().unwrap_or(0)
}

fn i16_at(units: &[u16], i: usize) -> i16 {
    u16_at(units, i) as i16
}

fn u32_at(units: &[u16], i: usize) -> u32 {
    let lo = u16_at(units, i) as u32;
    let hi = u16_at(units, i + 1) as u32;
    lo | (hi << 16)
}

fn i32_at(units: &[u16], i: usize) -> i32 {
    u32_at(units, i) as i32
}

fn fmt_target(off: u32, delta: i64) -> u32 {
    off.wrapping_add(delta as u32)
}

fn render_regs35c(count: u8, nibbles: [u8; 5]) -> String {
    let regs: Vec<String> = nibbles
        .iter()
        .take(count.min(5) as usize)
        .map(|r| format!("v{r}"))
        .collect();
    format!("{{{}}}", regs.join(", "))
}

pub fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn decode_insn(dex: &DexFile, units: &[u16], off: usize) -> Option<DecodedInsn> {
    let w0 = u16_at(units, off);
    let op = (w0 & 0xff) as u8;
    let info = &OPS[op as usize];
    let mnem = info.mnemonic;
    let b1 = (w0 >> 8) as u8;
    let a_nib = b1 & 0x0f;
    let b_nib = b1 >> 4;
    let off32 = off as u32;
    let mk = |size: usize, text: String, branch: Option<u32>| {
        Some(DecodedInsn {
            opcode: op,
            mnemonic: mnem,
            size_units: size,
            text,
            branch_target: branch,
        })
    };
    match info.format {
        Format::F10x => mk(1, mnem.to_string(), None),
        Format::F12x => mk(1, format!("{mnem} v{a_nib}, v{b_nib}"), None),
        Format::F11n => {
            let lit = ((b_nib as i8) << 4 >> 4) as i32;
            mk(1, format!("{mnem} v{a_nib}, #{lit}"), None)
        }
        Format::F11x => mk(1, format!("{mnem} v{b1}"), None),
        Format::F10t => {
            let delta = b1 as i8;
            let t = fmt_target(off32, delta as i64);
            mk(1, format!("{mnem} :L{t:x}"), Some(t))
        }
        Format::F20t => {
            let delta = i16_at(units, off + 1);
            let t = fmt_target(off32, delta as i64);
            mk(2, format!("{mnem} :L{t:x}"), Some(t))
        }
        Format::F22x => {
            let b = u16_at(units, off + 1);
            mk(2, format!("{mnem} v{b1}, v{b}"), None)
        }
        Format::F21t => {
            let delta = i16_at(units, off + 1);
            let t = fmt_target(off32, delta as i64);
            mk(2, format!("{mnem} v{b1}, :L{t:x}"), Some(t))
        }
        Format::F21s => {
            let lit = i16_at(units, off + 1);
            mk(2, format!("{mnem} v{b1}, #{lit}"), None)
        }
        Format::F21h => {
            let raw = u16_at(units, off + 1);
            let lit = (raw as i16 as i64) << 16;
            mk(2, format!("{mnem} v{b1}, #{lit}"), None)
        }
        Format::F21cString => {
            let idx = u16_at(units, off + 1) as u32;
            let s = escape_string(dex.string_value(idx));
            mk(2, format!("{mnem} v{b1}, \"{s}\""), None)
        }
        Format::F21cType => {
            let idx = u16_at(units, off + 1) as u32;
            let t = dex.type_name(idx);
            mk(2, format!("{mnem} v{b1}, {t}"), None)
        }
        Format::F21cField => {
            let idx = u16_at(units, off + 1) as u32;
            let r = dex.field_reference(idx);
            mk(2, format!("{mnem} v{b1}, {r}"), None)
        }
        Format::F21cMethod => {
            let idx = u16_at(units, off + 1) as u32;
            let r = dex.method_signature(idx);
            mk(2, format!("{mnem} v{b1}, {r}"), None)
        }
        Format::F21cProto => {
            let idx = u16_at(units, off + 1) as u32;
            let r = dex
                .protos
                .get(idx as usize)
                .map(|p| format!("({}){}", p.parameters.join(""), p.return_type))
                .unwrap_or_else(|| format!("proto@{idx}"));
            mk(2, format!("{mnem} v{b1}, {r}"), None)
        }
        Format::F23x => {
            let b = (u16_at(units, off + 1) & 0xff) as u8;
            let c = (u16_at(units, off + 1) >> 8) as u8;
            mk(2, format!("{mnem} v{b1}, v{b}, v{c}"), None)
        }
        Format::F22b => {
            let w1 = u16_at(units, off + 1);
            let b = (w1 & 0xff) as u8;
            let lit = (w1 >> 8) as u8 as i8;
            mk(2, format!("{mnem} v{b1}, v{b}, #{lit}"), None)
        }
        Format::F22t => {
            let delta = i16_at(units, off + 1);
            let t = fmt_target(off32, delta as i64);
            mk(2, format!("{mnem} v{a_nib}, v{b_nib}, :L{t:x}"), Some(t))
        }
        Format::F22s => {
            let lit = i16_at(units, off + 1);
            mk(2, format!("{mnem} v{a_nib}, v{b_nib}, #{lit}"), None)
        }
        Format::F22cType => {
            let idx = u16_at(units, off + 1) as u32;
            let t = dex.type_name(idx);
            mk(2, format!("{mnem} v{a_nib}, v{b_nib}, {t}"), None)
        }
        Format::F22cField => {
            let idx = u16_at(units, off + 1) as u32;
            let r = dex.field_reference(idx);
            mk(2, format!("{mnem} v{a_nib}, v{b_nib}, {r}"), None)
        }
        Format::F30t => {
            let delta = i32_at(units, off + 1);
            let t = fmt_target(off32, delta as i64);
            mk(3, format!("{mnem} :L{t:x}"), Some(t))
        }
        Format::F32x => {
            let a = u16_at(units, off + 1);
            let b = u16_at(units, off + 2);
            mk(3, format!("{mnem} v{a}, v{b}"), None)
        }
        Format::F31i => {
            let lit = i32_at(units, off + 1);
            mk(3, format!("{mnem} v{b1}, #{lit}"), None)
        }
        Format::F31t => {
            let delta = i32_at(units, off + 1);
            let t = fmt_target(off32, delta as i64);
            mk(3, format!("{mnem} v{b1}, :L{t:x}"), Some(t))
        }
        Format::F31cString => {
            let idx = u32_at(units, off + 1);
            let s = escape_string(dex.string_value(idx));
            mk(3, format!("{mnem} v{b1}, \"{s}\""), None)
        }
        Format::F35cMethod | Format::F35cType | Format::F35cCallsite => {
            let count = b_nib;
            let g = a_nib;
            let idx = u16_at(units, off + 1) as u32;
            let w3 = u16_at(units, off + 2);
            let c = (w3 & 0x0f) as u8;
            let d = ((w3 >> 4) & 0x0f) as u8;
            let e = ((w3 >> 8) & 0x0f) as u8;
            let f = ((w3 >> 12) & 0x0f) as u8;
            let regs = render_regs35c(count, [c, d, e, f, g]);
            let what = match info.format {
                Format::F35cMethod => dex.method_signature(idx),
                Format::F35cType => dex.type_name(idx),
                _ => format!("call_site@{idx}"),
            };
            mk(3, format!("{mnem} {regs}, {what}"), None)
        }
        Format::F3rcMethod | Format::F3rcType | Format::F3rcCallsite => {
            let count = b1;
            let idx = u16_at(units, off + 1) as u32;
            let start = u16_at(units, off + 2);
            let what = match info.format {
                Format::F3rcMethod => dex.method_signature(idx),
                Format::F3rcType => dex.type_name(idx),
                _ => format!("call_site@{idx}"),
            };
            mk(
                3,
                format!(
                    "{mnem} {{v{start} .. v{}}}, {what}",
                    start as u32 + count as u32 - (count > 0) as u32
                ),
                None,
            )
        }
        Format::F45cc => {
            let count = b_nib;
            let g = a_nib;
            let meth = u16_at(units, off + 1) as u32;
            let proto = u16_at(units, off + 3) as u32;
            let w3 = u16_at(units, off + 2);
            let c = (w3 & 0x0f) as u8;
            let d = ((w3 >> 4) & 0x0f) as u8;
            let e = ((w3 >> 8) & 0x0f) as u8;
            let f = ((w3 >> 12) & 0x0f) as u8;
            let regs = render_regs35c(count, [c, d, e, f, g]);
            let ms = dex.method_signature(meth);
            let ps = dex
                .protos
                .get(proto as usize)
                .map(|p| format!("({}){}", p.parameters.join(""), p.return_type))
                .unwrap_or_else(|| format!("proto@{proto}"));
            mk(4, format!("{mnem} {regs}, {ms}, {ps}"), None)
        }
        Format::F4rcc => {
            let count = b1;
            let meth = u16_at(units, off + 1) as u32;
            let start = u16_at(units, off + 2);
            let proto = u16_at(units, off + 3) as u32;
            let ms = dex.method_signature(meth);
            let ps = dex
                .protos
                .get(proto as usize)
                .map(|p| format!("({}){}", p.parameters.join(""), p.return_type))
                .unwrap_or_else(|| format!("proto@{proto}"));
            mk(
                4,
                format!(
                    "{mnem} {{v{start} .. v{}}}, {ms}, {ps}",
                    start as u32 + count as u32 - (count > 0) as u32
                ),
                None,
            )
        }
        Format::F51l => {
            let lo = u32_at(units, off + 1) as u64;
            let hi = u32_at(units, off + 3) as u64;
            let lit = (lo | (hi << 32)) as i64;
            mk(5, format!("{mnem} v{b1}, #{lit}"), None)
        }
    }
}

#[derive(Debug, Clone)]
pub enum Payload {
    PackedSwitch {
        first_key: i32,
        targets: Vec<i32>,
        size_units: usize,
    },
    SparseSwitch {
        keys: Vec<i32>,
        targets: Vec<i32>,
        size_units: usize,
    },
    FillArrayData {
        element_width: u16,
        size: u32,
        size_units: usize,
    },
}

pub fn decode_payload(units: &[u16], off: usize) -> Option<Payload> {
    let ident = u16_at(units, off);
    match ident {
        0x0100 => {
            let size = u16_at(units, off + 1) as usize;
            let first_key = i32_at(units, off + 2);
            let mut targets = Vec::with_capacity(size);
            for i in 0..size {
                targets.push(i32_at(units, off + 4 + i * 2));
            }
            Some(Payload::PackedSwitch {
                first_key,
                size_units: 4 + size * 2,
                targets,
            })
        }
        0x0200 => {
            let size = u16_at(units, off + 1) as usize;
            let mut keys = Vec::with_capacity(size);
            let mut targets = Vec::with_capacity(size);
            for i in 0..size {
                keys.push(i32_at(units, off + 2 + i * 2));
            }
            for i in 0..size {
                targets.push(i32_at(units, off + 2 + size * 2 + i * 2));
            }
            Some(Payload::SparseSwitch {
                keys,
                targets,
                size_units: 2 + size * 4,
            })
        }
        0x0300 => {
            let element_width = u16_at(units, off + 1);
            let size = u32_at(units, off + 2);
            let bytes = element_width as usize * size as usize;
            let size_units = 4 + bytes.div_ceil(2);
            Some(Payload::FillArrayData {
                element_width,
                size,
                size_units,
            })
        }
        _ => None,
    }
}

pub struct MethodDisasm {
    pub lines: Vec<String>,
    pub branch_targets: Vec<(u32, u32)>,
}

pub fn disassemble_method(dex: &DexFile, insns: &[u16]) -> MethodDisasm {
    let mut lines = Vec::new();
    let mut edges = Vec::new();
    let mut payload_offsets: Vec<u32> = Vec::new();
    let mut off = 0usize;
    while off < insns.len() {
        let Some(d) = decode_insn(dex, insns, off) else {
            lines.push(format!("{:04x}: <bad>", off));
            off += 1;
            continue;
        };
        if (d.mnemonic == "fill-array-data"
            || d.mnemonic == "packed-switch"
            || d.mnemonic == "sparse-switch")
            && let Some(t) = d.branch_target
        {
            payload_offsets.push(t);
        }
        if let Some(t) = d.branch_target {
            edges.push((off as u32, t));
        }
        lines.push(format!("{:04x}: {}", off, d.text));
        off += d.size_units.max(1);
    }
    for poff in payload_offsets {
        let Some(p) = decode_payload(insns, poff as usize) else {
            continue;
        };
        match p {
            Payload::PackedSwitch {
                first_key, targets, ..
            } => {
                lines.push(format!(
                    "{poff:04x}: packed-switch-payload first_key={first_key}"
                ));
                for (i, t) in targets.iter().enumerate() {
                    lines.push(format!("    case {}: -> {t:+}", first_key + i as i32));
                }
            }
            Payload::SparseSwitch { keys, targets, .. } => {
                lines.push(format!("{poff:04x}: sparse-switch-payload"));
                for (k, t) in keys.iter().zip(targets.iter()) {
                    lines.push(format!("    case {k}: -> {t:+}"));
                }
            }
            Payload::FillArrayData {
                element_width,
                size,
                size_units,
            } => {
                lines.push(format!(
                    "{poff:04x}: fill-array-data-payload width={element_width} size={size} (units={size_units})"
                ));
            }
        }
    }
    MethodDisasm {
        lines,
        branch_targets: edges,
    }
}

pub fn disassemble_dex(dex: &DexFile, class_filter: Option<&str>, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut emitted = 0usize;
    for class in &dex.classes {
        if let Some(f) = class_filter
            && !class.class.contains(f)
        {
            continue;
        }
        out.push(format!(".class {}", class.class));
        if let Some(s) = &class.superclass {
            out.push(format!(".super {}", s));
        }
        let Some(data) = &class.class_data else {
            continue;
        };
        for m in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            if emitted >= limit {
                return out;
            }
            emitted += 1;
            let sig = dex.method_signature(m.method_idx);
            out.push(format!(".method {sig}"));
            if m.code_off == 0 {
                out.push("    <no code>".to_string());
                continue;
            }
            match dex.code_item(m.code_off) {
                Ok(code) => {
                    out.push(format!(
                        "    .registers {} (ins={} outs={})",
                        code.registers_size, code.ins_size, code.outs_size
                    ));
                    let d = disassemble_method(dex, &code.insns);
                    for line in d.lines {
                        out.push(format!("    {line}"));
                    }
                }
                Err(e) => out.push(format!("    <code read error: {e}>")),
            }
        }
    }
    out
}
