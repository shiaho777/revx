//! DEX file format parser: header, string/type/proto/field/method tables,
//! class definitions, class data, and code items.

pub mod annotations;
pub mod classgen;
pub mod insns;
pub mod jni;
pub mod kotlin;
pub mod lift;
pub mod render;
pub mod signature;
pub mod structure;
pub mod types;

use std::fmt;

fn sleb128_at(data: &[u8], off: usize) -> std::result::Result<(i64, usize), DexError> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut pos = off;
    loop {
        let byte = *data.get(pos).ok_or(()).map_err(|_| DexError {
            message: "sleb128 out of bounds".into(),
            offset: pos,
        })?;
        pos += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= (-1i64) << shift;
            }
            break;
        }
        if shift >= 64 {
            break;
        }
    }
    Ok((result, pos))
}

#[derive(Debug, Clone)]
pub struct DexError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dex error at {:#x}: {}", self.offset, self.message)
    }
}

impl std::error::Error for DexError {}

type Result<T> = std::result::Result<T, DexError>;

fn err<T>(offset: usize, message: impl Into<String>) -> Result<T> {
    Err(DexError {
        message: message.into(),
        offset,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexHeader {
    pub version: u32,
    pub file_size: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
    pub map_off: u32,
}

#[derive(Debug, Clone)]
pub struct ProtoId {
    pub shorty: String,
    pub return_type: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FieldId {
    pub class: String,
    pub ty: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct MethodId {
    pub class: String,
    pub proto: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug, Clone)]
pub struct ClassDef {
    pub class: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub annotations_off: u32,
    pub class_data: Option<ClassData>,
}

#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
}

#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handlers: Vec<CatchHandler>,
    pub catch_all_addr: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CatchHandler {
    pub type_idx: u32,
    pub addr: u32,
}

#[derive(Debug, Clone)]
pub struct MethodHandleEntry {
    pub handle_type: u16,
    pub id: u16,
}

#[derive(Debug, Clone)]
pub struct CallSiteEntry {
    pub name: String,
    pub proto_idx: u32,
    pub bootstrap_method_idx: u32,
    pub impl_method_idx: Option<u32>,
}

pub struct DexFile {
    pub data: Vec<u8>,
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub protos: Vec<ProtoId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassDef>,
    pub method_handles: Vec<MethodHandleEntry>,
    pub call_sites: Vec<CallSiteEntry>,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u16_at(&self, off: usize) -> Result<u16> {
        let b = self
            .data
            .get(off..off + 2)
            .ok_or(())
            .map_err(|_| DexError {
                message: "u16 read out of bounds".into(),
                offset: off,
            })?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32_at(&self, off: usize) -> Result<u32> {
        let b = self
            .data
            .get(off..off + 4)
            .ok_or(())
            .map_err(|_| DexError {
                message: "u32 read out of bounds".into(),
                offset: off,
            })?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn uleb128_at(&self, off: usize) -> Result<(u32, usize)> {
        let mut result: u32 = 0;
        let mut shift = 0u32;
        let mut pos = off;
        loop {
            let byte = *self.data.get(pos).ok_or(()).map_err(|_| DexError {
                message: "uleb128 read out of bounds".into(),
                offset: pos,
            })?;
            result |= ((byte & 0x7f) as u32) << shift;
            pos += 1;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 32 {
                return err(off, "uleb128 too large");
            }
        }
        Ok((result, pos))
    }

    fn mutf8_at(&self, off: usize) -> Result<String> {
        let (utf16_len, mut pos) = self.uleb128_at(off)?;
        let mut out = String::new();
        let mut count = 0u32;
        while count < utf16_len {
            let byte = *self.data.get(pos).ok_or(()).map_err(|_| DexError {
                message: "mutf8 read out of bounds".into(),
                offset: pos,
            })?;
            if byte == 0 {
                break;
            }
            if byte < 0x80 {
                out.push(byte as char);
                pos += 1;
            } else if byte & 0xe0 == 0xc0 {
                let b2 = *self.data.get(pos + 1).ok_or(()).map_err(|_| DexError {
                    message: "mutf8 2-byte read out of bounds".into(),
                    offset: pos,
                })?;
                let cp = (((byte & 0x1f) as u32) << 6) | ((b2 & 0x3f) as u32);
                out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                pos += 2;
            } else if byte & 0xf0 == 0xe0 {
                let b2 = *self.data.get(pos + 1).ok_or(()).map_err(|_| DexError {
                    message: "mutf8 3-byte read out of bounds".into(),
                    offset: pos,
                })?;
                let b3 = *self.data.get(pos + 2).ok_or(()).map_err(|_| DexError {
                    message: "mutf8 3-byte read out of bounds".into(),
                    offset: pos,
                })?;
                let cp = (((byte & 0x0f) as u32) << 12)
                    | (((b2 & 0x3f) as u32) << 6)
                    | ((b3 & 0x3f) as u32);
                out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                pos += 3;
            } else {
                pos += 1;
            }
            count += 1;
        }
        Ok(out)
    }
}

impl DexFile {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let r = Reader { data: &data };
        let magic = data.get(0..8).ok_or(()).map_err(|_| DexError {
            message: "file too small for header".into(),
            offset: 0,
        })?;
        if magic[0..4] != [0x64, 0x65, 0x78, 0x0a] {
            return err(0, "bad magic (not a DEX file)");
        }
        let version = u32::from(magic[4] - b'0') * 100
            + u32::from(magic[5] - b'0') * 10
            + u32::from(magic[6] - b'0');
        let header = DexHeader {
            version,
            file_size: r.u32_at(0x20)?,
            string_ids_size: r.u32_at(0x38)?,
            string_ids_off: r.u32_at(0x3c)?,
            type_ids_size: r.u32_at(0x40)?,
            type_ids_off: r.u32_at(0x44)?,
            proto_ids_size: r.u32_at(0x48)?,
            proto_ids_off: r.u32_at(0x4c)?,
            field_ids_size: r.u32_at(0x50)?,
            field_ids_off: r.u32_at(0x54)?,
            method_ids_size: r.u32_at(0x58)?,
            method_ids_off: r.u32_at(0x5c)?,
            class_defs_size: r.u32_at(0x60)?,
            class_defs_off: r.u32_at(0x64)?,
            data_size: r.u32_at(0x68)?,
            data_off: r.u32_at(0x6c)?,
            map_off: r.u32_at(0x34)?,
        };
        if header.file_size as usize > data.len() {
            return err(0x20, "declared file size exceeds actual size");
        }

        let mut strings = Vec::with_capacity(header.string_ids_size as usize);
        for i in 0..header.string_ids_size {
            let off = r.u32_at(header.string_ids_off as usize + i as usize * 4)?;
            strings.push(r.mutf8_at(off as usize)?);
        }

        let mut types = Vec::with_capacity(header.type_ids_size as usize);
        for i in 0..header.type_ids_size {
            let idx = r.u32_at(header.type_ids_off as usize + i as usize * 4)?;
            let s = strings.get(idx as usize).cloned().unwrap_or_default();
            types.push(s);
        }

        let mut protos = Vec::with_capacity(header.proto_ids_size as usize);
        for i in 0..header.proto_ids_size {
            let base = header.proto_ids_off as usize + i as usize * 12;
            let shorty_idx = r.u32_at(base)?;
            let return_type_idx = r.u32_at(base + 4)?;
            let parameters_off = r.u32_at(base + 8)?;
            let shorty = strings
                .get(shorty_idx as usize)
                .cloned()
                .unwrap_or_default();
            let return_type = types
                .get(return_type_idx as usize)
                .cloned()
                .unwrap_or_default();
            let mut parameters = Vec::new();
            if parameters_off != 0 {
                let count = r.u32_at(parameters_off as usize)?;
                for j in 0..count {
                    let tidx = r.u16_at(parameters_off as usize + 4 + j as usize * 2)?;
                    parameters.push(types.get(tidx as usize).cloned().unwrap_or_default());
                }
            }
            protos.push(ProtoId {
                shorty,
                return_type,
                parameters,
            });
        }

        let mut fields = Vec::with_capacity(header.field_ids_size as usize);
        for i in 0..header.field_ids_size {
            let base = header.field_ids_off as usize + i as usize * 8;
            let class_idx = r.u16_at(base)?;
            let type_idx = r.u16_at(base + 2)?;
            let name_idx = r.u32_at(base + 4)?;
            fields.push(FieldId {
                class: types.get(class_idx as usize).cloned().unwrap_or_default(),
                ty: types.get(type_idx as usize).cloned().unwrap_or_default(),
                name: strings.get(name_idx as usize).cloned().unwrap_or_default(),
            });
        }

        let mut methods = Vec::with_capacity(header.method_ids_size as usize);
        for i in 0..header.method_ids_size {
            let base = header.method_ids_off as usize + i as usize * 8;
            let class_idx = r.u16_at(base)?;
            let proto_idx = r.u16_at(base + 2)?;
            let name_idx = r.u32_at(base + 4)?;
            methods.push(MethodId {
                class: types.get(class_idx as usize).cloned().unwrap_or_default(),
                proto: proto_idx as u32,
                name: strings.get(name_idx as usize).cloned().unwrap_or_default(),
            });
        }

        let mut classes = Vec::with_capacity(header.class_defs_size as usize);
        for i in 0..header.class_defs_size {
            let base = header.class_defs_off as usize + i as usize * 32;
            let class_idx = r.u32_at(base)?;
            let access_flags = r.u32_at(base + 4)?;
            let superclass_idx = r.u32_at(base + 8)?;
            let interfaces_off = r.u32_at(base + 12)?;
            let source_file_idx = r.u32_at(base + 16)?;
            let class_data_off = r.u32_at(base + 24)?;
            let annotations_off = r.u32_at(base + 20)?;

            let superclass = if superclass_idx == u32::MAX {
                None
            } else {
                Some(
                    types
                        .get(superclass_idx as usize)
                        .cloned()
                        .unwrap_or_default(),
                )
            };
            let mut interfaces = Vec::new();
            if interfaces_off != 0 {
                let count = r.u32_at(interfaces_off as usize)?;
                for j in 0..count {
                    let tidx = r.u16_at(interfaces_off as usize + 4 + j as usize * 2)?;
                    interfaces.push(types.get(tidx as usize).cloned().unwrap_or_default());
                }
            }
            let source_file = if source_file_idx == u32::MAX {
                None
            } else {
                Some(
                    strings
                        .get(source_file_idx as usize)
                        .cloned()
                        .unwrap_or_default(),
                )
            };
            let class_data = if class_data_off != 0 {
                Some(Self::parse_class_data(&r, class_data_off as usize)?)
            } else {
                None
            };
            classes.push(ClassDef {
                class: types.get(class_idx as usize).cloned().unwrap_or_default(),
                access_flags,
                superclass,
                interfaces,
                source_file,
                annotations_off,
                class_data,
            });
        }

        let (method_handles, call_sites) = Self::parse_call_tables(&r, header.map_off, &strings);

        Ok(DexFile {
            data,
            header,
            strings,
            types,
            protos,
            fields,
            methods,
            classes,
            method_handles,
            call_sites,
        })
    }

    fn parse_class_data(r: &Reader, off: usize) -> Result<ClassData> {
        let (static_fields_size, mut pos) = r.uleb128_at(off)?;
        let (instance_fields_size, p) = r.uleb128_at(pos)?;
        pos = p;
        let (direct_methods_size, p) = r.uleb128_at(pos)?;
        pos = p;
        let (virtual_methods_size, p) = r.uleb128_at(pos)?;
        pos = p;

        let mut static_fields = Vec::with_capacity(static_fields_size as usize);
        let mut idx = 0u32;
        for _ in 0..static_fields_size {
            let (diff, p) = r.uleb128_at(pos)?;
            pos = p;
            let (flags, p) = r.uleb128_at(pos)?;
            pos = p;
            idx += diff;
            static_fields.push(EncodedField {
                field_idx: idx,
                access_flags: flags,
            });
        }

        let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
        idx = 0;
        for _ in 0..instance_fields_size {
            let (diff, p) = r.uleb128_at(pos)?;
            pos = p;
            let (flags, p) = r.uleb128_at(pos)?;
            pos = p;
            idx += diff;
            instance_fields.push(EncodedField {
                field_idx: idx,
                access_flags: flags,
            });
        }

        let mut direct_methods = Vec::with_capacity(direct_methods_size as usize);
        idx = 0;
        for _ in 0..direct_methods_size {
            let (diff, p) = r.uleb128_at(pos)?;
            pos = p;
            let (flags, p) = r.uleb128_at(pos)?;
            pos = p;
            let (code_off, p) = r.uleb128_at(pos)?;
            pos = p;
            idx += diff;
            direct_methods.push(EncodedMethod {
                method_idx: idx,
                access_flags: flags,
                code_off,
            });
        }

        let mut virtual_methods = Vec::with_capacity(virtual_methods_size as usize);
        idx = 0;
        for _ in 0..virtual_methods_size {
            let (diff, p) = r.uleb128_at(pos)?;
            pos = p;
            let (flags, p) = r.uleb128_at(pos)?;
            pos = p;
            let (code_off, p) = r.uleb128_at(pos)?;
            pos = p;
            idx += diff;
            virtual_methods.push(EncodedMethod {
                method_idx: idx,
                access_flags: flags,
                code_off,
            });
        }

        Ok(ClassData {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        })
    }

    pub fn code_item(&self, code_off: u32) -> Result<CodeItem> {
        let r = Reader { data: &self.data };
        let off = code_off as usize;
        let registers_size = r.u16_at(off)?;
        let ins_size = r.u16_at(off + 2)?;
        let outs_size = r.u16_at(off + 4)?;
        let tries_size = r.u16_at(off + 6)?;
        let debug_info_off = r.u32_at(off + 8)?;
        let insns_size = r.u32_at(off + 12)?;
        let mut insns = Vec::with_capacity(insns_size as usize);
        for i in 0..insns_size {
            insns.push(r.u16_at(off + 16 + i as usize * 2)?);
        }
        let mut tries = Vec::new();
        if tries_size > 0 {
            let tries_start =
                off + 16 + insns_size as usize * 2 + if insns_size % 2 == 1 { 2 } else { 0 };
            let handlers_list_off = tries_start + tries_size as usize * 8;
            for i in 0..tries_size {
                let tries_off = tries_start + i as usize * 8;
                let start_addr = r.u32_at(tries_off)?;
                let insn_count = r.u16_at(tries_off + 4)?;
                let handler_off = r.u16_at(tries_off + 6)? as usize;
                let (handlers, catch_all) =
                    Self::parse_catch_handlers(&r, handlers_list_off + handler_off)?;
                tries.push(TryItem {
                    start_addr,
                    insn_count,
                    handlers,
                    catch_all_addr: catch_all,
                });
            }
        }
        Ok(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns,
            tries,
        })
    }

    fn parse_catch_handlers(r: &Reader, base: usize) -> Result<(Vec<CatchHandler>, Option<u32>)> {
        let Ok((size, mut p)) = sleb128_at(r.data, base) else {
            return Ok((vec![], None));
        };
        let mut handlers = Vec::new();
        let mut catch_all = None;
        let typed = if size <= 0 { size + 1 } else { size };
        for _ in 0..typed.max(0) {
            let Ok((type_idx, np)) = r.uleb128_at(p) else {
                break;
            };
            p = np;
            let Ok((addr, np)) = r.uleb128_at(p) else {
                break;
            };
            p = np;
            handlers.push(CatchHandler { type_idx, addr });
        }
        if size <= 0
            && let Ok((addr, _)) = r.uleb128_at(p)
        {
            catch_all = Some(addr);
        }
        Ok((handlers, catch_all))
    }

    fn read_indexed_value(r: &Reader, pos: usize) -> Option<(u8, u32, usize)> {
        let head = *r.data.get(pos)?;
        let ty = head & 0x1f;
        let arg = ((head >> 5) as usize) + 1;
        let mut idx = 0u32;
        for k in 0..arg {
            let b = *r.data.get(pos + 1 + k)?;
            idx |= (b as u32) << (k * 8);
        }
        Some((ty, idx, pos + 1 + arg))
    }

    fn parse_call_tables(
        r: &Reader,
        map_off: u32,
        strings: &[String],
    ) -> (Vec<MethodHandleEntry>, Vec<CallSiteEntry>) {
        let mut handles = Vec::new();
        let mut sites = Vec::new();
        if map_off == 0 {
            return (handles, sites);
        }
        let mo = map_off as usize;
        let Ok(map_size) = r.u32_at(mo) else {
            return (handles, sites);
        };
        let mut mh_off = 0u32;
        let mut mh_size = 0u32;
        let mut cs_off = 0u32;
        let mut cs_size = 0u32;
        for i in 0..map_size.min(64) {
            let base = mo + 4 + i as usize * 12;
            let ty = r.u16_at(base).unwrap_or(0);
            let cnt = r.u32_at(base + 4).unwrap_or(0);
            let off = r.u32_at(base + 8).unwrap_or(0);
            match ty {
                0x2008 => {
                    mh_off = off;
                    mh_size = cnt;
                }
                0x2007 => {
                    cs_off = off;
                    cs_size = cnt;
                }
                _ => {}
            }
        }
        for i in 0..mh_size.min(8192) {
            let base = mh_off as usize + i as usize * 8;
            let handle_type = r.u16_at(base).unwrap_or(0);
            let id = r.u16_at(base + 4).unwrap_or(0);
            handles.push(MethodHandleEntry { handle_type, id });
        }
        for i in 0..cs_size.min(8192) {
            let Ok(item_off) = r.u32_at(cs_off as usize + i as usize * 4) else {
                continue;
            };
            let Ok((n, mut p)) = r.uleb128_at(item_off as usize) else {
                continue;
            };
            let mut vals: Vec<(u8, u32)> = Vec::new();
            for _ in 0..n.min(16) {
                let Some((ty, idx, np)) = Self::read_indexed_value(r, p) else {
                    break;
                };
                p = np;
                vals.push((ty, idx));
            }
            let bootstrap_method_idx = vals
                .first()
                .filter(|(t, _)| *t == 0x16)
                .map(|(_, i)| *i)
                .unwrap_or(0);
            let name = vals
                .get(1)
                .filter(|(t, _)| *t == 0x17)
                .and_then(|(_, i)| strings.get(*i as usize).cloned())
                .unwrap_or_default();
            let proto_idx = vals
                .get(2)
                .filter(|(t, _)| *t == 0x15)
                .map(|(_, i)| *i)
                .unwrap_or(0);
            let impl_method_idx = vals
                .iter()
                .skip(3)
                .find(|(t, _)| *t == 0x16)
                .and_then(|(_, h)| handles.get(*h as usize))
                .filter(|h| h.handle_type < 5)
                .map(|h| h.id as u32);
            sites.push(CallSiteEntry {
                name,
                proto_idx,
                bootstrap_method_idx,
                impl_method_idx,
            });
        }
        (handles, sites)
    }

    pub fn method_proto(&self, method_idx: u32) -> Option<&ProtoId> {
        self.methods
            .get(method_idx as usize)
            .and_then(|m| self.protos.get(m.proto as usize))
    }

    pub fn method_signature(&self, method_idx: u32) -> String {
        let Some(m) = self.methods.get(method_idx as usize) else {
            return format!("method@{method_idx}");
        };
        let Some(p) = self.protos.get(m.proto as usize) else {
            return format!("{}->{}", m.class, m.name);
        };
        let params = p.parameters.join("");
        format!("{}->{}({}){}", m.class, m.name, params, p.return_type)
    }

    pub fn field_reference(&self, field_idx: u32) -> String {
        let Some(f) = self.fields.get(field_idx as usize) else {
            return format!("field@{field_idx}");
        };
        format!("{}->{}:{}", f.class, f.name, f.ty)
    }

    pub fn type_name(&self, type_idx: u32) -> String {
        self.types
            .get(type_idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("type@{type_idx}"))
    }

    pub fn string_value(&self, string_idx: u32) -> &str {
        self.strings
            .get(string_idx as usize)
            .map(|s| s.as_str())
            .unwrap_or("")
    }
}
