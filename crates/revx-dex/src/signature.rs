//! JVM generic signature parsing (ClassFile spec §4.7.9.1) to Java source
//! text. Signature strings come from the Signature annotation on classes,
//! methods, and fields.

pub struct ClassSigInfo {
    pub type_params: String,
    pub superclass: String,
    pub interfaces: Vec<String>,
}

pub struct MethodSigInfo {
    pub type_params: String,
    pub params: Vec<String>,
    pub ret: String,
    pub throws: Vec<String>,
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn ident(&mut self) -> String {
        let start = self.i;
        while let Some(c) = self.peek() {
            if matches!(
                c,
                b';' | b'<' | b'>' | b'.' | b'/' | b'[' | b':' | b'(' | b')' | b'^'
            ) {
                break;
            }
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }

    fn expect(&mut self, c: u8) -> Option<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Some(())
        } else {
            None
        }
    }

    fn java_type(&mut self) -> Option<String> {
        Some(match self.bump()? {
            b'Z' => "boolean".into(),
            b'B' => "byte".into(),
            b'S' => "short".into(),
            b'C' => "char".into(),
            b'I' => "int".into(),
            b'J' => "long".into(),
            b'F' => "float".into(),
            b'D' => "double".into(),
            b'V' => "void".into(),
            b'[' => {
                let inner = self.java_type()?;
                format!("{inner}[]")
            }
            b'T' => {
                let n = self.ident();
                self.expect(b';')?;
                n
            }
            b'L' => self.class_type()?,
            _ => return None,
        })
    }

    fn class_type(&mut self) -> Option<String> {
        let mut path = String::new();
        loop {
            path.push_str(&self.ident());
            if self.peek() == Some(b'/') {
                self.i += 1;
                path.push('/');
            } else {
                break;
            }
        }
        let mut name = crate::types::java_type(&format!("L{path};"));
        if let Some(stripped) = name.strip_prefix("java.lang.") {
            name = stripped.to_string();
        }
        let mut out = name;
        loop {
            match self.peek() {
                Some(b'<') => {
                    self.i += 1;
                    let mut args: Vec<String> = Vec::new();
                    loop {
                        if self.peek() == Some(b'>') {
                            self.i += 1;
                            break;
                        }
                        args.push(self.type_arg()?);
                        if args.len() > 16 {
                            return None;
                        }
                    }
                    out = format!("{out}<{}>", args.join(", "));
                }
                Some(b'.') => {
                    self.i += 1;
                    let nested = self.ident();
                    out = format!("{out}.{nested}");
                }
                _ => break,
            }
        }
        self.expect(b';')?;
        Some(out)
    }

    fn type_arg(&mut self) -> Option<String> {
        Some(match self.peek()? {
            b'*' => {
                self.i += 1;
                "?".into()
            }
            b'+' => {
                self.i += 1;
                format!("? extends {}", self.java_type()?)
            }
            b'-' => {
                self.i += 1;
                format!("? super {}", self.java_type()?)
            }
            _ => self.java_type()?,
        })
    }

    fn type_params(&mut self) -> Option<String> {
        if self.peek() != Some(b'<') {
            return Some(String::new());
        }
        self.i += 1;
        let mut parts: Vec<String> = Vec::new();
        while self.peek() != Some(b'>') {
            let name = self.ident();
            self.expect(b':')?;
            let mut bounds: Vec<String> = Vec::new();
            if matches!(self.peek(), Some(b'L') | Some(b'T') | Some(b'[')) {
                bounds.push(self.java_type()?);
            }
            while self.peek() == Some(b':') {
                self.i += 1;
                bounds.push(self.java_type()?);
            }
            let bstr = if bounds.is_empty() || bounds.iter().all(|b| b == "Object") {
                String::new()
            } else {
                format!(" extends {}", bounds.join(" & "))
            };
            parts.push(format!("{name}{bstr}"));
            if parts.len() > 8 {
                return None;
            }
        }
        self.i += 1;
        Some(format!("<{}>", parts.join(", ")))
    }
}

pub fn type_to_java(sig: &str) -> Option<String> {
    let mut p = P {
        s: sig.as_bytes(),
        i: 0,
    };
    let t = p.java_type()?;
    Some(t)
}

pub fn parse_class_sig(sig: &str) -> Option<ClassSigInfo> {
    let mut p = P {
        s: sig.as_bytes(),
        i: 0,
    };
    let type_params = p.type_params()?;
    let superclass = p.java_type()?;
    let mut interfaces: Vec<String> = Vec::new();
    while p.peek().is_some() {
        interfaces.push(p.java_type()?);
        if interfaces.len() > 8 {
            break;
        }
    }
    Some(ClassSigInfo {
        type_params,
        superclass,
        interfaces,
    })
}

pub fn parse_method_sig(sig: &str) -> Option<MethodSigInfo> {
    let mut p = P {
        s: sig.as_bytes(),
        i: 0,
    };
    let type_params = p.type_params()?;
    p.expect(b'(')?;
    let mut params: Vec<String> = Vec::new();
    while p.peek() != Some(b')') {
        params.push(p.java_type()?);
        if params.len() > 32 {
            return None;
        }
    }
    p.i += 1;
    let ret = p.java_type()?;
    let mut throws: Vec<String> = Vec::new();
    while p.peek() == Some(b'^') {
        p.i += 1;
        throws.push(p.java_type()?);
    }
    Some(MethodSigInfo {
        type_params,
        params,
        ret,
        throws,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_generic_list() {
        assert_eq!(
            type_to_java("Ljava/util/List<Ljava/lang/String;>;").unwrap(),
            "java.util.List<String>"
        );
    }

    #[test]
    fn parses_type_var() {
        assert_eq!(type_to_java("TT;").unwrap(), "T");
    }

    #[test]
    fn parses_array_type() {
        assert_eq!(type_to_java("[Ljava/lang/String;").unwrap(), "String[]");
        assert_eq!(type_to_java("[[I").unwrap(), "int[][]");
    }

    #[test]
    fn parses_wildcards() {
        assert_eq!(
            type_to_java("Ljava/util/List<+Ljava/lang/Number;>;").unwrap(),
            "java.util.List<? extends Number>"
        );
        assert_eq!(
            type_to_java("Ljava/util/List<-Ljava/lang/String;>;").unwrap(),
            "java.util.List<? super String>"
        );
        assert_eq!(
            type_to_java("Ljava/util/Map<Ljava/lang/String;*>;").unwrap(),
            "java.util.Map<String, ?>"
        );
    }

    #[test]
    fn parses_nested_generics() {
        assert_eq!(
            type_to_java(
                "Ljava/util/Map<Ljava/lang/String;Ljava/util/List<Ljava/lang/Integer;>;>;"
            )
            .unwrap(),
            "java.util.Map<String, java.util.List<Integer>>"
        );
    }

    #[test]
    fn parses_method_signature() {
        let m = parse_method_sig("<T:Ljava/lang/Object;>(TT;)TT;").unwrap();
        assert_eq!(m.type_params, "<T>");
        assert_eq!(m.params, vec!["T"]);
        assert_eq!(m.ret, "T");
    }

    #[test]
    fn parses_method_with_throws() {
        let m = parse_method_sig("(Ljava/lang/String;)V^Ljava/io/IOException;").unwrap();
        assert_eq!(m.params, vec!["String"]);
        assert_eq!(m.ret, "void");
        assert_eq!(m.throws, vec!["java.io.IOException"]);
    }

    #[test]
    fn parses_class_signature() {
        let c = parse_class_sig(
            "<K:Ljava/lang/Object;V:Ljava/lang/Object;>Ljava/lang/Object;Ljava/util/Map<TK;TV;>;",
        )
        .unwrap();
        assert_eq!(c.type_params, "<K, V>");
        assert_eq!(c.superclass, "Object");
        assert_eq!(c.interfaces, vec!["java.util.Map<K, V>"]);
    }

    #[test]
    fn parses_bounded_type_param() {
        let m =
            parse_method_sig("<T:Ljava/lang/Number;:Ljava/lang/Comparable<TT;>;>(TT;)TT;").unwrap();
        assert_eq!(m.type_params, "<T extends Number & Comparable<T>>");
    }

    #[test]
    fn parses_plain_signature() {
        let m = parse_method_sig("(II)I").unwrap();
        assert_eq!(m.type_params, "");
        assert_eq!(m.params, vec!["int", "int"]);
        assert_eq!(m.ret, "int");
    }
}
