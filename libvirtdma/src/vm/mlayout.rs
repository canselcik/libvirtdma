use byteorder::ByteOrder;
use itertools::Itertools;

pub fn parse_u64(s: &str, le: bool) -> Option<u64> {
    if s.contains("+") {
        let parts: Vec<_> = s.splitn(2, |c: char| c == '+').map(String::from).collect();
        let lh = parse_u64(&parts[0], le);
        let rh = parse_u64(&parts[1], le);
        if lh.is_none() || rh.is_none() {
            println!("Invalid expression");
            return None;
        }
        return Some(lh.unwrap() + rh.unwrap());
    }
    match s.strip_prefix("0x") {
        None => match s.parse::<u64>() {
            Ok(r) => Some(r),
            Err(_) => None,
        },
        Some(h) => {
            let hh = if h.len() < 16 {
                format!("{}{}", "0".repeat(16 - h.len()), h)
            } else {
                h.to_string()
            };
            match hex::decode(hh) {
                Ok(r) => Some(if le {
                    byteorder::LittleEndian::read_u64(&r)
                } else {
                    byteorder::BigEndian::read_u64(&r)
                }),
                Err(_) => None,
            }
        }
    }
}

#[test]
fn test_parse_u64() {
    // LE flag is invariant over decimal input
    assert_eq!(parse_u64("123", false), Some(123));
    assert_eq!(parse_u64("123", true), Some(123));

    // Prefix works as expected in BE mode
    assert_eq!(parse_u64("0x4A", false), Some(74));

    assert_eq!(
        parse_u64("0xCAFEBABEDEADBEEF", false),
        Some(14627333968688430831)
    );
    assert_eq!(
        parse_u64("0x0000000004a3f6e1", false),
        parse_u64("0x4a3f6e1", false),
    );
    assert_eq!(parse_u64("0x0000000004a3f6e1", false), Some(77854433));
}

#[derive(Clone, Debug)]
pub struct MemoryRange {
    pub range: std::ops::Range<u64>,
    pub name: String,
    pub parent: Option<String>,
    pub metadata: String,
}

pub struct MemoryLayout {
    pub sections: indexmap::IndexMap<u64, MemoryRange>,
}

impl MemoryLayout {
    pub fn from_x64dbg_table(s: &str) -> Result<MemoryLayout, &str> {
        let mut lines = s.lines();
        let mut sections: indexmap::IndexMap<u64, MemoryRange> = indexmap::IndexMap::new();
        let mut last_section_name = String::new();
        while let Some(line) = lines.next() {
            if line.trim().is_empty() {
                continue;
            }
            let subsection = line.contains('"');
            let parts: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect_vec();
            if parts.len() < 5 {
                return Err("came across a line with less than 5 parts");
            }
            let start: u64 = match parse_u64(&format!("0x{}", parts[0]), false) {
                Some(r) => r,
                None => return Err("cannot parse the start"),
            };
            let size: u64 = match parse_u64(&format!("0x{}", parts[1]), false) {
                Some(r) => r,
                None => return Err("cannot parse the start"),
            };
            let name = if parts.len() == 5 {
                "".to_string()
            } else {
                parts[2].to_string()
            };
            let parent = if subsection {
                Some(last_section_name.clone())
            } else {
                last_section_name = name.clone();
                None
            };
            let metadata = parts[parts.len() - 3..parts.len()].join(" ");
            sections.insert(
                start,
                MemoryRange {
                    range: (start..start + size),
                    parent,
                    name,
                    metadata,
                },
            );
        }
        Ok(MemoryLayout { sections })
    }
}

#[test]
fn test_from_x64_dbg_table() {
    let s = r#"
       00000000003E0000 000000000000F000                                                 PRV ERW-- ERW--
       0000000000400000 0000000000001000 xinput1_3.dll                                   IMG -R--- ERWC-
       0000000000401000 0000000000015000  ".text"             Executable code            IMG ER--- ERWC-
       0000000000416000 0000000000004000  ".data"             Initialized data           IMG -RW-- ERWC-
       000000000041A000 0000000000002000  ".pdata"            Exception information      IMG -R--- ERWC-
       000000000041C000 0000000000001000  ".rsrc"             Resources                  IMG -R--- ERWC-
       000000000041D000 0000000000001000  ".reloc"            Base relocations           IMG -R--- ERWC-
       000000007FFE0000 0000000000001000 KUSER_SHARED_DATA                               PRV -R--- -R---
       000000007FFE8000 0000000000001000                                                 PRV -R--- -R---
       0000000180000000 0000000000001000 sqlite3.dll                                     IMG -R--- ERWC-
       0000000180001000 000000000014E000  ".text"             Executable code            IMG ER--- ERWC-
       000000018014F000 0000000000032000  ".rdata"            Read-only initialized data IMG -R--- ERWC-
       0000000180181000 0000000000006000  ".data"             Initialized data           IMG -RW-- ERWC-
       0000000180187000 0000000000010000  ".pdata"            Exception information      IMG -R--- ERWC-
       0000000180197000 0000000000002000  ".idata"            Import tables              IMG -RW-- ERWC-
       0000000180199000 0000000000001000  "text"                                         IMG E---- ERWC-
       000000018019A000 0000000000003000  "data"                                         IMG -R--- ERWC-
       000000018019D000 0000000000002000  ".rsrc"             Resources                  IMG -R--- ERWC-
       000000018019F000 0000000000002000  ".reloc"            Base relocations           IMG -R--- ERWC-
       00000072D4330000 000000000000B000 Reserved                                        PRV       -RW--
       00000072D433B000 0000000000005000 Thread 2490 Stack                               PRV -RW-G -RW--
       00000072D4340000 000000000000B000 Reserved                                        PRV       -RW--
       00000072D434B000 0000000000005000 Thread 694 Stack                                PRV -RW-G -RW--
    "#;
    let layout = MemoryLayout::from_x64dbg_table(s);
    assert!(layout.is_ok());
    let l = layout.unwrap();
    // The output is actually far from perfect but good enough -- since we are mostly interested in offsets
    for (begin, record) in l.sections.iter() {
        println!("0x{:x} {:?}", begin, record);
    }
}
