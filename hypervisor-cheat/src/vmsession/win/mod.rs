extern crate static_assertions as sa;

pub mod eprocess;

// 0x2d8 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<eprocess::KPROCESS>() == 0x2d8);

// 0x850 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<eprocess::EPROCESS>() == 0x850);

pub mod ethread;

// 0x810 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<ethread::ETHREAD>() == 0x810);

// 0x5f0 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<ethread::KTHREAD>() == 0x5f0);

#[macro_use]
pub mod misc;

// 0x10 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<misc::GroupAffinity>() == 0x10);

pub mod peb_ldr_data;
pub mod unicode_string;

pub mod heap_entry;
pub mod list_entry;
pub mod peb;
pub mod peb_bitfield;
pub mod proc_heap_entry;
pub mod teb;

// For Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<teb::NtTIB>() == 0x38);
sa::const_assert!(std::mem::size_of::<teb::ClientID>() == 0x10);
sa::const_assert!(std::mem::size_of::<teb::ActivationContextStack>() == 0x28);
sa::const_assert!(std::mem::size_of::<teb::GUID>() == 0x10);

// 0x1838 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<teb::TEB>() == 0x1838);

// 0x10 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<heap_entry::HEAP_ENTRY>() == 0x10);

// 0x2c0 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<heap_entry::HEAP>() == 0x2c0);

// 0xa0 bytes (sizeof) on  Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<ethread::KldrDataTableEntry>() == 0xa0);

#[derive(Clone, Copy, Debug)]
pub struct Offsets {
    pub apl: i64,
    pub session: i64,
    pub stackCount: i64,
    pub imageFileName: i64,
    pub dirBase: i64,
    pub peb: i64,
    pub peb32: i64,
    pub threadListHead: i64,
    pub threadListEntry: i64,
    pub teb: i64,
}

impl Offsets {
    pub fn GetOffsets(ntVersion: u16, ntBuild: u32) -> Option<Offsets> {
        match ntVersion {
            502 => {
                /* XP SP2 */
                Some(Offsets {
                    apl: 0xe0,
                    session: 0x260,
                    stackCount: 0xa0,
                    imageFileName: 0x268,
                    dirBase: 0x28,
                    peb: 0x2c0,
                    peb32: 0x30,
                    threadListHead: 0x290,
                    threadListEntry: 0x3d0,
                    teb: 0xb0,
                })
            }
            601 => {
                // Windows 7
                let mut ret = Offsets {
                    apl: 0x188,
                    session: 0x2d8,
                    stackCount: 0xdc,
                    imageFileName: 0x2e0,
                    dirBase: 0x28,
                    peb: 0x338,
                    peb32: 0x30,
                    threadListHead: 0x300,
                    threadListEntry: 0x420,
                    teb: 0xb8,
                };
                /* SP1 */
                if ntBuild == 7601 {
                    ret.imageFileName = 0x2d8;
                    ret.threadListEntry = 0x428;
                }
                Some(ret)
            }
            602 => {
                // Windows 8
                Some(Offsets {
                    apl: 0x2e8,
                    session: 0x430,
                    stackCount: 0x234,
                    imageFileName: 0x438,
                    dirBase: 0x28,
                    peb: 0x338,
                    /*peb will be wrong on Windows 8 and 8.1*/
                    peb32: 0x30,
                    threadListHead: 0x470,
                    threadListEntry: 0x400,
                    teb: 0xf0,
                })
            }
            603 => {
                // Windows 8.1
                Some(Offsets {
                    apl: 0x2e8,
                    session: 0x430,
                    stackCount: 0x234,
                    imageFileName: 0x438,
                    dirBase: 0x28,
                    peb: 0x338,
                    peb32: 0x30,
                    threadListHead: 0x470,
                    threadListEntry: 0x688,
                    /* 0x650 on previous builds */
                    teb: 0xf0,
                })
            }
            1000 => {
                // Windows 10
                let mut ret = Offsets {
                    apl: 0x2e8, // ActiveProcessLinks
                    session: 0x448,
                    stackCount: 0x23c, // _KPROCESS offset
                    imageFileName: 0x450,
                    dirBase: 0x28,
                    peb: 0x3f8,
                    peb32: 0x30,
                    threadListHead: 0x488,
                    threadListEntry: 0x6a8,
                    teb: 0xf0,
                };
                if ntBuild >= 18362 {
                    // Version 1903 or higher
                    ret.apl = 0x2f0;
                    ret.threadListEntry = 0x6b8;
                }
                Some(ret)
            }
            _ => None,
        }
    }
}
