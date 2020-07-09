extern crate static_assertions as sa;

pub mod pe;

sa::const_assert!(std::mem::size_of::<pe::ImageNtHeaders64>() == 0x108);

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
    pub stack_count: i64,
    pub image_file_name: i64,
    pub dirbase: i64,
    pub peb: i64,
    pub peb32: i64,
    pub thread_list_head: i64,
    pub thread_list_entry: i64,
    pub teb: i64,
}

impl Offsets {
    pub fn get_offsets(nt_version: u16, nt_build: u32) -> Option<Offsets> {
        match nt_version {
            502 => {
                /* XP SP2 */
                Some(Offsets {
                    apl: 0xe0,
                    session: 0x260,
                    stack_count: 0xa0,
                    image_file_name: 0x268,
                    dirbase: 0x28,
                    peb: 0x2c0,
                    peb32: 0x30,
                    thread_list_head: 0x290,
                    thread_list_entry: 0x3d0,
                    teb: 0xb0,
                })
            }
            601 => {
                // Windows 7
                let mut ret = Offsets {
                    apl: 0x188,
                    session: 0x2d8,
                    stack_count: 0xdc,
                    image_file_name: 0x2e0,
                    dirbase: 0x28,
                    peb: 0x338,
                    peb32: 0x30,
                    thread_list_head: 0x300,
                    thread_list_entry: 0x420,
                    teb: 0xb8,
                };
                /* SP1 */
                if nt_build == 7601 {
                    ret.image_file_name = 0x2d8;
                    ret.thread_list_entry = 0x428;
                }
                Some(ret)
            }
            602 => {
                // Windows 8
                Some(Offsets {
                    apl: 0x2e8,
                    session: 0x430,
                    stack_count: 0x234,
                    image_file_name: 0x438,
                    dirbase: 0x28,
                    peb: 0x338,
                    /*peb will be wrong on Windows 8 and 8.1*/
                    peb32: 0x30,
                    thread_list_head: 0x470,
                    thread_list_entry: 0x400,
                    teb: 0xf0,
                })
            }
            603 => {
                // Windows 8.1
                Some(Offsets {
                    apl: 0x2e8,
                    session: 0x430,
                    stack_count: 0x234,
                    image_file_name: 0x438,
                    dirbase: 0x28,
                    peb: 0x338,
                    peb32: 0x30,
                    thread_list_head: 0x470,
                    thread_list_entry: 0x688,
                    /* 0x650 on previous builds */
                    teb: 0xf0,
                })
            }
            1000 => {
                // Windows 10
                let mut ret = Offsets {
                    apl: 0x2e8, // ActiveProcessLinks
                    session: 0x448,
                    stack_count: 0x23c, // _KPROCESS offset
                    image_file_name: 0x450,
                    dirbase: 0x28,
                    peb: 0x3f8,
                    peb32: 0x30,
                    thread_list_head: 0x488,
                    thread_list_entry: 0x6a8,
                    teb: 0xf0,
                };
                if nt_build >= 18362 {
                    // Version 1903 or higher
                    ret.apl = 0x2f0;
                    ret.thread_list_entry = 0x6b8;
                }
                Some(ret)
            }
            _ => None,
        }
    }
}
