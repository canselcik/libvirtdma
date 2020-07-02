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
pub mod teb;

// For Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<teb::NtTIB>() == 0x38);
sa::const_assert!(std::mem::size_of::<teb::ClientID>() == 0x10);
sa::const_assert!(std::mem::size_of::<teb::ActivationContextStack>() == 0x28);
sa::const_assert!(std::mem::size_of::<teb::GUID>() == 0x10);

// 0x1838 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<teb::TEB>() == 0x1838);
