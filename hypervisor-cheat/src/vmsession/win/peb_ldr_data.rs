#![allow(dead_code)]
use crate::vmsession::vm::VMBinding;
use crate::vmsession::win::list_entry::ListEntry;
use crate::vmsession::win::unicode_string::UnicodeString;

// 0x58 bytes (sizeof)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PebLdrData {
    pub(crate) Length: u32,                                // 0x0
    pub(crate) Initialized: u32,                           // 0x4
    pub(crate) SsHandle: u64,                              // 0x8 ptr
    pub(crate) InLoadOrderModuleList: ListEntry,           // 0x10
    pub(crate) InMemoryOrderModuleList: ListEntry,         // 0x20
    pub(crate) InInitializationOrderModuleList: ListEntry, // 0x30
    pub(crate) EntryInProgress: u64,                       // 0x40 ptr
    pub(crate) ShutdownInProgress: u32,                    // 0x48
    pub(crate) ShutdownThreadId: u64,                      // 0x50 ptr
}

impl PebLdrData {
    pub fn likelyInvalid(&self) -> bool {
        self.Length == 0
            && self.Initialized == 0
            && self.SsHandle == 0
            && self.InLoadOrderModuleList.Flink == 0
            && self.InLoadOrderModuleList.Blink == 0
            && self.InMemoryOrderModuleList.Flink == 0
            && self.InMemoryOrderModuleList.Blink == 0
            && self.InInitializationOrderModuleList.Flink == 0
            && self.InInitializationOrderModuleList.Blink == 0
            && self.EntryInProgress == 0
            && self.ShutdownInProgress == 0
            && self.ShutdownThreadId == 0
    }

    pub fn getFirstInMemoryOrderModuleListWithDirbase(
        &self,
        vm: &VMBinding,
        dirbase: u64,
    ) -> Option<LdrModule> {
        self.InMemoryOrderModuleList.getNextWithDirbase(
            vm,
            Some(dirbase),
            std::mem::size_of::<ListEntry>() as u64,
        )
    }

    pub fn getFirstInLoadOrderModuleListWithDirbase(
        &self,
        vm: &VMBinding,
        dirbase: u64,
    ) -> Option<LdrModule> {
        self.InLoadOrderModuleList
            .getNextWithDirbase(vm, Some(dirbase), 0)
    }

    pub fn getFirstInInitializationOrderModuleListWithDirbase(
        &self,
        vm: &VMBinding,
        dirbase: u64,
    ) -> Option<LdrModule> {
        self.InInitializationOrderModuleList.getNextWithDirbase(
            vm,
            Some(dirbase),
            2 * std::mem::size_of::<ListEntry>() as u64,
        )
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LdrModule {
    pub(crate) InLoadOrderModuleList: ListEntry,
    pub(crate) InMemoryOrderModuleList: ListEntry,
    pub(crate) InInitializationOrderModuleList: ListEntry,
    pub(crate) BaseAddress: u64, // void*
    pub(crate) EntryPoint: u64,  // void*
    pub(crate) SizeOfImage: u32,
    pub(crate) FullDllName: UnicodeString,
    pub(crate) BaseDllName: UnicodeString,
    pub(crate) Flags: u32,
    pub(crate) LoadCount: i16,
    pub(crate) TlsIndex: i16,
    pub(crate) HashTableEntry: ListEntry,
    pub(crate) TimeDateStamp: u32,
}

impl LdrModule {
    pub fn getNextInLoadOrderModuleListWithDirbase(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
    ) -> Option<LdrModule> {
        self.InLoadOrderModuleList
            .getNextWithDirbase(vm, dirbase, 0)
    }

    pub fn getNextInMemoryOrderModuleListWithDirbase(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
    ) -> Option<LdrModule> {
        self.InMemoryOrderModuleList.getNextWithDirbase(
            vm,
            dirbase,
            std::mem::size_of::<ListEntry>() as u64,
        )
    }
}
