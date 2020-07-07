#![allow(dead_code)]
use crate::vm::VMBinding;
use crate::win::list_entry::ListEntry;
use crate::win::unicode_string::UnicodeString;

// 0x58 bytes (sizeof)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
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
    pub fn likely_invalid(&self) -> bool {
        self.Length == 0
            && self.Initialized == 0
            && self.SsHandle == 0
            && self.InLoadOrderModuleList.flink == 0
            && self.InLoadOrderModuleList.blink == 0
            && self.InMemoryOrderModuleList.flink == 0
            && self.InMemoryOrderModuleList.blink == 0
            && self.InInitializationOrderModuleList.flink == 0
            && self.InInitializationOrderModuleList.blink == 0
            && self.EntryInProgress == 0
            && self.ShutdownInProgress == 0
            && self.ShutdownThreadId == 0
    }

    pub fn get_first_in_memory_order_module_list_with_dirbase(
        &self,
        vm: &VMBinding,
        dirbase: u64,
    ) -> Option<LdrModule> {
        self.InMemoryOrderModuleList.get_next_with_dirbase(
            vm,
            Some(dirbase),
            std::mem::size_of::<ListEntry>() as u64,
        )
    }

    pub fn get_first_in_load_order_module_list_with_dirbase(
        &self,
        vm: &VMBinding,
        dirbase: u64,
    ) -> Option<LdrModule> {
        self.InLoadOrderModuleList
            .get_next_with_dirbase(vm, Some(dirbase), 0)
    }

    pub fn get_first_in_initialization_order_module_list_with_dirbase(
        &self,
        vm: &VMBinding,
        dirbase: u64,
    ) -> Option<LdrModule> {
        self.InInitializationOrderModuleList.get_next_with_dirbase(
            vm,
            Some(dirbase),
            2 * std::mem::size_of::<ListEntry>() as u64,
        )
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
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
    pub fn get_next_in_load_order_module_list_with_dirbase(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
    ) -> Option<LdrModule> {
        self.InLoadOrderModuleList
            .get_next_with_dirbase(vm, dirbase, 0)
    }

    pub fn get_next_in_memory_order_module_list_with_dirbase(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
    ) -> Option<LdrModule> {
        self.InMemoryOrderModuleList.get_next_with_dirbase(
            vm,
            dirbase,
            std::mem::size_of::<ListEntry>() as u64,
        )
    }
}
