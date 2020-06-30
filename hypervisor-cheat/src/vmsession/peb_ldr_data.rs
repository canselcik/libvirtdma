use crate::vmsession::list_entry::ListEntry;
use crate::vmsession::unicode_string::UnicodeString;
use vmread::WinProcess;
use vmread_sys::WinCtx;

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
    pub fn getFirstInLoadOrderModuleListForProcess(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
    ) -> Option<LdrModule> {
        self.InLoadOrderModuleList
            .getNextFromProcess(native_ctx, proc, 0)
    }

    pub fn getFirstInMemoryOrderModuleListForProcess(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
    ) -> Option<LdrModule> {
        // For some reason we get full paths on this
        self.InMemoryOrderModuleList.getNextFromProcess(
            native_ctx,
            proc,
            std::mem::size_of::<ListEntry>() as u64,
        )
    }

    pub fn getFirstInInitializationOrderModuleListForProcess(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
    ) -> Option<LdrModule> {
        self.InInitializationOrderModuleList.getNextFromProcess(
            native_ctx,
            proc,
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
    pub fn getNextInLoadOrderModuleListForProcess(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
    ) -> Option<LdrModule> {
        self.InLoadOrderModuleList
            .getNextFromProcess(native_ctx, proc, 0)
    }

    pub fn getNextInMemoryOrderModuleListForProcess(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
    ) -> Option<LdrModule> {
        self.InMemoryOrderModuleList.getNextFromProcess(
            native_ctx,
            proc,
            std::mem::size_of::<ListEntry>() as u64,
        )
    }

    pub fn getNextInInitializationOrderModuleListForProcess(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
    ) -> Option<LdrModule> {
        self.InInitializationOrderModuleList.getNextFromProcess(
            native_ctx,
            proc,
            2 * std::mem::size_of::<ListEntry>() as u64,
        )
    }
}