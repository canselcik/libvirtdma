#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

macro_rules! implNopFmtDebug {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}(len=0x{:x})",
                    stringify!($name),
                    std::mem::size_of::<$name>()
                )
            }
        }
    };
}

use crate::win::list_entry::ListEntry;
use crate::win::misc::*;
use crate::win::peb::FullPEB;
use crate::win::unicode_string::UnicodeString;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ProcessorNumber {
    pub Group: u16,
    pub Number: u8,
    pub Reserved: u8,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ActivationContextStack {
    pub ActiveFrame: *mut libc::c_void,
    pub FrameListCache: ListEntry,
    pub Flags: u32,
    pub NextCookieSequenceNumber: u32,
    pub StackId: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ClientID {
    pub UniqueProcess: u64,
    pub UniqueThread: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NtTIB {
    pub ExceptionList: *mut libc::c_void,
    pub StackBase: *mut libc::c_void,
    pub StackLimit: *mut libc::c_void,
    pub SubSystemTib: *mut libc::c_void,
    pub FiberDataOrVersion: FiberDataOrVersion,
    pub ArbitraryUserPointer: *mut libc::c_void,
    pub Self_0: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union FiberDataOrVersion {
    pub FiberData: *mut libc::c_void,
    pub Version: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TEB {
    pub NtTib: NtTIB,
    pub EnvironmentPointer: *mut libc::c_void,
    pub ClientId: ClientID,
    pub ActiveRpcHandle: *mut libc::c_void,
    pub ThreadLocalStoragePointer: *mut libc::c_void,
    pub ProcessEnvironmentBlock: *mut FullPEB,
    pub LastErrorValue: u32,
    pub CountOfOwnedCriticalSections: u32,
    pub CsrClientThread: *mut libc::c_void,
    pub Win32ThreadInfo: *mut libc::c_void,
    pub User32Reserved: [u32; 26],
    pub UserReserved: [u32; 5],
    pub WOW32Reserved: *mut libc::c_void,
    pub CurrentLocale: u32,
    pub FpSoftwareStatusRegister: u32,
    pub ReservedForDebuggerInstrumentation: [*mut libc::c_void; 16],
    pub SystemReserved1: [*mut libc::c_void; 30],
    pub PlaceholderCompatibilityMode: i8,
    pub PlaceholderHydrationAlwaysExplicit: u8,
    pub PlaceholderReserved: [i8; 10],
    pub ProxiedProcessId: u32,
    pub _ActivationStack: ActivationContextStack,
    pub WorkingOnBehalfTicket: [u8; 8],
    pub ExceptionCode: i32,
    pub Padding0: [u8; 4],
    pub ActivationContextStackPointer: *mut ActivationContextStack,
    pub InstrumentationCallbackSp: u64,
    pub InstrumentationCallbackPreviousPc: u64,
    pub InstrumentationCallbackPreviousSp: u64,
    pub TxFsContext: u32,
    pub InstrumentationCallbackDisabled: u8,
    pub UnalignedLoadStoreExceptions: u8,
    pub Padding1: [u8; 2],
    pub GdiTebBatch: Bytes1256,
    pub RealClientId: ClientID,
    pub GdiCachedProcessHandle: *mut libc::c_void,
    pub GdiClientPID: u32,
    pub GdiClientTID: u32,
    pub GdiThreadLocalInfo: *mut libc::c_void,
    pub Win32ClientInfo: Bytes496,
    pub glDispatchTable: VoidPointers233,
    pub glReserved1: [u64; 29],
    pub glReserved2: *mut libc::c_void,
    pub glSectionInfo: *mut libc::c_void,
    pub glSection: *mut libc::c_void,
    pub glTable: *mut libc::c_void,
    pub glCurrentRC: *mut libc::c_void,
    pub glContext: *mut libc::c_void,
    pub LastStatusValue: u32,
    pub Padding2: [u8; 4],
    pub StaticUnicodeString: UnicodeString,
    pub StaticUnicodeBuffer: DoubleBytes261,
    pub Padding3: [u8; 6],
    pub DeallocationStack: *mut libc::c_void,
    pub TlsSlots: VoidPointers64,
    pub TlsLinks: ListEntry,
    pub Vdm: *mut libc::c_void,
    pub ReservedForNtRpc: *mut libc::c_void,
    pub DbgSsReserved: [*mut libc::c_void; 2],
    pub HardErrorMode: u32,
    pub Padding4: [u8; 4],
    pub Instrumentation: [*mut libc::c_void; 11],
    pub ActivityId: GUID,
    pub SubProcessTag: *mut libc::c_void,
    pub PerflibData: *mut libc::c_void,
    pub EtwTraceData: *mut libc::c_void,
    pub WinSockData: *mut libc::c_void,
    pub GdiBatchCount: u32,
    pub c2rust_unnamed: IdealProcessor,
    pub GuaranteedStackBytes: u32,
    pub Padding5: [u8; 4],
    pub ReservedForPerf: *mut libc::c_void,
    pub ReservedForOle: *mut libc::c_void,
    pub WaitingOnLoaderLock: u32,
    pub Padding6: [u8; 4],
    pub SavedPriorityState: *mut libc::c_void,
    pub ReservedForCodeCoverage: u64,
    pub ThreadPoolData: *mut libc::c_void,
    pub TlsExpansionSlots: *mut *mut libc::c_void,
    pub DeallocationBStore: *mut libc::c_void,
    pub BStoreLimit: *mut libc::c_void,
    pub MuiGeneration: u32,
    pub IsImpersonating: u32,
    pub NlsCache: *mut libc::c_void,
    pub pShimData: *mut libc::c_void,
    pub HeapData: u32,
    pub Padding7: [u8; 4],
    pub CurrentTransactionHandle: *mut libc::c_void,
    pub ActiveFrame: u64, // _TEB_ACTIVE_FRAME*
    pub FlsData: *mut libc::c_void,
    pub PreferredLanguages: *mut libc::c_void,
    pub UserPrefLanguages: *mut libc::c_void,
    pub MergedPrefLanguages: *mut libc::c_void,
    pub MuiImpersonation: u32,
    pub CrossTebFlags: TebFlagsUnion,
    pub SameTebFlags: SameTebFlags,
    pub TxnScopeEnterCallback: *mut libc::c_void,
    pub TxnScopeExitCallback: *mut libc::c_void,
    pub TxnScopeContext: *mut libc::c_void,
    pub LockCount: u32,
    pub WowTebOffset: i32,
    pub ResourceRetValue: *mut libc::c_void,
    pub ReservedForWdf: *mut libc::c_void,
    pub ReservedForCrt: u64,
    pub EffectiveContainerId: GUID,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union SameTebFlags {
    pub SameTebFlags: u16,
    pub Bitfield: TebFlagsBitfield,
}

#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct TebFlagsBitfield {
    #[bitfield(name = "SafeThunkCall", ty = "u16", bits = "0..=0")]
    #[bitfield(name = "InDebugPrint", ty = "u16", bits = "1..=1")]
    #[bitfield(name = "HasFiberData", ty = "u16", bits = "2..=2")]
    #[bitfield(name = "SkipThreadAttach", ty = "u16", bits = "3..=3")]
    #[bitfield(name = "WerInShipAssertCode", ty = "u16", bits = "4..=4")]
    #[bitfield(name = "RanProcessInit", ty = "u16", bits = "5..=5")]
    #[bitfield(name = "ClonedThread", ty = "u16", bits = "6..=6")]
    #[bitfield(name = "SuppressDebugMsg", ty = "u16", bits = "7..=7")]
    #[bitfield(name = "DisableUserStackWalk", ty = "u16", bits = "8..=8")]
    #[bitfield(name = "RtlExceptionAttached", ty = "u16", bits = "9..=9")]
    #[bitfield(name = "InitialThread", ty = "u16", bits = "10..=10")]
    #[bitfield(name = "SessionAware", ty = "u16", bits = "11..=11")]
    #[bitfield(name = "LoadOwner", ty = "u16", bits = "12..=12")]
    #[bitfield(name = "LoaderWorker", ty = "u16", bits = "13..=13")]
    #[bitfield(name = "SkipLoaderInit", ty = "u16", bits = "14..=14")]
    #[bitfield(name = "SpareSameTebBits", ty = "u16", bits = "15..=15")]
    pub value: [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union TebFlagsUnion {
    pub CrossTebFlags: u16,
    pub SpareCrossTebBits: u16,
}

implNopFmtDebug!(TebFlagsUnion);
implNopFmtDebug!(IdealProcessor);
implNopFmtDebug!(IdealProcessorFlags);
implNopFmtDebug!(SameTebFlags);
implNopFmtDebug!(FiberDataOrVersion);

use crate::win::heap_entry::HEAP_ENTRY;
implNopFmtDebug!(HEAP_ENTRY);

#[derive(Copy, Clone)]
#[repr(C)]
pub union IdealProcessor {
    pub CurrentIdealProcessor: ProcessorNumber,
    pub IdealProcessorValue: u32,
    pub Flags: IdealProcessorFlags,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IdealProcessorFlags {
    pub ReservedPad0: u8,
    pub ReservedPad1: u8,
    pub ReservedPad2: u8,
    pub IdealProcessor: u8,
}
