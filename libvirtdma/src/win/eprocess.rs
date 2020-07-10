#![allow(non_snake_case)]
use crate::win::list_entry::{ListEntry, SingleListEntry};
use crate::win::misc::*;

// 0x1 bytes (sizeof)
#[repr(C)]
#[derive(Copy, Clone, BitfieldStruct)]
pub struct PsProtection {
    #[bitfield(name = "Type", ty = "u8", bits = "0..=2")]
    #[bitfield(name = "Audit", ty = "bool", bits = "3..=3")]
    #[bitfield(name = "Signer", ty = "u8", bits = "4..=7")]
    pub value: [u8; 1],
}

#[derive(Copy, Debug, Clone, PartialEq)]
pub enum PsProtectedType {
    None = 0,
    ProtectedLight = 1,
    Protected = 2,
    Unknown = 0xF0,
}

impl From<u8> for PsProtectedType {
    fn from(item: u8) -> Self {
        match item {
             0 => PsProtectedType::None,
             1 => PsProtectedType::ProtectedLight,
             2 => PsProtectedType::Protected,
             _ => PsProtectedType::Unknown,
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq)]
pub enum PsProtectedSigner {
    None = 0,
    Authenticode = 1,
    CodeGen = 2,
    Antimalware = 3,
    Lsa = 4,
    Windows = 5,
    WinTcb = 6,
    WinSystem = 7,
    App = 8,
    Unknown = 0xF0,
}

impl From<u8> for PsProtectedSigner {
    fn from(item: u8) -> Self {
        match item {
            0 => PsProtectedSigner::None,
            1 => PsProtectedSigner::Authenticode,
            2 => PsProtectedSigner::CodeGen,
            3 => PsProtectedSigner::Antimalware,
            4 => PsProtectedSigner::Lsa,
            5 => PsProtectedSigner::Windows,
            6 => PsProtectedSigner::WinTcb,
            7 => PsProtectedSigner::WinSystem,
            8 => PsProtectedSigner::App,
            _ => PsProtectedSigner::Unknown,
        }
    }
}

impl PsProtection {
    pub fn SignerEnum(&self) -> PsProtectedSigner {
        self.Signer().into()
    }

    pub fn TypeEnum(&self) -> PsProtectedType {
        self.Type().into()
    }
}

impl std::fmt::Debug for PsProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f, "type={:?} audit={} signer={:?}",
            self.TypeEnum(), self.Audit(), self.SignerEnum(),
        )
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EPROCESS {
    pub Pcb: KPROCESS,
    pub ProcessLock: u64, // _EX_PUSH_LOCK
    pub UniqueProcessId: u64,
    pub ActiveProcessLinks: ListEntry,
    pub RundownProtect: u64, //0x2f8 _EX_RUNDOWN_REF
    pub Flags2: u32,
    pub Flags: u32,
    pub CreateTime: u64, // _LARGE_INTEGER
    pub ProcessQuotaUsage: [u64; 2],
    pub ProcessQuotaPeak: [u64; 2],
    pub PeakVirtualSize: u64,
    pub VirtualSize: u64,
    pub SessionProcessLinks: ListEntry,
    pub ExceptionPortData: u64,
    pub Token: u64, // _EX_FAST_REF
    pub MmReserved: u64,
    pub AddressCreationLock: u64,          // _EX_PUSH_LOCK
    pub PageTableCommitmentLock: u64,      //0x370 _EX_PUSH_LOCK
    pub RotateInProgress: u64,             //0x378 _ETHREAD*
    pub ForkInProgress: u64,               //0x380 _ETHREAD*
    pub CommitChargeJob: u64,              //0x388 _EJOB*
    pub CloneRoot: u64,                    //0x390 _RTL_AVL_TREE
    pub NumberOfPrivatePages: u64,         //0x398
    pub NumberOfLockedPages: u64,          //0x3a0
    pub Win32Process: u64,                 //0x3a8 void*
    pub Job: u64,                          //0x3b0 _EJOB*
    pub SectionObject: u64,                //0x3b8 VOID*
    pub SectionBaseAddress: u64,           //0x3c0 VOID*
    pub Cookie: u32,                       //0x3c8
    pub WorkingSetWatch: u64,              //0x3d0 _PAGEFAULT_HISTORY*
    pub Win32WindowStation: u64,           //0x3d8 VOID*
    pub InheritedFromUniqueProcessId: u64, //0x3e0 VOID*
    pub Spare0: u64,                       //0x3e8 VOID*
    pub OwnerProcessId: u64,               //0x3f0
    pub Peb: u64,                          //0x3f8 _PEB*
    pub Session: u64,                      //0x400 _MM_SESSION_SPACE*
    pub Spare1: u64,                       //0x408 VOID*
    pub QuotaBlock: u64,                   //0x410 _EPROCESS_QUOTA_BLOCK*
    pub ObjectTable: u64,                  //0x418 _HANDLE_TABLE*
    pub DebugPort: u64,                    //0x420 VOID*
    pub WoW64Process: u64,                 //0x428 _EWOW64PROCESS*
    pub DeviceMap: u64,                    //0x430 VOID*
    pub EtwDataSource: u64,                //0x438 VOID*
    pub PageDirectoryPte: u64,             //0x440
    pub ImageFilePointer: u64,             //0x448 _FILE_OBJECT*
    pub ImageFileName: [u8; 15],           //0x450
    pub PriorityClass: u8,                 //0x45f
    pub SecurityPort: u64,                 //0x460 VOID*
    pub SeAuditProcessCreationInfo: u64,   //0x468 _SE_AUDIT_PROCESS_CREATION_INFO
    pub JobLinks: ListEntry,               //0x470
    pub HighestUserAddress: u64,           //0x480 VOID*
    pub ThreadListHead: ListEntry,         //0x488
    pub ActiveThreads: u32,                //0x498
    pub ImagePathHash: u32,                //0x49c
    pub DefaultHardErrorProcessing: u32,   //0x4a0
    pub LastThreadExitStatus: u32,         //0x4a4
    pub PrefetchTrace: u64,                //0x4a8 _EX_FAST_REF
    pub LockedPagesList: u64,              //0x4b0 VOID*
    pub ReadOperationCount: u64,           //0x4b8 _LARGE_INTEGER
    pub WriteOperationCount: u64,          //0x4c0 _LARGE_INTEGER
    pub OtherOperationCount: u64,          //0x4c8 _LARGE_INTEGER
    pub ReadTransferCount: u64,            //0x4d0 _LARGE_INTEGER
    pub WriteTransferCount: u64,           //0x4d8 _LARGE_INTEGER
    pub OtherTransferCount: u64,           //0x4e0 _LARGE_INTEGER
    pub CommitChargeLimit: u64,            //0x4e8
    pub CommitCharge: u64,                 //0x4f0
    pub CommitChargePeak: u64,             //0x4f8
    pub Vm: Bytes272,                      //0x500 _MMSUPPORT_FULL
    pub MmProcessLinks: ListEntry,         //0x610
    pub ModifiedPageCount: u32,            //0x620
    pub ExitStatus: u32,                   //0x624
    pub VadRoot: u64,                      //0x628 _RTL_AVL_TREE
    pub VadHint: u64,                      //0x630 VOID*
    pub VadCount: u64,                     //0x638
    pub VadPhysicalPages: u64,             //0x640
    pub VadPhysicalPagesLimit: u64,        //0x648
    pub AlpcContext: Bytes32,              //0x650 _ALPC_PROCESS_CONTEXT
    pub TimerResolutionLink: ListEntry,    //0x670
    pub TimerResolutionStackRecord: u64,   //0x680 _PO_DIAG_STACK_RECORD*
    pub RequestedTimerResolution: u32,     //0x688
    pub SmallestTimerResolution: u32,      //0x68c
    pub ExitTime: u64,                     //0x690 _LARGE_INTEGER
    pub InvertedFunctionTable: u64,        //0x698 _INVERTED_FUNCTION_TABLE*
    pub InvertedFunctionTableLock: u64,    //0x6a0 _EX_PUSH_LOCK
    pub ActiveThreadsHighWatermark: u32,   //0x6a8
    pub LargePrivateVadCount: u32,         //0x6ac
    pub ThreadListLock: u64,               //0x6b0 _EX_PUSH_LOCK
    pub WnfContext: u64,                   //0x6b8 VOID*
    pub ServerSilo: u64,                   //0x6c0 _EJOB*
    pub SignatureLevel: u8,                //0x6c8 related to protection
    pub SectionSignatureLevel: u8,         //0x6c9
    pub Protection: PsProtection,          //0x6ca _PS_PROTECTION

    pub HangOrGhostCountAndPrefilterException: u8, //0x6cb
    pub Flags3: u32, //0x6cc SystemProcess, ForegroundSystem, HighGraphicsPriority etc. in a bitfield

    pub DeviceAsid: u32,                     //0x6d0
    pub SvmData: u64,                        //0x6d8 VOID*
    pub SvmProcessLock: u64,                 //0x6e0 _EX_PUSH_LOCK
    pub SvmLock: u64,                        //0x6e8
    pub SvmProcessDeviceListHead: ListEntry, //0x6f0
    pub LastFreezeInterruptTime: u64,        //0x700
    pub DiskCounters: u64,                   //0x0078 _PROCESS_DISK_COUNTERS*
    pub PicoContext: u64,                    //0x710 VOID*
    pub EnclaveTable: u64,                   //0x718 VOID*
    pub EnclaveNumber: u64,                  //0x720
    pub EnclaveLock: u64,                    //0x728 _EX_PUSH_LOCK
    pub HighPriorityFaultsAllowed: u32,      //0x730
    pub EnergyContext: u64,                  //0x738 _PO_PROCESS_ENERGY_CONTEXT*
    pub VmContext: u64,                      //0x740 VOID*
    pub SequenceNumber: u64,                 //0x748
    pub CreateInterruptTime: u64,            //0x750
    pub CreateUnbiasedInterruptTime: u64,    //0x758
    pub TotalUnbiasedFrozenTime: u64,        //0x760
    pub LastAppStateUpdateTime: u64,         //0x768
    pub LastAppStateUptimeAndState: u64,     //0x770 LastAppStateUptime:61, LastAppState:3
    pub SharedCommitCharge: u64,             //0x778
    pub SharedCommitLock: u64,               //0x780 _EX_PUSH_LOCK
    pub SharedCommitLinks: ListEntry,        //0x788
    pub AllowedCpuSets: u64,                 //0x798 sometimes indirect w/ a pointer
    pub DefaultCpuSets: u64,                 //0x7a0 sometimes indirect w/ a pointer
    pub DiskIoAttribution: u64,              //0x7a8 VOID*
    pub DxgProcess: u64,                     //0x7b0 VOID*
    pub Win32KFilterSet: u32,                //0x7b8
    pub ProcessTimerDelay: u64,              //0x7c0 _PS_INTERLOCKED_TIMER_DELAY_VALUES
    pub KTimerSets: u32,                     //0x7c8
    pub KTimer2Sets: u32,                    //0x7cc
    pub ThreadTimerSets: u32,                //0x7d0
    pub VirtualTimerListLock: u64,           //0x7d8
    pub VirtualTimerListHead: ListEntry,     //0x7e0
    pub WakeChannelOrInfo: Bytes48,          //0x7f0 _WNF_STATE_NAME or _PS_PROCESS_WAKE_INFORMATION
    pub MitigationFlags: u32, //0x820 important FlowGuard etc. along with allow disallow syscalls dynamic code, ASLR
    pub MitigationFlags2: u32, //0x824 more important security flags
    pub PartitionObject: u64, //0x828 VOID*
    pub SecurityDomain: u64,  //0x830
    pub ParentSecurityDomain: u64, //0x838
    pub CoverageSamplerContext: u64, //0x840 VOID*
    pub MmHotPatchContext: u64, //0x848 VOID*
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KPROCESS {
    pub Header: Bytes24,                // 0x00 DispatcherHeader
    pub ProfileListHead: ListEntry,     // 0x18
    pub DirectoryTableBase: u64,        // 0x28
    pub ThreadListHead: ListEntry,      // 0x30
    pub ProcessLock: u32,               // 0x40
    pub ProcessTimerDelay: u32,         // 0x44
    pub DeepFreezeStartTime: u64,       // 0x48
    pub Affinity: Bytes168,             // 0x50 _KAFFINITY_EX
    pub ReadyListHead: ListEntry,       // 0xf8
    pub SwapListEntry: SingleListEntry, // 0x108
    pub ActiveProcessors: Bytes168,     // 0x110 _KAFFINITY_EX
    pub ProcessFlags: u32,              // 0x1b8
    pub BasePriority: u8,               // 0x1bc
    pub QuantumReset: u8,               // 0x1bd
    pub Visited: u8,                    // 0x1be
    pub Flags: u8,                      // 0x1bf
    pub ThreadSeed: Bytes80,            // 0x1c0
    pub IdealNode: Bytes40,             // 0x210
    pub IdealGlobalNode: u16,           // 0x238
    pub Spare1: u16,                    // 0x23a
    pub StackCount: u32,                // 0x23c _KSTACK_COUNT
    pub ProcessListEntry: ListEntry,    // 0x240
    pub CycleTime: u64,                 // 0x250
    pub ContextSwitches: u64,           // 0x258
    pub SchedulingGroup: u64,           // 0x260 _KSCHEDULING_GROUP*
    pub FreezeCount: u32,               // 0x268
    pub KernelTime: u32,                // 0x26c
    pub UserTime: u32,                  // 0x270
    pub ReadyTime: u32,                 // 0x274
    pub UserDirectoryTableBase: u64,    // 0x278
    pub AddressPolicy: u8,              // 0x280
    pub Spare2: Bytes71,                // 0x281
    pub InstrumentationCallback: u64,   // 0x2c8 void*
    pub SecureState: u64,               // 0x2d0
}
