extern crate static_assertions as sa;

use crate::vmsession::bytesLargeFmt::*;
use crate::vmsession::list_entry::{ListEntry, SingleListEntry};
use crate::vmsession::peb_ldr_data::PebLdrData;
use crate::vmsession::VMSession;
use vmread::WinProcess;

#[derive(Debug, Copy, Clone)]
pub struct PEBBitfieldReading {
    ImageUsesLargePages: bool,
    IsProtectedProcess: bool,
    IsLegacyProcess: bool,
    IsImageDynamicallyRelocated: bool,
    SkipPatchingUser32Forwarders: bool,
    SpareBit0: bool,
    SpareBit1: bool,
    SpareBit2: bool,
}

#[derive(Copy, Clone)]
pub struct PEBBitfield(u8);

impl PEBBitfield {
    fn interpret(&self) -> Option<PEBBitfieldReading> {
        let s = self.as_bitstr();
        if s.len() != 8 {
            return None;
        }
        let serialized = s.as_bytes();
        Some(PEBBitfieldReading {
            ImageUsesLargePages: serialized[0] == '1' as u8,
            IsProtectedProcess: serialized[1] == '1' as u8,
            IsLegacyProcess: serialized[2] == '1' as u8,
            IsImageDynamicallyRelocated: serialized[3] == '1' as u8,
            SkipPatchingUser32Forwarders: serialized[4] == '1' as u8,
            SpareBit0: serialized[5] == '1' as u8,
            SpareBit1: serialized[6] == '1' as u8,
            SpareBit2: serialized[7] == '1' as u8,
        })
    }

    fn as_bitstr(&self) -> String {
        let s = format!("{:b}", self.0);
        format!("{}{}", "0".repeat(8 - s.len()), s)
            .chars()
            .rev()
            .collect::<String>()
    }
}

impl std::fmt::Debug for PEBBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PEBBitfield(dec={}, beBinary={:b}, intermediate={}, detailed={:#?})",
            self.0,
            self.0,
            self.as_bitstr(),
            self.interpret().unwrap(),
        )
    }
}

impl FullPEB {
    pub fn read_loader(&self, vm: &VMSession, proc: &WinProcess) -> PebLdrData {
        proc.read(&vm.native_ctx, self.Ldr)
    }
    pub fn read_loader_using_dirbase(&self, vm: &VMSession, dirbase: u64) -> PebLdrData {
        vm.read_physical(vm.translate(dirbase, self.Ldr))
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FullPEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingFebugged: u8,
    pub BitField: PEBBitfield,
    pub Padding0: [u8; 4usize],
    pub Mutant: u64,
    pub ImageBaseAddress: u64,
    pub Ldr: u64,                  // ptr
    pub ProcessParameters: u64,    // ptr (0x0020) to RTL_USER_PROCESS_PARAMETERS64
    pub SubSystemData: u64,        // ptr (0x0028)
    pub ProcessHeap: u64,          // ptr (0x0030)
    pub FastPebLock: u64,          // ptr (0x0038)
    pub _SYSTEM_DEPENDENT_02: u64, // ptr (0x0040)
    pub _SYSTEM_DEPENDENT_03: u64, // ptr (0x0048)
    pub _SYSTEM_DEPENDENT_04: u64, // ptr (0x0050)
    pub CbTableOrSharedInfo: u64,  // ptr (0x0058) to UserSharedInfoPtr or KernelCallbackTable
    pub SystemReserved: u32,
    pub _SYSTEM_DEPENDENT_05: u32,               // ptr (0x0064)
    pub _SYSTEM_DEPENDENT_06: u64,               // ptr (0x0068)
    pub TlsExpansionCounter: u64,                // ptr (0x0070)
    pub TlsBitmap: u64,                          // ptr (0x0078)
    pub TlsBitmapBits: [u32; 2],                 // ptr (0x0080)
    pub ReadOnlySharedMemoryBase: u64,           // ptr (0x0088)
    pub _SYSTEM_DEPENDENT_07: u64,               // ptr (0x0090)
    pub ReadOnlyStaticServerData: u64,           // ptr (0x0098)
    pub AnsiCodePageData: u64,                   // ptr (0x00A0)
    pub OemCodePageData: u64,                    // ptr (0x00A8)
    pub UnicodeCaseTableData: u64,               // ptr (0x00B0)
    pub NumberOfProcessors: u32,                 // ptr (0x00B8)
    pub NtGlobalFlag: u32,                       // ptr (0x00BC)
    pub CriticalSectionTimeout: u64,             // ptr (0x00C0)
    pub HeapSegmentReserve: u64,                 // ptr (0x00C8)
    pub HeapSegmentCommit: u64,                  // ptr (0x00D0)
    pub HeapDeCommitTotalFreeThreshold: u64,     // ptr (0x00D8)
    pub HeapDeCommitFreeBlockThreshold: u64,     // ptr (0x00E0)
    pub NumberOfHeaps: u32,                      // ptr (0x00E8)
    pub MaximumNumberOfHeaps: u32,               // ptr (0x00EC)
    pub ProcessHeaps: u64,                       // ptr (0x00F0) void**
    pub GdiSharedHandleTable: u64,               // ptr (0x00F8)
    pub ProcessStarterHelper: u64,               // ptr (0x0100)
    pub GdiDCAttributeList: u64,                 // ptr (0x0108)
    pub LoaderLock: u64,                         // ptr (0x0110)
    pub OSMajorVersion: u32,                     // ptr (0x0118)
    pub OSMinorVersion: u32,                     // ptr (0x011C)
    pub OSBuildNumber: u16,                      // ptr (0x0120)
    pub OSCSDVersion: u16,                       // ptr (0x0122)
    pub OSPlatformId: u32,                       // ptr (0x0124)
    pub ImageSubsystem: u32,                     // ptr (0x0128)
    pub ImageSubsystemMajorVersion: u32,         // ptr (0x012C)
    pub ImageSubsystemMinorVersion: u64,         // ptr (0x0130)
    pub ProcessAffinityMask: u64,                // ptr (0x0138)
    pub GdiHandleBuffer: [u64; 30],              // ptr (0x0140)
    pub PostProcessInitRoutine: u64,             // ptr (0x0230)
    pub TlsExpansionBitmap: u64,                 // ptr (0x0238)
    pub TlsExpansionBitmapBits: [u32; 32],       // ptr (0x0240)
    pub SessionId: u64,                          // ptr (0x02C0)
    pub AppCompatFlags: u64,                     // ptr (0x02C8)
    pub AppCompatFlagsUser: u64,                 // ptr (0x02D0)
    pub pShimData: u64,                          // ptr (0x02D8)
    pub AppCompatInfo: u64,                      // ptr (0x02E0)
    pub CSDVersion: [u8; 16],                    //     (0x02E8)
    pub ActivationContextData: u64,              // ptr (0x02F8)
    pub ProcessAssemblyStorageMap: u64,          // ptr (0x0300)
    pub SystemDefaultActivationContextData: u64, // ptr (0x0308)
    pub SystemAssemblyStorageMap: u64,           // ptr (0x0310)
    pub MinimumStackCommit: u64,                 // ptr (0x0318)
    pub FlsCallbackInfo: u64,                    // ptr (0x0320) void**
    pub FlsListHead: [u8; 16],                   // ptr (0x0328) to __LIST_ENTRY
    pub FlsBitmap: u64,                          // ptr (0x0338)
    pub FlsBitmapBits: [u8; 16],                 //     (0x0340)
    pub FlsHighIndex: u32,                       //     (0x0350)

    // Vista and Beyond
    pub WerRegistrationData: u64, // ptr (0x0358)
    pub WerShipAssertPtr: u64,    // ptr (0x0360)

    // Win7 and Beyond
    pub pContextData: u64,      // ptr (0x0368) -- unused on Win8 and beyond
    pub pImageHeaderHash: u64,  // ptr (0x0370)
    pub TracingFlags: u32,      // ptr (0x0378)
    pub Padding1: [u8; 4usize], // ptr (0x037C)
    pub CsrServerReadOnlySharedMemoryBase: u64, // ptr (0x0380)

    // Win10 and Beyond
    pub TppWorkerpListLock: u64,           // ptr (0x0388)
    pub TppWorkerpList: [u8; 16],          // ptr (0x0390) to __LIST_ENTRY
    pub WaitOnAddressHashTable: Bytes1024, // ptr (0x03A0)
    pub TelemetryCoverageHeader: u64,      // ptr (0x07A0)
    pub CloudFileFlags: u64,               // uu32 (0x07A8)
}

#[derive(Debug, Clone)]
pub struct ProcKernelInfo {
    pub name: String,
    pub eprocess: EPROCESS,
    pub eprocessVirtAddr: u64,
    pub eprocessPhysAddr: u64,
}

impl ProcKernelInfo {
    pub fn new(name: &str, eprocess: EPROCESS, virtAddr: u64, physAddr: u64) -> ProcKernelInfo {
        ProcKernelInfo {
            name: name.to_string(),
            eprocess,
            eprocessPhysAddr: physAddr,
            eprocessVirtAddr: virtAddr,
        }
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
    pub SignatureLevel: u8,                //0x6c8
    pub SectionSignatureLevel: u8,         //0x6c9
    pub Protection: u8,                    //0x6ca _PS_PROTECTION

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

pub const KTHREAD_THREAD_LIST_OFFSET: u64 = 0x2f8;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KTHREAD {
    pub Placeholder: Bytes760,
    pub ThreadListEntry: ListEntry, // 0x2f8
    pub Placeholder2: Bytes744,
}

pub const ETHREAD_THREAD_LIST_OFFSET: u64 = 0x6a8;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ETHREAD {
    pub Tcb: KTHREAD,                            //0x0 _KTHREAD
    pub CreateTime: u64,                         //0x5f0  _LARGE_INTEGER
    pub ExitTimeOrKeyedWaitChain: [u8; 0x10],    //0x5f8 _LARGE_INTEGER ExitTime or ListEntry
    pub PostBlockList: ListEntry, //0x608 listentry postblocklist or fwlinkshadow and startaddress
    pub TerminationPort: u64, //0x618 _TERMINATION_PORT* or KeyedWaitValue or ReaperLink ETHREAD*
    pub ActiveTimerListLock: u64, //0x620
    pub ActiveTimerListHead: ListEntry, //0x628
    pub CidUniqueProcess: u64, //0x638
    pub CidUniqueThread: u64, //0x640
    pub KeyedOrAlpcWaitSemaphore: [u8; 0x20], //0x648
    pub ClientSecurity: u64,  //0x668 _PS_CLIENT_SECURITY_CONTEXT
    pub IrpList: ListEntry,   //0x670
    pub TopLevelIrp: u64,     //0x680
    pub DeviceToVerify: u64,  //0x688 _DEVICE_OBJECT*
    pub Win32StartAddress: u64, //0x690 VOID*
    pub ChargeOnlySession: u64, //0x698 VOID*
    pub LegacyPowerObject: u64, //0x6a0 VOID*
    pub ThreadListEntry: ListEntry, //0x6a8
    pub RundownProtect: u64,  //0x6b8 _EX_RUNDOWN_REF
    pub ThreadLock: u64,      //0x6c0 _EX_PUSH_LOCK
    pub ReadClusterSize: u32, //0x6c8
    pub MmLockOrdering: i32,  //0x6cc
    pub CrossThreadFlags: u32, //0x6d0
    pub SameThreadPassiveFlags: u32, //0x6d4
    pub SameThreadApcFlags: u32, //0x6d8
    pub CacheManagerActive: u8, //0x6dc
    pub DisablePageFaultClustering: u8, //0x6dd
    pub ActiveFaultCount: u8, //0x6de
    pub LockOrderState: u8,   //0x6df
    pub AlpcMessageId: u64,   //0x6e0
    pub AlpcMessage: u64,     //0x6e8 VOID*  or ULONG
    pub AlpcWaitListEntry: ListEntry, //0x6f0
    pub ExitStatus: i32,      //0x700
    pub CacheManagerCount: u32, //0x704
    pub IoBoostCount: u32,    //0x708
    pub IoQoSBoostCount: u32, //0x70c
    pub IoQoSThrottleCount: u32, //0x710
    pub KernelStackReference: u32, //0x714
    pub BoostList: ListEntry, //0x718
    pub DeboostList: ListEntry, //0x728
    pub BoostListLock: u64,   //0x738
    pub IrpListLock: u64,     //0x740
    pub ReservedForSynchTracking: u64, //0x748 VOID*
    pub CmCallbackListHead: SingleListEntry, //0x750
    pub ActivityId: u64,      //0x758 _GUID*
    pub SeLearningModeListHead: SingleListEntry, //0x760
    pub VerifierContext: u64, //0x768 VOID*
    pub AdjustedClientToken: u64, //0x770 VOID*
    pub WorkOnBehalfThread: u64, //0x778 VOID*
    pub PropertySet: [u8; 0x18], //0x780 _PS_PROPERTY_SET
    pub PicoContext: u64,     //0x798 VOID*
    pub UserFsBase: u64,      //0x7a0
    pub UserGsBase: u64,      //0x7a8
    pub EnergyValues: u64,    //0x7b0 _THREAD_ENERGY_VALUES*
    pub CmDbgInfo: u64,       //0x7b8 VOID*
    pub SelectedCpuSetsOrIndirect: u64, //0x7c0 ulonglong or ulonglong*
    pub Silo: u64,            //0x7c8 _EJOB*
    pub ThreadName: u64,      //0x7d0 _UNICODE_STRING*
    pub SetContextState: u64, //0x7d8 _CONTEXT*
    pub LastExpectedRunTime: u32, //0x7e0
    pub HeapData: u32,        //0x7e4
    pub OwnerEntryListHead: ListEntry, //0x7e8
    pub DisownedOwnerEntryListLock: u64, //0x7f8
    pub DisownedOwnerEntryListHead: ListEntry, //0x800
}

// 0x2d8 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<KPROCESS>() == 0x2d8);

// 0x850 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<EPROCESS>() == 0x850);

// 0x810 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<ETHREAD>() == 0x810);

// 0x5f0 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<KTHREAD>() == 0x5f0);
