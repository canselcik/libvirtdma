extern crate static_assertions as sa;
use crate::vmsession::bytesLargeFmt::*;
use crate::vmsession::list_entry::{ListEntry, SingleListEntry};

// 0x810 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<ETHREAD>() == 0x810);

// 0x5f0 bytes (sizeof) on Windows 10 | 2016 1809 Redstone 5 (October Update) x64
sa::const_assert!(std::mem::size_of::<KTHREAD>() == 0x5f0);

pub const KTHREAD_THREAD_LIST_OFFSET: u64 = 0x2f8;
pub const ETHREAD_THREAD_LIST_OFFSET: u64 = 0x6a8;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KTHREAD {
    pub Placeholder: Bytes760,
    pub ThreadListEntry: ListEntry,            //0x2f8
    pub MutantListHead: ListEntry,             //0x308
    pub AbEntrySummary: u8,                    //0x318
    pub AbWaitEntryCount: u8,                  //0x319
    pub AbAllocationRegionCount: u8,           //0x31a
    pub SystemPriority: u8,                    //0x31b
    pub SecureThreadCookie: u32,               //0x31c
    pub LockEntries: [Bytes96; 6],             //0x320
    pub PropagateBoostsEntry: SingleListEntry, //0x560
    pub IoSelfBoostsEntry: SingleListEntry,    //0x568
    pub PriorityFloorCounts: [u8; 16],         //0x570
    pub PriorityFloorSummary: u32,             //0x580
    pub AbCompletedIoBoostCount: i32,          //0x584
    pub AbCompletedIoQoSBoostCount: i32,       //0x588
    pub KeReferenceCount: i16,                 //0x58c
    pub AbOrphanedEntrySummary: u8,            //0x58e
    pub AbOwnedEntryCount: u8,                 //0x58f
    pub ForegroundLossTime: u32,               //0x590
    pub GlobalForegroundListEntry: ListEntry,  //0x598
    pub ReadOperationCount: u64,               //0x5a8
    pub WriteOperationCount: u64,              //0x5b0
    pub OtherOperationCount: u64,              //0x5b8
    pub ReadTransferCount: u64,                //0x5c0
    pub WriteTransferCount: u64,               //0x5c8
    pub OtherTransferCount: u64,               //0x5d0
    pub QueuedScb: u64,                        //0x5d8 _KSCB*
    pub ThreadTimerDelay: u32,                 //0x5e0
    pub ThreadFlags2: u32,                     //0x5e4
    pub SchedulerAssist: u64,                  //0x5e8 VOID*
}

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
