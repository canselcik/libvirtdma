#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use crate::win::list_entry::ListEntry;
use crate::win::misc::Bytes336;
use crate::win::proc_heap_entry::{HeapBlock, HeapBlockOrRegion, ProcessHeapEntry};
use std::ffi::c_void;

//0x2c0 bytes (sizeof)
#[derive(Clone, Debug)]
#[repr(C)]
pub struct HEAP {
    pub Segment: HeapSegment,
    pub Flags: u32,                      //0x70
    pub ForceFlags: u32,                 //0x74
    pub CompatibilityFlags: u32,         //0x78
    pub EncodeFlagMask: u32,             //0x7c
    pub Encoding: HEAP_ENTRY,            //0x80
    pub Interceptor: u32,                //0x90
    pub VirtualMemoryThreshold: u32,     //0x94
    pub Signature: u32,                  //0x98
    pub SegmentReserve: u64,             //0xa0
    pub SegmentCommit: u64,              //0xa8
    pub DeCommitFreeBlockThreshold: u64, //0xb0
    pub DeCommitTotalFreeThreshold: u64, //0xb8
    pub TotalFreeSize: u64,              //0xc0
    pub MaximumAllocationSize: u64,      //0xc8
    pub ProcessHeapsListIndex: u16,      //0xd0
    pub HeaderValidateLength: u16,       //0xd2
    pub HeaderValidateCopy: u64,         //0xd8 void* ptr
    pub NextAvailableTagIndex: u16,      //0xe0
    pub MaximumTagIndex: u16,            //0xe2
    pub TagEntries: u64,                 //0xe8 _HEAP_TAG_ENTRY*
    pub UCRList: ListEntry,              //0xf0
    pub AlignRound: u64,                 //0x100
    pub AlignMask: u64,                  //0x108
    pub VirtualAllocdBlocks: ListEntry,  //0x110
    pub SegmentList: ListEntry,          //0x120
    pub AllocatorBackTraceIndex: i32,    //0x130 size was given wrong here
    pub NonDedicatedListLength: u32,     //0x134
    pub BlocksIndex: u64,                //0x138 void*
    pub UCRIndex: u64,                   //0x140 void*
    pub PseudoTagEntries: u64,           //0x148 _HEAP_PSEUDO_TAG_ENTRY*
    pub FreeLists: ListEntry,            //0x150
    pub LockVariable: u64,               //0x160 _HEAP_LOCK*
    pub CommitRoutine: u64, //0x168 funct pointer LONG (*CommitRoutine)(VOID* arg1, VOID** arg2, ULONGLONG* arg3)

    pub RestPlaceholder: Bytes336,
    // union _RTL_RUN_ONCE StackTraceInitVar;                                  //0x170
    // struct _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;                     //0x178
    // pub FrontEndHeap: u64,                                                     //0x198 void*
    // USHORT FrontHeapLockCount;                                              //0x1a0
    // UCHAR FrontEndHeapType;                                                 //0x1a2
    // UCHAR RequestedFrontEndHeapType;                                        //0x1a3
    // WCHAR* FrontEndHeapUsageData;                                           //0x1a8
    // USHORT FrontEndHeapMaximumIndex;                                        //0x1b0
    // volatile UCHAR FrontEndHeapStatusBitmap[129];                           //0x1b2
    // struct _HEAP_COUNTERS Counters;                                         //0x238
    // struct _HEAP_TUNING_PARAMETERS TuningParameters;                        //0x2b0
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct HeapSegment {
    pub Entry: HEAP_ENTRY,                   //0x0
    pub SegmentSignature: u32,               //0x10
    pub SegmentFlags: u32,                   //0x14
    pub SegmentListEntry: ListEntry,         //0x18
    pub Heap: *mut c_void,                   //0x28 selfptr
    pub BaseAddress: *mut c_void,            //0x30
    pub NumberOfPages: u32,                  //0x38
    pub FirstEntry: *mut HEAP_ENTRY,         //0x40
    pub LastValidEntry: *mut HEAP_ENTRY,     //0x48
    pub NumberOfUnCommittedPages: u32,       //0x50
    pub NumberOfUnCommittedRanges: u32,      //0x54
    pub SegmentAllocatorBackTraceIndex: u16, //0x58
    pub Reserved: u16,                       //0x5a
    pub UCRSegmentList: ListEntry,           //0x60
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct HEAP_ENTRY {
    pub OuterUnion: HeapEntryOuterUnion,
}

impl HEAP_ENTRY {
    pub fn into_proc_heap_entry(&self) -> ProcessHeapEntry {
        ProcessHeapEntry {
            lpData: 0, // self.OuterUnion.UnpackedEntry.,
            cbData: 0,
            cbOverhead: 0,
            iRegionIndex: 0,
            wFlags: 0,
            BlockOrRegion: HeapBlockOrRegion {
                Block: HeapBlock {
                    hMem: 0,
                    dwReserved: [0, 0, 0],
                },
            },
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union HeapEntryOuterUnion {
    pub UnpackedEntry: HEAP_UNPACKED_ENTRY,
    pub c2rust_unnamed: C2RustUnnamed_14,
    pub ExtendedEntry: HEAP_EXTENDED_ENTRY,
    pub c2rust_unnamed_0: C2RustUnnamed_11,
    pub c2rust_unnamed_1: C2RustUnnamed_6,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct HEAP_UNPACKED_ENTRY {
    pub PreviousBlockPrivateData: u64,
    pub OuterUnion: HeapUnpackedEntryOuterUnion,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct HEAP_EXTENDED_ENTRY {
    pub Reserved: u64,
    pub InterceptorUnion: HeapExtendedEntryInterceptorUnion,
    pub UnusedBytesLength: u16,
    pub EntryOffset: u8,
    pub ExtendedBlockSignature: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct HeapUnpackedEntryOuterUnionInnerStructB {
    pub SubSegmentCode: u32,
    pub PreviousSize: u16,
    pub c2rust_unnamed: C2RustUnnamed_1,
    pub UnusedBytes: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub ReservedForAlignment: u64,
    pub c2rust_unnamed: C2RustUnnamed_7,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub FunctionIndex: u16,
    pub ContextValue: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HeapUnpackedEntryOuterUnionInnerStructA {
    pub Size: u16,
    pub Flags: u8,
    pub SmallTagIndex: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union HeapUnpackedEntryOuterUnion {
    pub c2rust_unnamed: HeapUnpackedEntryOuterUnionInnerStructA,
    pub c2rust_unnamed_0: HeapUnpackedEntryOuterUnionInnerStructB,
    pub CompactHeader: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_14 {
    pub PreviousBlockPrivateData: u64,
    pub c2rust_unnamed: C2RustUnnamed_15,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_13 {
    pub FunctionIndex: u16,
    pub ContextValue: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub Code1: u32,
    pub c2rust_unnamed: C2RustUnnamed_9,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_10 {
    pub Code2: u16,
    pub Code3: u8,
    pub Code4: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_11 {
    pub Reserved: u64,
    pub c2rust_unnamed: C2RustUnnamed_12,
    pub UnusedBytesLength: u16,
    pub EntryOffset: u8,
    pub ExtendedBlockSignature: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_16 {
    pub SubSegmentCode: u32,
    pub PreviousSize: u16,
    pub c2rust_unnamed: C2RustUnnamed_17,
    pub UnusedBytes: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_18 {
    pub Size: u16,
    pub Flags: u8,
    pub SmallTagIndex: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub SegmentOffset: u8,
    pub LFHFlags: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union HeapExtendedEntryInterceptorUnion {
    pub c2rust_unnamed: C2RustUnnamed_4,
    pub InterceptorValue: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_7 {
    pub c2rust_unnamed: C2RustUnnamed_8,
    pub AgregateCode: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub c2rust_unnamed: C2RustUnnamed_10,
    pub Code234: u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_12 {
    pub c2rust_unnamed: C2RustUnnamed_13,
    pub InterceptorValue: u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_15 {
    pub c2rust_unnamed: C2RustUnnamed_18,
    pub c2rust_unnamed_0: C2RustUnnamed_16,
    pub CompactHeader: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_17 {
    pub SegmentOffset: u8,
    pub LFHFlags: u8,
}
