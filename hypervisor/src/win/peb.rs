#![allow(non_snake_case)]
use crate::vm::VMBinding;
use crate::win::misc::*;
use crate::win::peb_bitfield::PEBBitfield;
use crate::win::peb_ldr_data::PebLdrData;

impl FullPEB {
    pub fn read_loader_with_dirbase(&self, vm: &VMBinding, dirbase: u64) -> PebLdrData {
        vm.vread(dirbase, self.Ldr)
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
