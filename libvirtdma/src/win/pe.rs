#![allow(non_snake_case)]
use std::mem::size_of;
use crate::vm::VMBinding;
use std::fmt::Formatter;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ImageBaseRelocation {
   pub VirtualAddress: u32,
   pub SizeOfBlock: u32,
}

#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct TypeOffset {
    #[bitfield(name = "Type", ty = "u16", bits = "0..=3")]
    #[bitfield(name = "Offset", ty = "u16", bits = "4..=15")]
    pub value: [u8; 2],
}

impl std::fmt::Debug for TypeOffset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f, "TypeOffset[type={}, offset={}]",
            self.Type(), self.Offset(),
        )
    }
}

impl ImageBaseRelocation {
    pub fn get_type_offsets(&self, vm: &VMBinding, dtb: u64, va_self: u64) -> Vec<TypeOffset> {
        let typeoffset_size = size_of::<TypeOffset>() as u64;
        let count = (self.SizeOfBlock as u64 - size_of::<Self>() as u64) / typeoffset_size;
        let va_self_end = va_self + size_of::<Self>() as u64;

        let mut output = Vec::new();
        for i in 0..count {
            let typeoffset = vm.vread(dtb, i * typeoffset_size + va_self_end);
            output.push(typeoffset);
        }
        return output;
   }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
//0x108 bytes (sizeof)
pub struct ImageNtHeaders64 {
    pub Signature: u32,                                                //0x0
    pub FileHeader: ImageFileHeader,                                   //0x4
    pub OptionalHeader: ImageOptionalHeader64,                         //0x18
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
//0x14 bytes (sizeof)
pub struct ImageFileHeader {
    pub Machine: u16,                                                          //0x0
    pub NumberOfSections: u16,                                                 //0x2
    pub TimeDateStamp: u32,                                                    //0x4
    pub PointerToSymbolTable: u32,                                             //0x8
    pub NumberOfSymbols: u32,                                                  //0xc
    pub SizeOfOptionalHeader: u16,                                             //0x10
    pub Characteristics: u16,                                                  //0x12
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
//0x8 bytes (sizeof)
pub struct ImageDataDirectory {
    pub VirtualAddress: u32,                                           //0x0
    pub Size: u32,                                                     //0x4
}

//0x28 bytes (sizeof)
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ImageSectionHeader {
    pub Name: [u8; 8],                                                            //0x0
    pub PhysicalAddressOrVirtualSize: u32,                                        //0x8
    pub VirtualAddress: u32,                                                      //0xc
    pub SizeOfRawData: u32,                                                       //0x10
    pub PointerToRawData: u32,                                                    //0x14
    pub PointerToRelocations: u32,                                                //0x18
    pub PointerToLinenumbers: u32,                                                //0x1c
    pub NumberOfRelocations: u16,                                                 //0x20
    pub NumberOfLinenumbers: u16,                                                 //0x22
    pub Characteristics: u32,                                                     //0x24
}

impl ImageSectionHeader {
    pub fn get_name(&self) -> String {
        self.Name.iter().map(|b| *b as char).collect()
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
//0xf0 bytes (sizeof)
pub struct ImageOptionalHeader64 {
    pub Magic: u16,                             //0x0
    pub MajorLinkerVersion: u8,                 //0x2
    pub MinorLinkerVersion: u8,                 //0x3
    pub SizeOfCode: u32,                        //0x4
    pub SizeOfInitializedData: u32,             //0x8
    pub SizeOfUninitializedData: u32,           //0xc
    pub AddressOfEntryPoint: u32,               //0x10
    pub BaseOfCode: u32,                        //0x14
    pub ImageBase: u64,                         //0x18
    pub SectionAlignment: u32,                  //0x20
    pub FileAlignment: u32,                     //0x24
    pub MajorOperatingSystemVersion: u16,       //0x28
    pub MinorOperatingSystemVersion: u16,       //0x2a
    pub MajorImageVersion: u16,                 //0x2c
    pub MinorImageVersion: u16,                 //0x2e
    pub MajorSubsystemVersion: u16,             //0x30
    pub MinorSubsystemVersion: u16,             //0x32
    pub Win32VersionValue: u32,                 //0x34
    pub SizeOfImage: u32,                       //0x38
    pub SizeOfHeaders: u32,                     //0x3c
    pub CheckSum: u32,                          //0x40
    pub Subsystem: u16,                         //0x44
    pub DllCharacteristics: u16,                //0x46
    pub SizeOfStackReserve: u64,                //0x48
    pub SizeOfStackCommit: u64,                 //0x50
    pub SizeOfHeapReserve: u64,                 //0x58
    pub SizeOfHeapCommit: u64,                  //0x60
    pub LoaderFlags: u32,                       //0x68
    pub NumberOfRvaAndSizes: u32,               //0x6c
    pub DataDirectory: [ImageDataDirectory; 16],//0x70
}