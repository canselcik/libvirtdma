use crate::vmsession::vm::VMBinding;
use crate::vmsession::win::heap_entry::HEAP;
use crate::vmsession::win::peb::FullPEB;
use pelite::image::{IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER};
use pelite::pe64::image::IMAGE_OPTIONAL_HEADER;
use std::collections::HashMap;
use std::mem::size_of;
use vmread::WinExport;
use vmread_sys::IMAGE_DATA_DIRECTORY;

impl VMBinding {
    pub fn list_kernel_procs(&self) {
        for (sname, rec) in self.cachedKernelExports.iter() {
            println!("KernelExport @ 0x{:x}\t{}", rec.address, sname);
        }
    }

    pub fn find_kernel_proc(&self, name: &str) -> Option<u64> {
        match self.cachedKernelExports.get(name) {
            None => None,
            Some(export) => Some(export.address),
        }
    }

    pub fn get_module_exports(
        &self,
        dirbase: u64,
        moduleBase: u64,
    ) -> Result<HashMap<String, WinExport>, String> {
        let mut hmap = HashMap::new();

        let ntHeadersAddr = match self.get_nt_header(dirbase, moduleBase) {
            Some((_, addr)) => addr,
            _ => return Err("couldn't get the NT header".to_string()),
        };

        let dataDirOffset =
            size_of::<IMAGE_FILE_HEADER>() + size_of::<u32>() + size_of::<IMAGE_OPTIONAL_HEADER>()
                - size_of::<[IMAGE_DATA_DIRECTORY; 0]>();
        let exportTable: IMAGE_DATA_DIRECTORY =
            self.vread(dirbase, ntHeadersAddr + dataDirOffset as u64);
        if exportTable.Size > 0x7fffffu32 {
            return Err(format!(
                "table size of 0x{:x} is greater than 0x7fffff",
                exportTable.Size
            ));
        }
        if exportTable.VirtualAddress as u64 == moduleBase {
            return Err(format!(
                "VirtualAddress of exportTable equals the moduleBase 0x{:x}",
                moduleBase
            ));
        }
        if exportTable.Size < size_of::<IMAGE_EXPORT_DIRECTORY>() as u32 {
            return Err(format!(
                "ExportTable size ({:x}) is smaller than size of IMAGE_EXPORT_DIRECTORY",
                exportTable.Size,
            ));
        }

        let bufBegin = moduleBase + exportTable.VirtualAddress as u64;
        let exportDir: IMAGE_EXPORT_DIRECTORY = self.vread(dirbase, bufBegin);
        if exportDir.NumberOfNames == 0 || exportDir.AddressOfNames == 0 {
            return Err(format!(
                "IMAGE_EXPORT_DIRECTORY->NumberOfNames or AddressOfNames is 0"
            ));
        }

        let namesPtr: u64 = moduleBase + exportDir.AddressOfNames as u64;
        // if exportDir.AddressOfNames as usize - exportOffset
        //     + exportDir.NumberOfNames as usize * size_of::<u32>()
        //     > exportTable.Size as usize
        // {
        //     return Err(format!("Offset issues for names"));
        // }

        let ordinalsPtr: u64 = moduleBase + exportDir.AddressOfNameOrdinals as u64;
        // if exportDir.AddressOfNameOrdinals as usize - exportOffset
        //     + exportDir.NumberOfNames as usize * size_of::<u16>()
        //     > exportTable.Size as usize
        // {
        //     return Err(format!("Offset issues for ordinals"));
        // }

        let fnPtr: u64 = moduleBase + exportDir.AddressOfFunctions as u64;
        // if exportDir.AddressOfFunctions as usize - exportOffset
        //     + exportDir.NumberOfFunctions as usize * size_of::<u32>()
        //     > exportTable.Size as usize
        // {
        //     return Err(format!("Offset issues for functions"));
        // }

        for i in 0..exportDir.NumberOfNames as u64 {
            let namePos = namesPtr + i * size_of::<u32>() as u64;
            let ordinalPos = ordinalsPtr + i * size_of::<u16>() as u64;

            let namePtr: u32 = self.vread(dirbase, namePos);
            let name = self.read_cstring_from_physical_mem(
                self.native_translate(dirbase, moduleBase + namePtr as u64),
                Some(128),
            );

            let ordinal: u16 = self.vread(dirbase, ordinalPos);
            let fnPos = fnPtr + ordinal as u64 * size_of::<u32>() as u64;
            let func: u32 = self.vread(dirbase, fnPos);

            hmap.insert(
                name.clone(),
                WinExport {
                    name: name.clone(),
                    address: func as u64 + moduleBase,
                },
            );
        }
        return Ok(hmap);
    }

    pub fn get_full_peb(&self, dirbase: u64, physProcess: u64) -> FullPEB {
        let peb_offset_from_eprocess = self.offsets.unwrap().peb as u64;
        let ptr: u64 = self.read_physical(physProcess + peb_offset_from_eprocess);
        self.vread(dirbase, ptr)
    }

    pub fn get_process_heap(&self, dirbase: u64, physProcess: u64) -> Vec<HEAP> {
        let peb = self.get_full_peb(dirbase, physProcess);
        // let primary_heap = peb.ProcessHeap;
        // println!("PEB->ProcessHeap = 0x{:x}", primary_heap);
        // println!("PEB->ProcessHeaps = 0x{:x}", peb.ProcessHeaps);
        let mut res: Vec<HEAP> = Vec::new();
        let heaps_array_begin: u64 = peb.ProcessHeaps;
        for heap_index in 0..peb.NumberOfHeaps {
            let offset = heap_index as usize * size_of::<u64>();
            let heapptr = heaps_array_begin + offset as u64;
            // println!("&PEB->ProcessHeaps[{}] = 0x{:x}", heap_index, heapptr);
            let heap: HEAP = self.vread(dirbase, heapptr);
            // println!("PEB->ProcessHeaps[{}] = ", heap_index, heapptr);
            res.push(heap);
        }
        return res;
    }
}
