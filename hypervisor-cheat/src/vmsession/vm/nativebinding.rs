#![allow(dead_code)]
use crate::vmsession::proc_kernelinfo::ProcKernelInfo;
use crate::vmsession::vm::{VMBinding, WinExport};
use crate::vmsession::win::eprocess::EPROCESS;
use crate::vmsession::win::ethread::{ETHREAD, KTHREAD_THREAD_LIST_OFFSET};
use crate::vmsession::win::heap_entry::HEAP;
use crate::vmsession::win::peb::FullPEB;
use itertools::Itertools;
use pelite::image::{IMAGE_DATA_DIRECTORY, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER};
use pelite::pe64::image::IMAGE_OPTIONAL_HEADER;
use std::collections::HashMap;
use std::mem::size_of;

impl VMBinding {
    pub fn list_kernel_exports(&self) {
        for (sname, rec) in self.cachedNtExports.iter() {
            println!("KernelExport @ 0x{:x}\t{}", rec.address, sname);
        }
    }

    pub fn find_kernel_export(&self, name: &str) -> Option<u64> {
        match self.cachedNtExports.get(name) {
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
        let ptr: u64 = self.read(physProcess + peb_offset_from_eprocess);
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

    pub fn get_processes(&self, require_alive: bool) -> HashMap<u64, ProcKernelInfo> {
        let mut m: HashMap<u64, ProcKernelInfo> = HashMap::new();
        let mut curProc = self.initialProcess.eprocessAddr;
        let mut virtProcess = self.initialProcess.eprocessVA;
        loop {
            let eprocess: EPROCESS = self.read(curProc);
            if eprocess.UniqueProcessId == 0 {
                println!("Returning early from walking EPROCESS because PID is 0");
                break;
            }

            let dirbase = eprocess.Pcb.DirectoryTableBase;

            // The end of the process list usually has corrupted values,
            // some sort of address, and we avoid the issue by checking
            // the PID (which shouldn't be over 32 bit limit anyways)
            if eprocess.UniqueProcessId >= 2u64.pow(31) {
                // println!("Skipping EPROCESS entry due to due to corrupt PID");
            } else if eprocess.Pcb.StackCount < 1 {
                // println!("Skipping EPROCESS entry due to due to StackCount = 0");
            } else {
                let peb = self.get_full_peb(eprocess.Pcb.DirectoryTableBase, curProc);
                let ldr = peb.read_loader_with_dirbase(&self, dirbase);
                let base_module_name =
                    match ldr.getFirstInMemoryOrderModuleListWithDirbase(&self, dirbase) {
                        None => eprocess.ImageFileName.iter().map(|b| *b as char).join(""),
                        Some(m) => m
                            .BaseDllName
                            .resolve(&self, Some(dirbase), Some(512))
                            .unwrap_or("unknown".to_string()),
                    };
                // Liveness check
                let pe_magic: [u8; 2] = self.vread(dirbase, peb.ImageBaseAddress);
                let valid_pe = pe_magic[0] == 'M' as u8 && pe_magic[1] == 'Z' as u8;
                if valid_pe || !require_alive {
                    m.insert(
                        eprocess.UniqueProcessId,
                        ProcKernelInfo::new(&base_module_name, eprocess, virtProcess, curProc),
                    );
                }
            }

            let aplOffset = self.offsets.unwrap().apl as u64;
            let vp: u64 = self.read(curProc + aplOffset);
            virtProcess = vp - aplOffset;
            if virtProcess == 0 {
                println!("Returning early from walking EPROCESS list due to VIRTPROC == 0");
                break;
            }
            curProc = self.native_translate(self.initialProcess.dirBase, virtProcess);
            if curProc == 0 {
                println!("Returning early from walking EPROCESS list due to CURPROC == 0");
                break;
            }
            if curProc == self.initialProcess.eprocessAddr
                || virtProcess == self.initialProcess.eprocessVA
            {
                // println!("Completed walking kernel EPROCESS list");
                break;
            }
        }
        return m;
    }

    pub fn threads_from_eprocess(&self, info: &ProcKernelInfo) -> Vec<ETHREAD> {
        // The non KPROCESS ThreadList doesn't seem to work but this is an okay workaround.
        let mut kThNext: Option<ETHREAD> = info.eprocess.Pcb.ThreadListHead.getNextWithDirbase(
            &self,
            Some(info.eprocess.Pcb.DirectoryTableBase),
            KTHREAD_THREAD_LIST_OFFSET,
        );
        let active_thread_count = info.eprocess.ActiveThreads;
        let mut threads = Vec::with_capacity(active_thread_count as usize);
        for _ in 0..active_thread_count {
            match kThNext {
                Some(curr) => {
                    kThNext = curr.Tcb.ThreadListEntry.getNextWithDirbase(
                        &self,
                        Some(info.eprocess.Pcb.DirectoryTableBase),
                        KTHREAD_THREAD_LIST_OFFSET,
                    );
                    threads.push(curr);
                }
                None => break,
            }
        }
        return threads;
    }
}
