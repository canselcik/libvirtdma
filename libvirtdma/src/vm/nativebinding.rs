#![allow(dead_code)]
use crate::proc_kernelinfo::ProcKernelInfo;
use crate::vm::WinExport;
use crate::win::eprocess::EPROCESS;
use crate::win::ethread::{ETHREAD, KTHREAD_THREAD_LIST_OFFSET};
use crate::win::heap_entry::HEAP;
use crate::win::peb::FullPEB;
use pelite::image::{IMAGE_DATA_DIRECTORY, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER};
use pelite::pe64::image::IMAGE_OPTIONAL_HEADER;
use std::collections::HashMap;
use std::mem::size_of;
use crate::vm::VMBinding;
use itertools::Itertools;

impl VMBinding {
    pub fn list_kernel_exports(&self) {
        for (sname, rec) in self.cached_nt_exports.iter() {
            println!("KernelExport @ 0x{:x}\t{}", rec.address, sname);
        }
    }

    pub fn find_kernel_export(&self, name: &str) -> Option<u64> {
        match self.cached_nt_exports.get(name) {
            None => None,
            Some(export) => Some(export.address),
        }
    }

    pub fn get_module_exports(
        &self,
        dirbase: u64,
        module_base: u64,
    ) -> Result<HashMap<String, WinExport>, String> {
        let mut hmap = HashMap::new();

        let nt_headers_addr = match self.get_nt_header(dirbase, module_base) {
            Some((_, addr)) => addr,
            _ => return Err("couldn't get the NT header".to_string()),
        };

        let data_dir_offset =
            size_of::<IMAGE_FILE_HEADER>() + size_of::<u32>() + size_of::<IMAGE_OPTIONAL_HEADER>()
                - size_of::<[IMAGE_DATA_DIRECTORY; 0]>();
        let export_table: IMAGE_DATA_DIRECTORY =
            self.vread(dirbase, nt_headers_addr + data_dir_offset as u64);
        if export_table.Size > 0x7fffffu32 {
            return Err(format!(
                "table size of 0x{:x} is greater than 0x7fffff",
                export_table.Size
            ));
        }
        if export_table.VirtualAddress as u64 == module_base {
            return Err(format!(
                "VirtualAddress of export_table equals the module_base 0x{:x}",
                module_base
            ));
        }
        if export_table.Size < size_of::<IMAGE_EXPORT_DIRECTORY>() as u32 {
            return Err(format!(
                "ExportTable size ({:x}) is smaller than size of IMAGE_EXPORT_DIRECTORY",
                export_table.Size,
            ));
        }

        let buf_begin = module_base + export_table.VirtualAddress as u64;
        let export_dir: IMAGE_EXPORT_DIRECTORY = self.vread(dirbase, buf_begin);
        if export_dir.NumberOfNames == 0 || export_dir.AddressOfNames == 0 {
            return Err(format!(
                "IMAGE_EXPORT_DIRECTORY->NumberOfNames or AddressOfNames is 0"
            ));
        }

        let names_ptr: u64 = module_base + export_dir.AddressOfNames as u64;
        // if export_dir.AddressOfNames as usize - exportOffset
        //     + export_dir.NumberOfNames as usize * size_of::<u32>()
        //     > export_table.Size as usize
        // {
        //     return Err(format!("Offset issues for names"));
        // }

        let ordinals_ptr: u64 = module_base + export_dir.AddressOfNameOrdinals as u64;
        // if export_dir.AddressOfNameOrdinals as usize - exportOffset
        //     + export_dir.NumberOfNames as usize * size_of::<u16>()
        //     > export_table.Size as usize
        // {
        //     return Err(format!("Offset issues for ordinals"));
        // }

        let fn_ptr: u64 = module_base + export_dir.AddressOfFunctions as u64;
        // if export_dir.AddressOfFunctions as usize - exportOffset
        //     + export_dir.NumberOfFunctions as usize * size_of::<u32>()
        //     > export_table.Size as usize
        // {
        //     return Err(format!("Offset issues for functions"));
        // }

        for i in 0..export_dir.NumberOfNames as u64 {
            let name_pos = names_ptr + i * size_of::<u32>() as u64;
            let ordinal_pos = ordinals_ptr + i * size_of::<u16>() as u64;

            let name_ptr: u32 = self.vread(dirbase, name_pos);
            let name = self.read_cstring_from_physical_mem(
                self.native_translate(dirbase, module_base + name_ptr as u64),
                Some(128),
            );

            let ordinal: u16 = self.vread(dirbase, ordinal_pos);
            let fn_pos = fn_ptr + ordinal as u64 * size_of::<u32>() as u64;
            let func: u32 = self.vread(dirbase, fn_pos);

            hmap.insert(
                name.clone(),
                WinExport {
                    name: name.clone(),
                    address: func as u64 + module_base,
                },
            );
        }
        return Ok(hmap);
    }

    pub fn get_full_peb(&self, dirbase: u64, phys_process: u64) -> FullPEB {
        let peb_offset_from_eprocess = self.offsets.unwrap().peb as u64;
        let ptr: u64 = self.read(phys_process + peb_offset_from_eprocess);
        self.vread(dirbase, ptr)
    }

    pub fn get_process_heap(&self, dirbase: u64, phys_process: u64) -> Vec<HEAP> {
        let peb = self.get_full_peb(dirbase, phys_process);
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
        let mut cur_proc = self.initial_process.eprocess_addr;
        let mut virt_process = self.initial_process.eprocess_va;
        loop {
            let eprocess: EPROCESS = self.read(cur_proc);
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
                let peb = self.get_full_peb(eprocess.Pcb.DirectoryTableBase, cur_proc);
                let ldr = peb.read_loader_with_dirbase(&self, dirbase);
                let base_module_name =
                    match ldr.get_first_in_memory_order_module_list_with_dirbase(&self, dirbase) {
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
                        ProcKernelInfo::new(&base_module_name, eprocess, virt_process, cur_proc),
                    );
                }
            }

            let apl_offset = self.offsets.unwrap().apl as u64;
            let vp: u64 = self.read(cur_proc + apl_offset);
            virt_process = vp - apl_offset;
            if virt_process == 0 {
                println!("Returning early from walking EPROCESS list due to VIRTPROC == 0");
                break;
            }
            cur_proc = self.native_translate(self.initial_process.dirbase, virt_process);
            if cur_proc == 0 {
                println!("Returning early from walking EPROCESS list due to CURPROC == 0");
                break;
            }
            if cur_proc == self.initial_process.eprocess_addr
                || virt_process == self.initial_process.eprocess_va
            {
                // println!("Completed walking kernel EPROCESS list");
                break;
            }
        }
        return m;
    }

    pub fn threads_from_eprocess(&self, info: &ProcKernelInfo) -> Vec<ETHREAD> {
        // The non KPROCESS ThreadList doesn't seem to work but this is an okay workaround.
        let mut k_th_next: Option<ETHREAD> = info.eprocess.Pcb.ThreadListHead.get_next_with_dirbase(
            &self,
            Some(info.eprocess.Pcb.DirectoryTableBase),
            KTHREAD_THREAD_LIST_OFFSET,
        );
        let active_thread_count = info.eprocess.ActiveThreads;
        let mut threads = Vec::with_capacity(active_thread_count as usize);
        for _ in 0..active_thread_count {
            match k_th_next {
                Some(curr) => {
                    k_th_next = curr.Tcb.ThreadListEntry.get_next_with_dirbase(
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
