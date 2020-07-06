#![allow(dead_code)]
use crate::vmsession::proc_kernelinfo::ProcKernelInfo;
use crate::vmsession::vm::VMBinding;
use crate::vmsession::win::ethread::KldrDataTableEntry;
use crate::vmsession::win::heap_entry::HEAP;
use crate::vmsession::win::list_entry::ListEntry;
use crate::vmsession::win::peb_ldr_data::LdrModule;
use pelite::image::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS_SIGNATURE,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use std::collections::HashMap;
use std::mem::size_of;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};

impl VMBinding {
    pub fn find_kmod(&self, name: &str) -> Option<KldrDataTableEntry> {
        match self.get_kmods() {
            Err(e) => {
                println!("Failed to get kernel modules: {}", e);
                None
            }
            Ok(kmods) => kmods.get(name).cloned(),
        }
    }

    pub fn find_process_by_pid(&self, pid: u64, require_alive: bool) -> Option<ProcKernelInfo> {
        for (_, info) in self.get_processes(require_alive).iter() {
            if info.eprocess.UniqueProcessId == pid {
                return Some(info.clone());
            }
        }
        return None;
    }

    pub fn find_process_by_name(&self, name: &str, require_alive: bool) -> Option<ProcKernelInfo> {
        for (_, info) in self.get_processes(require_alive).iter() {
            if name.to_string().eq(&info.name) {
                return Some(info.clone());
            }
        }
        return None;
    }

    pub fn list_kmods(&self) {
        match self.get_kmods() {
            Err(e) => println!("Failed to list kernel modules: {}", e),
            Ok(kmods) => {
                let mut table = Table::new();
                table.max_column_width = 45;
                table.style = TableStyle::thin();

                table.add_row(Row::new(vec![TableCell::new_with_alignment(
                    "Kernel Modules",
                    3,
                    Alignment::Center,
                )]));
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("Name", 1, Alignment::Center),
                    TableCell::new_with_alignment("Base Address", 1, Alignment::Center),
                    TableCell::new_with_alignment("Size", 1, Alignment::Center),
                ]));
                for (name, m) in kmods.iter() {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment(name, 1, Alignment::Left),
                        TableCell::new_with_alignment(
                            format!("0x{:x}", m.DllBase),
                            1,
                            Alignment::Right,
                        ),
                        TableCell::new_with_alignment(
                            format!("0x{:x}", m.SizeOfImage),
                            1,
                            Alignment::Right,
                        ),
                    ]));
                }
                println!("{}", table.render());
            }
        }
    }

    pub fn get_kmods(&self) -> Result<HashMap<String, KldrDataTableEntry>, &'static str> {
        let kernel_dirbase = self.initialProcess.dirBase;
        let module_list = match self.find_kernel_export("PsLoadedModuleList") {
            Some(addr) => addr,
            None => {
                return Err("Failed to find the 'PsLoadedModuleList' kernel export");
            }
        };

        let mut hmap: HashMap<String, KldrDataTableEntry> = HashMap::new();
        let psloadedmodulelist: ListEntry = self.vread(kernel_dirbase, module_list);

        let mut kldr: Option<KldrDataTableEntry> =
            psloadedmodulelist.getNextFromKernelInitialProcess(&self, 0);
        while let Some(m) = kldr {
            let name = m
                .BaseDllName
                .resolve(&self, Some(kernel_dirbase), Some(255))
                .unwrap_or("unknown".to_string());

            hmap.insert(name, m);
            if m.InLoadOrderLinks.Flink == module_list {
                break;
            }
            kldr = m.InLoadOrderLinks.getNextFromKernelInitialProcess(&self, 0);
        }
        Ok(hmap)
    }

    pub fn list_processes(&self, require_alive: bool) {
        let mut table = Table::new();
        table.max_column_width = 45;
        table.style = TableStyle::thin();

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "EPROCESS Walk",
            3,
            Alignment::Center,
        )]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("PID", 1, Alignment::Center),
            TableCell::new_with_alignment("Name", 1, Alignment::Center),
            TableCell::new_with_alignment("DirectoryTableBase", 1, Alignment::Center),
        ]));
        for (pid, info) in self.get_processes(require_alive).iter() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(format!("{}", pid), 1, Alignment::Center),
                TableCell::new_with_alignment(info.name.to_string(), 1, Alignment::Center),
                TableCell::new_with_alignment(
                    format!("0x{:x}", info.eprocess.Pcb.DirectoryTableBase),
                    1,
                    Alignment::Center,
                ),
            ]));
        }
        println!("{}", table.render());
    }

    pub fn dump_kmod_vmem(&self, module: &KldrDataTableEntry) -> Result<Vec<u8>, i64> {
        let begin = module.DllBase;
        let end = begin + module.SizeOfImage as u64;
        match self.getvmem(Some(self.initialProcess.dirBase), begin, end) {
            None => Err(-1),
            Some(res) => Ok(res.into_vec()),
        }
    }

    pub fn dump_module_vmem(&self, dirbase: u64, module: &LdrModule) -> Result<Vec<u8>, i64> {
        let begin = module.BaseAddress;
        let end = begin + module.SizeOfImage as u64;
        match self.getvmem(Some(dirbase), begin, end) {
            None => Err(-1),
            Some(res) => Ok(res.into_vec()),
        }
    }

    pub fn get_heaps_with_dirbase(&self, dirbase: u64, physProcess: u64) -> Vec<HEAP> {
        let peb = self.get_full_peb(dirbase, physProcess);
        let primary_heap = peb.ProcessHeap;
        println!("PEB->ProcessHeap = 0x{:x}", primary_heap);
        println!("PEB->ProcessHeaps = 0x{:x}", peb.ProcessHeaps);
        let mut res: Vec<HEAP> = Vec::new();
        let heaps_array_begin: u64 = peb.ProcessHeaps;
        for heap_index in 0..peb.NumberOfHeaps {
            let offset = heap_index as usize * size_of::<u64>();
            let heapptr = heaps_array_begin + offset as u64;
            println!("&PEB->ProcessHeaps[{}] = 0x{:x}", heap_index, heapptr);
            let heap: HEAP = self.vread(dirbase, heapptr);
            // println!("PEB->ProcessHeaps[{}] = ", heap_index, heapptr);
            res.push(heap);
        }
        return res;
    }

    pub fn pinspect(&self, proc: &mut ProcKernelInfo) {
        let dirbase = proc.eprocess.Pcb.DirectoryTableBase;
        let (match_str, mismatch_str) = ("match".to_string(), "MISMATCH".to_string());

        let peb = self.get_full_peb(dirbase, proc.eprocessPhysAddr);
        let base = match self
            .get_process_modules(&proc)
            .iter()
            .find(|m| m.BaseAddress == peb.ImageBaseAddress)
            .cloned()
        {
            None => {
                println!("Unable to find the base module");
                return;
            }
            Some(base) => base,
        };

        let mut overview = Table::new();
        overview.max_column_width = 45;
        overview.style = TableStyle::thin();

        overview.add_row(Row::new(vec![TableCell::new_with_alignment(
            format!("Overview of {}", proc.name),
            2,
            Alignment::Center,
        )]));

        let dos_header: IMAGE_DOS_HEADER = self.vread(dirbase, base.BaseAddress);

        let mut add_overview_row = |text, val| {
            overview.add_row(Row::new(vec![
                TableCell::new_with_alignment(text, 1, Alignment::Left),
                TableCell::new_with_alignment(val, 1, Alignment::Right),
            ]));
        };
        add_overview_row(
            "DOS Magic (MZ)",
            if dos_header.e_magic == IMAGE_DOS_SIGNATURE {
                match_str.clone()
            } else {
                mismatch_str.clone()
            },
        );

        let nt_header_addr = base.BaseAddress + dos_header.e_lfanew as u64;
        let new_exec_header: IMAGE_NT_HEADERS64 = self.vread(dirbase, nt_header_addr);
        add_overview_row(
            "NT Header (PE\\0\\0)",
            if new_exec_header.Signature == IMAGE_NT_HEADERS_SIGNATURE {
                match_str.clone()
            } else {
                mismatch_str.clone()
            },
        );
        add_overview_row(
            "Optional64Hdr Magic",
            if new_exec_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                match_str.clone()
            } else {
                mismatch_str.clone()
            },
        );

        add_overview_row(
            "RVA of NT Header (e_lfanew)",
            format!("0x{:x}", dos_header.e_lfanew),
        );
        add_overview_row(
            "Pointer to Symbol Table",
            format!("0x{:x}", new_exec_header.FileHeader.PointerToSymbolTable),
        );
        add_overview_row(
            "Base of Code",
            format!("0x{:x}", new_exec_header.OptionalHeader.BaseOfCode),
        );
        add_overview_row(
            "Size of Code",
            format!("0x{:x}", new_exec_header.OptionalHeader.SizeOfCode),
        );
        add_overview_row(
            "Address of EntryPoint",
            format!("0x{:x}", new_exec_header.OptionalHeader.AddressOfEntryPoint),
        );
        add_overview_row(
            "ImageBase",
            format!("0x{:x}", new_exec_header.OptionalHeader.ImageBase),
        );

        add_overview_row(
            "Symbol Count",
            format!("{}", new_exec_header.FileHeader.NumberOfSymbols),
        );

        let section_count = new_exec_header.FileHeader.NumberOfSections;
        add_overview_row("Section Count", format!("{}", section_count));

        println!("{}", overview.render());

        // TODO: Something is funky here
        let section_hdr_addr = nt_header_addr + size_of::<IMAGE_NT_HEADERS64>() as u64;
        for section_idx in 0..section_count {
            let section_header: pelite::image::IMAGE_SECTION_HEADER = self.vread(
                dirbase,
                section_hdr_addr
                    + (section_idx as u64
                        * size_of::<pelite::image::IMAGE_SECTION_HEADER>() as u64),
            );
            println!(
                "section_header: {} {:#?}",
                section_header.Name, section_header
            );
            // let section_size = next_section.VirtualAddress - data_header.VirtualAddress;
            // println!("section_size: 0x{:x}", section_header.VirtualSize);
        }
    }

    pub fn list_process_modules(&self, proc: &mut ProcKernelInfo) {
        let modules = self.get_process_modules(proc);
        if modules.is_empty() {
            println!("Unable to find any process modules");
            return;
        }
        let mut table = Table::new();
        table.max_column_width = 45;
        table.style = TableStyle::thin();

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "Process Modules",
            3,
            Alignment::Center,
        )]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Name", 1, Alignment::Center),
            TableCell::new_with_alignment("Base Address", 1, Alignment::Center),
            TableCell::new_with_alignment("Size", 1, Alignment::Center),
        ]));
        for m in modules.iter() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(
                    m.BaseDllName
                        .resolve(&self, Some(proc.eprocess.Pcb.DirectoryTableBase), Some(255))
                        .unwrap_or("unknown".to_string()),
                    1,
                    Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    format!("0x{:x}", m.BaseAddress),
                    1,
                    Alignment::Right,
                ),
                TableCell::new_with_alignment(
                    format!("0x{:x}", m.SizeOfImage),
                    1,
                    Alignment::Right,
                ),
            ]));
        }
        println!("{}", table.render());
    }

    pub fn get_process_modules(&self, info: &ProcKernelInfo) -> Vec<LdrModule> {
        let peb = self.get_full_peb(info.eprocess.Pcb.DirectoryTableBase, info.eprocessPhysAddr);
        let loader = peb.read_loader_with_dirbase(&self, info.eprocess.Pcb.DirectoryTableBase);
        let first_link = loader.InLoadOrderModuleList.Flink;

        let mut modules: Vec<LdrModule> = Vec::new();
        let mut module = loader
            .getFirstInLoadOrderModuleListWithDirbase(&self, info.eprocess.Pcb.DirectoryTableBase);
        loop {
            if module.is_none() {
                break;
            }
            let m = module.unwrap();
            if m.InLoadOrderModuleList.Flink == first_link {
                break;
            }
            let _name = match m.BaseDllName.resolve(
                &self,
                Some(info.eprocess.Pcb.DirectoryTableBase),
                Some(512),
            ) {
                Some(n) => n,
                None => "unknown".to_string(),
            };

            let _is_base_module = m.BaseAddress == peb.ImageBaseAddress;
            modules.push(m);
            module = m.getNextInLoadOrderModuleListWithDirbase(
                &self,
                Some(info.eprocess.Pcb.DirectoryTableBase),
            );
        }
        return modules;
    }
}
