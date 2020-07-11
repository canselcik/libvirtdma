#![allow(dead_code)]
use crate::proc_kernelinfo::ProcKernelInfo;
use crate::vm::VMBinding;
use crate::win::ethread::KldrDataTableEntry;
use crate::win::list_entry::ListEntry;
use crate::win::peb_ldr_data::LdrModule;
use pelite::image::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS_SIGNATURE,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use std::collections::HashMap;
use std::mem::size_of;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};
use crate::win::pe::{ImageNtHeaders64, ImageSectionHeader};
use crate::win::eprocess::{PsProtectedType, PsProtectedSigner};

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
        let kernel_dirbase = self.initial_process.dirbase;
        let module_list = match self.find_kernel_export("PsLoadedModuleList") {
            Some(addr) => addr,
            None => {
                return Err("Failed to find the 'PsLoadedModuleList' kernel export");
            }
        };

        let mut hmap: HashMap<String, KldrDataTableEntry> = HashMap::new();
        let psloadedmodulelist: ListEntry = self.vread(kernel_dirbase, module_list);

        let mut kldr: Option<KldrDataTableEntry> =
            psloadedmodulelist.get_next_from_kernel_initial_process(&self, 0);
        while let Some(m) = kldr {
            let name = m
                .BaseDllName
                .resolve(&self, Some(kernel_dirbase), Some(255))
                .unwrap_or("unknown".to_string());

            hmap.insert(name, m);
            if m.InLoadOrderLinks.flink == module_list {
                break;
            }
            kldr = m
                .InLoadOrderLinks
                .get_next_from_kernel_initial_process(&self, 0);
        }
        Ok(hmap)
    }

    pub fn set_process_security(&self, proc: &mut ProcKernelInfo, typ: PsProtectedType, signer: PsProtectedSigner) {
        let current = &mut proc.eprocess.Protection;
        if current.SignerEnum() != signer {
            current.set_Signer(signer as u8);
        }
        if current.TypeEnum() != typ {
            current.set_Type(typ as u8);
        }
        // PS_PROTECTION offset in EPROCESS
        self.write(proc.eprocessPhysAddr + 0x6ca, &current.value);
    }

    pub fn list_processes(&self, require_alive: bool) {
        let mut table = Table::new();
        table.max_column_width = 45;
        table.style = TableStyle::thin();

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "EPROCESS Walk",
            4,
            Alignment::Center,
        )]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("PID", 1, Alignment::Center),
            TableCell::new_with_alignment("Name", 1, Alignment::Center),
            TableCell::new_with_alignment("DirectoryTableBase", 1, Alignment::Center),
            TableCell::new_with_alignment("ProtectionType", 1, Alignment::Center),
            TableCell::new_with_alignment("Audit", 1, Alignment::Center),
            TableCell::new_with_alignment("Signer", 1, Alignment::Center),
        ]));
        for (pid, info) in self.get_processes(require_alive).iter() {
            let sprotect = info.eprocess.Protection;
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(format!("{}", pid), 1, Alignment::Center),
                TableCell::new_with_alignment(info.name.to_string(), 1, Alignment::Center),
                TableCell::new_with_alignment(
                    format!("0x{:x}", info.eprocess.Pcb.DirectoryTableBase),
                    1,
                    Alignment::Center,
                ),
                TableCell::new_with_alignment(
                    format!("{:?}", sprotect.TypeEnum()),
                    1,
                    Alignment::Center,
                ),
                TableCell::new_with_alignment(
                    format!("{}", sprotect.Audit()),
                    1,
                    Alignment::Center,
                ),
                TableCell::new_with_alignment(
                    format!("{:?}", sprotect.SignerEnum()),
                    1,
                    Alignment::Center,
                ),
            ]));
        }
        println!("{}", table.render());
    }

    pub fn dump_kmod_vmem(&self, module: &KldrDataTableEntry) -> Box<[u8]> {
        self.vreadvec(
            self.initial_process.dirbase,
            module.DllBase,
            module.SizeOfImage as u64,
        )
    }

    pub fn dump_module_vmem(&self, dirbase: u64, module: &LdrModule) -> Box<[u8]> {
        self.vreadvec(dirbase, module.BaseAddress, module.SizeOfImage as u64)
    }

    pub fn get_module_sections(&self, proc: &mut ProcKernelInfo, module: &LdrModule) -> Vec<ImageSectionHeader> {
        let dirbase = proc.eprocess.Pcb.DirectoryTableBase;
        let dos_header: IMAGE_DOS_HEADER = self.vread(dirbase, module.BaseAddress);

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            println!("WARN: unexpected e_magic (0x{:x})", dos_header.e_magic);
        }

        let nt_header_addr = module.BaseAddress + dos_header.e_lfanew as u64;
        let new_exec_header: ImageNtHeaders64 = self.vread(dirbase, nt_header_addr);
        if new_exec_header.Signature != IMAGE_NT_HEADERS_SIGNATURE {
            println!("WARN: unexpected NTHeader (0x{:x})", new_exec_header.Signature);
        }
        if new_exec_header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            println!("WARN: unexpected Optional64Hdr (0x{:x})", new_exec_header.OptionalHeader.Magic);
        }

        let mut res = Vec::new();
        let first_section_address = nt_header_addr + size_of::<ImageNtHeaders64>() as u64;
        for section_idx in 0..new_exec_header.FileHeader.NumberOfSections {
            let offset = section_idx as u64 * size_of::<ImageSectionHeader>() as u64;
            let section_header: ImageSectionHeader = self.vread(dirbase, first_section_address + offset);
            res.push(section_header);
        }
        return res;
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
            let dllname = m.BaseDllName
                .resolve(&self, Some(proc.eprocess.Pcb.DirectoryTableBase), Some(255))
                .unwrap_or("unknown".to_string());
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(
                    &dllname,
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
            // let exports = match self.get_module_exports(proc.eprocess.Pcb.DirectoryTableBase, m.BaseAddress) {
            //     Ok(exp) => exp,
            //     Err(e) => {
            //         println!("Failed to get exports for module: {}", e);
            //         continue;
            //     }
            // };
            for (name, export) in exports.iter() {
                println!("[0x{:x}] [{}] {}", export.address, dllname, name);
            }
        }
        println!("{}", table.render());
    }

    pub fn get_process_modules_map(&self, info: &ProcKernelInfo) -> HashMap<String, LdrModule> {
        let mut map: HashMap<String, LdrModule> = HashMap::new();
        let dirbase = info.eprocess.Pcb.DirectoryTableBase;
        let mut idx = 0usize;
        for module in self.get_process_modules(info).drain(0..) {
            let name = module
                .BaseDllName
                .resolve(&self, Some(dirbase), Some(255))
                .unwrap_or(format!("unknown@{}", idx));
            map.insert(name, module);
            idx += 1;
        }
        map
    }

    pub fn get_process_modules(&self, info: &ProcKernelInfo) -> Vec<LdrModule> {
        let peb = self.get_full_peb(info.eprocess.Pcb.DirectoryTableBase, info.eprocessPhysAddr);
        let loader = peb.read_loader_with_dirbase(&self, info.eprocess.Pcb.DirectoryTableBase);
        let first_link = loader.InLoadOrderModuleList.flink;

        let mut modules: Vec<LdrModule> = Vec::new();
        let mut module = loader.get_first_in_load_order_module_list_with_dirbase(
            &self,
            info.eprocess.Pcb.DirectoryTableBase,
        );
        loop {
            if module.is_none() {
                break;
            }
            let m = module.unwrap();
            if m.InLoadOrderModuleList.flink == first_link {
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
            module = m.get_next_in_load_order_module_list_with_dirbase(
                &self,
                Some(info.eprocess.Pcb.DirectoryTableBase),
            );
        }
        return modules;
    }
}
