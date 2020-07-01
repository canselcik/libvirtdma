#![allow(dead_code)]
extern crate memmem;
extern crate pelite;
extern crate regex;
extern crate term_table;
extern crate vmread;
extern crate vmread_sys;

use self::regex::bytes::Regex;
use self::term_table::row::Row;
use crate::vmsession::eprocess::EPROCESS;
use crate::vmsession::ethread::{ETHREAD, KTHREAD_THREAD_LIST_OFFSET};
use crate::vmsession::fullpeb::FullPEB;
use crate::vmsession::heap_entry::ProcessHeapEntry;
use crate::vmsession::proc_kernelinfo::ProcKernelInfo;
use itertools::Itertools;
use memmem::Searcher;
use pelite::image::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS_SIGNATURE,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::mem::size_of;
use std::mem::ManuallyDrop;
use std::str;
use std::sync::{Arc, RwLock};
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};
use vmread::{WinContext, WinDll, WinProcess};
use vmread_sys::{ProcessData, WinCtx, WinModule, PEB};

mod bytesLargeFmt;
pub mod eprocess;
pub mod ethread;
pub mod fullpeb;
mod heap_entry;
mod list_entry;
pub mod peb_bitfield;
mod peb_ldr_data;
pub mod proc_kernelinfo;
mod unicode_string;

pub struct PtrForeign<T> {
    ptr: u64,
    vm: std::sync::Arc<VMSession>,
    proc: Option<WinProcess>,
    typ: PhantomData<*const T>,
}

impl<T> PtrForeign<T> {
    pub fn new(ptr: u64, vm: std::sync::Arc<VMSession>, proc: Option<WinProcess>) -> PtrForeign<T> {
        return PtrForeign {
            ptr,
            vm,
            proc,
            typ: PhantomData,
        };
    }

    pub fn read(&self) -> T {
        match &self.proc {
            Some(proc) => proc.read(&self.vm.native_ctx, self.ptr),
            None => self.vm.ctx.read(self.ptr),
        }
    }
}

pub struct VMSession {
    self_ref: RwLock<Option<Arc<Self>>>,
    pub ctx: WinContext,
    pub native_ctx: WinCtx,
}

fn str_chunks<'a>(s: &'a str, n: usize) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    Box::new(s.as_bytes().chunks(n).map(|c| str::from_utf8(c).unwrap()))
}

impl VMSession {
    unsafe fn escape_hatch(&self) -> &mut Self {
        std::mem::transmute_copy(&self)
    }

    pub fn as_mut(&self) -> &mut Self {
        unsafe { self.escape_hatch() }
    }

    pub fn clone(&self) -> Arc<Self> {
        let arc = self.self_ref.read().unwrap();
        Arc::clone(arc.as_ref().unwrap())
    }

    pub fn map_physmem_as_slice<T>(&self) -> ManuallyDrop<&mut [u8]> {
        let len = self.native_ctx.process.mapsSize as usize;
        let ptr = self.native_ctx.process.mapsStart as *mut u8;
        unsafe { ManuallyDrop::new(std::slice::from_raw_parts_mut(ptr, len)) }
    }

    pub fn map_physmem_as<T>(&self, phys_addr: u64) -> Option<ManuallyDrop<Box<T>>> {
        let start = self.native_ctx.process.mapsStart;
        let bufsize: usize = self.native_ctx.process.mapsSize as usize;
        let sz = size_of::<T>();
        if phys_addr + sz as u64 > start + bufsize as u64 {
            return None;
        }
        unsafe {
            let ptr: *mut T = std::mem::transmute(start + phys_addr);
            Some(ManuallyDrop::new(std::boxed::Box::from_raw(ptr)))
        }
    }

    pub fn new() -> Result<Arc<VMSession>, String> {
        let ctx_ret = vmread::create_context(0);
        if ctx_ret.is_err() {
            let (eval, estr) = ctx_ret.err().unwrap();
            Err(format!("Initialization error {}: {}", eval, estr))
        } else {
            match ctx_ret {
                Ok((ctx, native_ctx)) => {
                    let arc = Arc::new(VMSession {
                        ctx,
                        native_ctx,
                        self_ref: RwLock::new(None),
                    });
                    *arc.self_ref.write().unwrap() = Some(Arc::clone(&arc));
                    Ok(arc)
                }
                Err((eval, estr)) => Err(format!("Initialization error {}: {}", eval, estr)),
            }
        }
    }

    pub fn list_kmods(&mut self, refresh: bool) {
        if refresh {
            self.ctx.refresh_kmods();
        }

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

        let mut add_entry = |name, dirbase, phys| {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(name, 1, Alignment::Left),
                TableCell::new_with_alignment(format!("0x{:x}", dirbase), 1, Alignment::Right),
                TableCell::new_with_alignment(format!("0x{:x}", phys), 1, Alignment::Right),
            ]));
        };

        for kmod in self.ctx.kmod_list.iter() {
            let info: &vmread_sys::WinModule = &kmod.info;
            add_entry(&kmod.name, info.baseAddress, info.sizeOfModule);
        }
        println!("{}", table.render());
    }

    pub fn find_kmod(&mut self, name: &str, case_sensitive: bool, refresh: bool) -> Option<WinDll> {
        if refresh {
            self.ctx.refresh_kmods();
        }
        for kmod in self.ctx.kmod_list.iter() {
            let matched = match case_sensitive {
                true => name.eq(&kmod.name),
                false => name.eq_ignore_ascii_case(&kmod.name),
            };
            if matched {
                return Some(kmod.clone());
            }
        }
        return None;
    }

    pub fn find_process(
        &mut self,
        name: &str,
        case_sensitive: bool,
        require_alive: bool,
        refresh: bool,
    ) -> Option<WinProcess> {
        if refresh {
            self.ctx.refresh_processes();
        }
        let mut proc_list = self.ctx.process_list.clone();
        for proc in proc_list.iter_mut() {
            if require_alive && !proc.is_valid_pe(self.native_ctx) {
                continue;
            }

            let matched = match case_sensitive {
                true => name.eq(&proc.name),
                false => name.eq_ignore_ascii_case(&proc.name),
            };
            if matched {
                return Some(proc.clone().into());
            }
        }
        return None;
    }

    pub fn list_process(&mut self, require_alive: bool, refresh: bool) {
        if refresh {
            self.ctx.refresh_processes();
        }

        let mut table = Table::new();
        table.max_column_width = 45;
        table.style = TableStyle::thin();

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "Processes",
            3,
            Alignment::Center,
        )]));

        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("PID", 1, Alignment::Left),
            TableCell::new_with_alignment("Name", 1, Alignment::Center),
            TableCell::new_with_alignment("Dirbase", 1, Alignment::Center),
            TableCell::new_with_alignment("Physical Addr", 1, Alignment::Center),
        ]));

        let mut add_entry = |pid, name, dirbase, phys| {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(format!("{}", pid), 1, Alignment::Left),
                TableCell::new_with_alignment(name, 1, Alignment::Left),
                TableCell::new_with_alignment(format!("0x{:x}", dirbase), 1, Alignment::Right),
                TableCell::new_with_alignment(format!("0x{:x}", phys), 1, Alignment::Right),
            ]));
        };
        for proc in self.ctx.process_list.iter() {
            if require_alive && !proc.is_valid_pe(self.native_ctx) {
                continue;
            }
            let info: &vmread_sys::WinProc = &proc.proc;
            add_entry(&proc.proc.pid, &proc.name, info.dirBase, info.physProcess);
        }
        println!("{}", table.render());
    }

    pub fn dump_process_vmem(
        &self,
        proc: &mut WinProcess,
        mod_info: &WinModule,
    ) -> Result<Vec<u8>, i64> {
        self.dump_module_vmem(proc.proc.dirBase, mod_info)
    }

    pub fn dump_kmod_vmem(&self, mod_info: &WinModule) -> Result<Vec<u8>, i64> {
        self.dump_module_vmem(self.native_ctx.initialProcess.dirBase, mod_info)
    }

    pub fn dump_module_vmem(&self, dirbase: u64, mod_info: &WinModule) -> Result<Vec<u8>, i64> {
        let begin = mod_info.baseAddress;
        let end = begin + mod_info.sizeOfModule;
        match self.getvmem(Some(dirbase), begin, end) {
            None => Err(-1),
            Some(res) => Ok(res.into_vec()),
        }
    }

    pub fn translate(&self, dirbase: u64, addr: u64) -> u64 {
        unsafe {
            vmread_sys::VTranslate(
                &self.native_ctx.process as *const ProcessData,
                dirbase,
                addr,
            )
        }
    }

    pub fn read_cstring_from_physical_mem(&self, addr: u64, maxlen: Option<u64>) -> String {
        let mut out: Vec<u8> = Vec::new();
        let mut len = 0;
        loop {
            let val: u8 = self.read_physical(addr + len);
            if val == 0 {
                break;
            }
            out.push(val);
            len += 1;
            if let Some(max) = maxlen {
                if len >= max {
                    break;
                }
            }
        }
        std::string::String::from_iter(out.iter().map(|b| *b as char))
    }

    pub fn get_eprocess_entries(&self, pid_filter: Option<u64>) -> HashMap<u64, ProcKernelInfo> {
        let mut m: HashMap<u64, ProcKernelInfo> = HashMap::new();
        let mut curProc = self.native_ctx.initialProcess.physProcess;
        let mut virtProcess = self.native_ctx.initialProcess.process;
        loop {
            let eprocess: EPROCESS = self.read_physical(curProc);
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
                if pid_filter.is_none() || pid_filter.unwrap() == eprocess.UniqueProcessId {
                    let peb = self.get_full_peb(curProc);
                    let ldr = peb.read_loader_using_dirbase(&self, dirbase);
                    let base_module_name =
                        match ldr.getFirstInMemoryOrderModuleListWithDirbase(&self, dirbase) {
                            None => eprocess.ImageFileName.iter().map(|b| *b as char).join(""),
                            Some(m) => m
                                .BaseDllName
                                .resolve_with_dirbase(&self, dirbase, Some(512))
                                .unwrap_or("unknown".to_string()),
                        };
                    m.insert(
                        eprocess.UniqueProcessId,
                        ProcKernelInfo::new(&base_module_name, eprocess, virtProcess, curProc),
                    );
                }
            }

            let vp: u64 = self.read_physical(curProc + self.native_ctx.offsets.apl as u64);
            virtProcess = vp - self.native_ctx.offsets.apl as u64;
            if virtProcess == 0 {
                println!("Returning early from walking EPROCESS list due to VIRTPROC == 0");
                break;
            }
            curProc = self.translate(self.native_ctx.initialProcess.dirBase, virtProcess);
            if curProc == 0 {
                println!("Returning early from walking EPROCESS list due to CURPROC == 0");
                break;
            }
            if curProc == self.native_ctx.initialProcess.physProcess
                || virtProcess == self.native_ctx.initialProcess.process
            {
                println!("Completed walking kernel EPROCESS list");
                break;
            }
        }
        return m;
    }

    pub fn walk_eprocess(&self) {
        for (pid, info) in self.get_eprocess_entries(None).iter() {
            println!(
                "EPROCESS[pid={}, name={}, virtual=0x{:x}, phys=0x{:x}, activeThreads={}]",
                pid,
                info.name,
                info.eprocessVirtAddr,
                info.eprocessPhysAddr,
                info.eprocess.ActiveThreads,
            );
        }
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

    pub fn eprocess_for_pid(&self, pid: u64) -> Option<ProcKernelInfo> {
        let procs = self.get_eprocess_entries(Some(pid));
        match procs.get(&pid) {
            Some(r) => Some(r.clone()),
            None => None,
        }
    }

    pub fn list_process_modules(&self, proc: &mut WinProcess, refresh: bool) {
        if refresh {
            proc.refresh_modules(self.native_ctx);
        }
        let mut table = Table::new();
        table.max_column_width = 45;
        table.style = TableStyle::thin();

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            format!("Modules of {}", proc.name),
            3,
            Alignment::Center,
        )]));

        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Name", 1, Alignment::Center),
            TableCell::new_with_alignment("Start", 1, Alignment::Center),
            TableCell::new_with_alignment("End", 1, Alignment::Center),
        ]));

        let mut add_entry = |name, dirbase, phys| {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(name, 1, Alignment::Left),
                TableCell::new_with_alignment(format!("0x{:x}", dirbase), 1, Alignment::Right),
                TableCell::new_with_alignment(format!("0x{:x}", phys), 1, Alignment::Right),
            ]));
        };

        for m in proc.module_list.iter() {
            let begin = m.info.baseAddress;
            let end = begin + m.info.sizeOfModule;
            add_entry(&m.name, begin, end);
        }
        println!("{}", table.render());
    }

    pub fn get_peb(&self, proc: &WinProcess) -> PEB {
        proc.get_peb(self.native_ctx)
    }

    pub fn get_full_peb(&self, physProcess: u64) -> FullPEB {
        let ptr: u64 = self
            .ctx
            .read(physProcess + self.native_ctx.offsets.peb as u64);
        // let pPEB: PtrForeign<FullPEB> = PtrForeign::new(ptr, self.clone(), Some(proc.clone()));
        // let peb: FullPEB = pPEB.read();
        self.read_physical(ptr)
    }

    pub fn get_full_peb_for_process(&self, proc: &WinProcess) -> FullPEB {
        self.get_full_peb(proc.proc.physProcess)
    }

    pub fn get_process_heaps(&self, proc: &WinProcess) {
        let peb = self.get_full_peb_for_process(proc);
        for heap_index in 0..peb.NumberOfHeaps {
            let offset = heap_index as usize * size_of::<ProcessHeapEntry>();
            let heap: ProcessHeapEntry =
                proc.read(&self.native_ctx, peb.ProcessHeaps + offset as u64);
            println!(
                "{}",
                heap.as_table(Some(format!("Heap Entry {}", heap_index)))
            );
        }
    }

    pub fn pinspect(&self, proc: &mut WinProcess, refresh: bool) {
        let (match_str, mismatch_str) = ("match".to_string(), "MISMATCH".to_string());
        if refresh {
            proc.refresh_modules(self.native_ctx);
        }

        let base = match proc.module_list.iter().find(|m| m.name == proc.name) {
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

        let dos_header: IMAGE_DOS_HEADER = proc.read(&self.native_ctx, base.info.baseAddress);

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

        let nt_header_addr = base.info.baseAddress + dos_header.e_lfanew as u64;
        let new_exec_header: IMAGE_NT_HEADERS64 = proc.read(&self.native_ctx, nt_header_addr);
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
            let section_header: pelite::image::IMAGE_SECTION_HEADER = proc.read(
                &self.native_ctx,
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

    pub fn read_physical<T>(&self, address: u64) -> T {
        self.ctx.read(address)
    }

    fn _getvmem(&self, dirbase: Option<u64>, local_begin: u64, begin: u64, end: u64) -> i64 {
        let len = end - begin;
        if len <= 8 {
            let data = match dirbase {
                Some(d) => unsafe { vmread_sys::VMemReadU64(&self.native_ctx.process, d, begin) },
                None => unsafe { vmread_sys::MemReadU64(&self.native_ctx.process, begin) },
            };
            let bit64: [u8; 8] = data.to_le_bytes();
            let slice =
                unsafe { std::slice::from_raw_parts_mut(local_begin as *mut u8, len as usize) };
            for i in 0..len {
                slice[i as usize] = bit64[i as usize];
            }
            return len as i64;
        }
        if len <= 0 {
            return -2;
        }
        let mut res: i64 = match dirbase {
            Some(d) => unsafe {
                vmread_sys::VMemRead(&self.native_ctx.process, d, local_begin, begin, len)
            },
            None => unsafe {
                vmread_sys::MemRead(&self.native_ctx.process, local_begin, begin, len)
            },
        };
        if res < 0 {
            let chunksize = len / 2;
            res = self._getvmem(dirbase, local_begin, begin, begin + chunksize);
            if res < 0 {
                return res;
            }
            res = self._getvmem(dirbase, local_begin + chunksize, begin + chunksize, end);
        }
        return res;
    }

    pub fn getvmem(&self, dirbase: Option<u64>, begin: u64, end: u64) -> Option<Box<[u8]>> {
        let len = end - begin;
        let buffer: Box<[std::mem::MaybeUninit<u8>]> = Box::new_uninit_slice(len as usize);
        let buffer_begin = buffer.as_ptr() as u64;
        if self._getvmem(dirbase, buffer_begin, begin, end) > 0 {
            return Some(unsafe { buffer.assume_init() });
        }
        return None;
    }

    pub fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        memmem::TwoWaySearcher::new(needle).search_in(haystack)
    }

    pub fn find_module_from_addr(&self, modules: &[WinDll], addr: u64) -> Option<WinDll> {
        for m in modules.iter() {
            let begin = m.info.baseAddress;
            let end = begin + m.info.sizeOfModule;
            if addr >= begin && addr <= end {
                return Some(m.clone());
            }
        }
        return None;
    }

    pub fn pmemmem(haystack: &[u8], needle_string: &str) -> Result<Vec<usize>, String> {
        let mut restr = String::from("(?-u:");
        for ch in str_chunks(&needle_string, 2) {
            let chunk: Vec<char> = ch.chars().collect();
            if chunk.len() != 2 {
                return Err("input needle_string without even length".to_string());
            }
            let (first, second) = (*chunk.get(0).unwrap(), *chunk.get(1).unwrap());
            let qmPresent = first == '?' || second == '?';
            let wildcard = first == '?' && second == '?';
            if qmPresent && !wildcard {
                return Err("needle_string has wildcards of uneven length".to_string());
            }
            if wildcard {
                restr += ".";
            } else {
                restr += "\\x";
                restr += ch;
            }
        }
        restr += ")";

        let re: Regex = match Regex::new(&restr) {
            Ok(r) => r,
            Err(e) => return Err(e.to_string()),
        };
        Ok(re.find_iter(haystack).map(|f| f.start()).collect())
    }

    pub fn memmemn(haystack: &[u8], needle: &[u8], max_opt: Option<usize>) -> Vec<usize> {
        match VMSession::memmem(haystack, needle) {
            None => vec![],
            Some(offset) => {
                let res = vec![offset];
                match max_opt {
                    Some(1) => res,
                    other => {
                        let updatedn = match other {
                            Some(x) => Some(x - 1),
                            None => None,
                        };
                        let needle_end = offset + needle.len();
                        let mut downstream_results =
                            VMSession::memmemn(&haystack[needle_end..], needle, updatedn);
                        for res in downstream_results.iter_mut() {
                            *res += needle_end;
                        }
                        let mut res = vec![offset];
                        res.append(&mut downstream_results);
                        res
                    }
                }
            }
        }
    }

    pub fn write_all_modules_to_fs(
        &self,
        proc: &mut WinProcess,
        path_prefix: Option<&str>,
        refresh: bool,
    ) -> Result<(), String> {
        if refresh {
            proc.refresh_modules(self.native_ctx.clone());
        }
        if let Some(dir) = path_prefix {
            std::fs::create_dir_all(dir).unwrap();
        }
        let module_list = proc.module_list.clone();
        for module in module_list.iter() {
            let info: &vmread_sys::WinModule = &module.info;
            match self.dump_process_vmem(proc, info) {
                Ok(data) => {
                    match std::fs::write(
                        format!(
                            "{}/{}",
                            match path_prefix {
                                Some(s) => s,
                                None => ".",
                            },
                            module.name,
                        ),
                        &data,
                    ) {
                        Ok(_) => println!("Dumped {}", module.name),
                        Err(_) => println!("Failed to write while dumping {}", module.name),
                    }
                }
                Err(code) => {
                    return Err(format!(
                        "Dump of {} failed with code: {}",
                        module.name, code,
                    ))
                }
            }
        }
        Ok(())
    }
}

#[test]
pub fn test_pmemmem() {
    let re: Regex = Regex::new(
    r"(?-u:\x48\x89\x05....\x48\x83\xc4\x38\xc3\x48\xc7\x05........\x48\x83\xc4\x38\xc3\xcc\xcc\xcc\xcc\xcc\x48)"
    ).unwrap();
    let md1: Vec<u8> = vec![
        0x48, 0x89, 0x05, 0xAA, 0xAB, 0xAC, 0xAD, 0x48, 0x83, 0xc4, 0x38, 0xc3, 0x48, 0xc7, 0x05,
        0xAA, 0xAB, 0xAC, 0xAD, 0xAA, 0xAB, 0xAC, 0xAD, 0x48, 0x83, 0xc4, 0x38, 0xc3, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, 0x48,
    ];
    let mut m = false;
    for matched in re.find_iter(&md1) {
        m = true;
        println!("MATCHED: {:?}", matched);
    }
    assert!(m);
}
