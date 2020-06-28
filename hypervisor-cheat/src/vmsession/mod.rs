#![allow(dead_code)]
extern crate memmem;
extern crate pelite;
extern crate regex;
extern crate vmread;
extern crate vmread_sys;

use self::regex::bytes::Regex;
use memmem::Searcher;
use vmread::{WinContext, WinDll, WinProcess};
use vmread_sys::{WinCtx, WinModule};

pub struct VMSession {
    pub ctx: WinContext,
    pub native_ctx: WinCtx,
}

use std::mem::ManuallyDrop;
use std::str;

fn str_chunks<'a>(s: &'a str, n: usize) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    Box::new(s.as_bytes().chunks(n).map(|c| str::from_utf8(c).unwrap()))
}

impl VMSession {
    pub fn mmap_physmem_as<T>(&self, phys_addr: u64) -> Option<ManuallyDrop<Box<T>>> {
        let start = self.native_ctx.process.mapsStart;
        let bufsize: usize = self.native_ctx.process.mapsSize as usize;
        let sz = std::mem::size_of::<T>();
        if phys_addr + sz as u64 > start + bufsize as u64 {
            return None;
        }
        unsafe {
            let ptr: *mut T = std::mem::transmute(start + phys_addr);
            Some(ManuallyDrop::new(std::boxed::Box::from_raw(ptr)))
        }
    }

    pub fn new() -> Result<VMSession, String> {
        let ctx_ret = vmread::create_context(0);
        if ctx_ret.is_err() {
            let (eval, estr) = ctx_ret.err().unwrap();
            Err(format!("Initialization error {}: {}", eval, estr))
        } else {
            match ctx_ret {
                Ok((ctx, native_ctx)) => Ok(VMSession { ctx, native_ctx }),
                Err((eval, estr)) => Err(format!("Initialization error {}: {}", eval, estr)),
            }
        }
    }

    pub fn list_kmods(&mut self, refresh: bool) {
        if refresh {
            self.ctx.refresh_kmods();
        }
        println!("======= KERNEL MODULES =======");
        for kmod in self.ctx.kmod_list.iter() {
            let info: &vmread_sys::WinModule = &kmod.info;
            println!("{}\t{}\t{}", kmod.name, info.baseAddress, info.sizeOfModule);
        }
        println!("==== END OF KERNEL MODULES ====")
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
        println!("======= USER PROCESSES =======");
        for proc in self.ctx.process_list.iter() {
            if require_alive && !proc.is_valid_pe(self.native_ctx) {
                continue;
            }
            let info: &vmread_sys::WinProc = &proc.proc;
            println!("{}\t{}\t{}", proc.name, info.dirBase, info.physProcess)
        }
        println!("==== END OF USER PROCESSES ====")
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
        match self.getvmem(dirbase, begin, end) {
            None => Err(-1),
            Some(res) => Ok(res.into_vec()),
        }
    }

    pub fn get_process_sections(&self, proc: &mut WinProcess, refresh: bool) {
        if refresh {
            proc.refresh_modules(self.native_ctx);
        }
        match proc.module_list.iter().find(|m| m.name == proc.name) {
            None => return,
            Some(base) => {
                let dos_header: pelite::image::IMAGE_DOS_HEADER =
                    proc.read(&self.native_ctx, base.info.baseAddress);
                assert_eq!(dos_header.e_magic, pelite::image::IMAGE_DOS_SIGNATURE);

                let nt_header_addr = base.info.baseAddress + dos_header.e_lfanew as u64;
                let new_exec_header: pelite::image::IMAGE_NT_HEADERS64 =
                    proc.read(&self.native_ctx, nt_header_addr);
                assert_eq!(
                    new_exec_header.Signature,
                    pelite::image::IMAGE_NT_HEADERS_SIGNATURE
                );

                let section_hdr_addr = nt_header_addr
                    + std::mem::size_of::<pelite::image::IMAGE_NT_HEADERS64>() as u64;
                for section_idx in 0..new_exec_header.FileHeader.NumberOfSections {
                    let section_header: pelite::image::IMAGE_SECTION_HEADER = proc.read(
                        &self.native_ctx,
                        section_hdr_addr
                            + (section_idx as u64
                                * std::mem::size_of::<pelite::image::IMAGE_NT_HEADERS64>() as u64),
                    );

                    println!(
                        "section_header: {} {:#?}",
                        section_header.Name, section_header
                    );
                    // let section_size = next_section.VirtualAddress - data_header.VirtualAddress;
                    // println!("section_size: 0x{:x}", section_header.VirtualSize);
                }
            }
        }
    }

    fn _getvmem(&self, dirbase: u64, local_begin: u64, begin: u64, end: u64) -> i64 {
        let len = end - begin;
        if len <= 8 {
            let data = unsafe { vmread_sys::VMemReadU64(&self.native_ctx.process, dirbase, begin) };
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
        let mut res: i64 = unsafe {
            vmread_sys::VMemRead(&self.native_ctx.process, dirbase, local_begin, begin, len)
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

    pub fn getvmem(&self, dirbase: u64, begin: u64, end: u64) -> Option<Box<[u8]>> {
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
