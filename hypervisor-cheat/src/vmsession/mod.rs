extern crate memmem;
extern crate vmread;
extern crate vmread_sys;
use memmem::Searcher;

use vmread::{WinContext, WinDll, WinProcess};
use vmread_sys::{WinCtx, WinModule};

pub struct VMSession {
    pub ctx: WinContext,
    pub native_ctx: WinCtx,
}

impl VMSession {
    pub fn new() -> Result<VMSession, String> {
        let ctx_ret = vmread::create_context(0);
        if ctx_ret.is_err() {
            let (eval, estr) = ctx_ret.err().unwrap();
            Err(format!("Initialization error {}: {}", eval, estr))
        } else {
            match ctx_ret {
                Ok((mut ctx, native_ctx)) => Ok(VMSession { ctx, native_ctx }),
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
