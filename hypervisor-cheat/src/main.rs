#![feature(new_uninit)]
extern crate hexdump;
extern crate memmem;
extern crate vmread;
extern crate vmread_sys;

use memmem::Searcher;

use vmread::{WinContext, WinDll, WinProcess};
use vmread_sys::{WinCtx, WinModule};

fn list_kmod(ctx: &mut WinContext, refresh: bool) {
    if refresh {
        ctx.refresh_kmods();
    }
    println!("======= KERNEL MODULES =======");
    for kmod in ctx.kmod_list.iter() {
        let info: &vmread_sys::WinModule = &kmod.info;
        println!("{}\t{}\t{}", kmod.name, info.baseAddress, info.sizeOfModule);
    }
    println!("==== END OF KERNEL MODULES ====")
}

fn find_kmod(
    ctx: &mut WinContext,
    name: &str,
    case_sensitive: bool,
    refresh: bool,
) -> Option<WinDll> {
    if refresh {
        ctx.refresh_kmods();
    }
    for kmod in ctx.kmod_list.iter() {
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

fn find_process(
    ctx: &mut WinContext,
    native_ctx: WinCtx,
    name: &str,
    case_sensitive: bool,
    require_alive: bool,
    refresh: bool,
) -> Option<WinProcess> {
    if refresh {
        ctx.refresh_processes();
    }
    let mut proc_list = ctx.process_list.clone();
    for proc in proc_list.iter_mut() {
        if require_alive && !proc.is_valid_pe(native_ctx) {
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

fn list_process(ctx: &mut WinContext, native_ctx: WinCtx, require_alive: bool, refresh: bool) {
    if refresh {
        ctx.refresh_processes();
    }
    println!("======= USER PROCESSES =======");
    for proc in ctx.process_list.iter() {
        if require_alive && !proc.is_valid_pe(native_ctx) {
            continue;
        }
        let info: &vmread_sys::WinProc = &proc.proc;
        println!("{}\t{}\t{}", proc.name, info.dirBase, info.physProcess)
    }
    println!("==== END OF USER PROCESSES ====")
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memmem::TwoWaySearcher::new(needle).search_in(haystack)
}

fn dump_process_vmem(
    native_ctx: &WinCtx,
    proc: &mut WinProcess,
    mod_info: &WinModule,
) -> Result<Vec<u8>, i64> {
    return dump_module_vmem(native_ctx, proc.proc.dirBase, mod_info);
}

fn dump_kmod_vmem(native_ctx: &WinCtx, mod_info: &WinModule) -> Result<Vec<u8>, i64> {
    dump_module_vmem(native_ctx, native_ctx.initialProcess.dirBase, mod_info)
}

fn dump_module_vmem(
    native_ctx: &WinCtx,
    dirbase: u64,
    mod_info: &WinModule,
) -> Result<Vec<u8>, i64> {
    let begin = mod_info.baseAddress;
    let end = begin + mod_info.sizeOfModule;
    match getmem(native_ctx, dirbase, begin, end) {
        None => Err(-1),
        Some(res) => Ok(res.into_vec()),
    }
}

fn _getmem(native_ctx: &WinCtx, dirbase: u64, local_begin: u64, begin: u64, end: u64) -> i64 {
    let len = end - begin;
    if len < 8 {
        let data = unsafe { vmread_sys::VMemReadU64(&native_ctx.process, dirbase, begin) };
        let bit64: [u8; 8] = data.to_le_bytes();
        let slice = unsafe { std::slice::from_raw_parts_mut(local_begin as *mut u8, len as usize) };
        for i in 0..len {
            slice[i as usize] = bit64[i as usize];
        }
        return len as i64;
    }
    if len <= 0 {
        return -2;
    }
    let mut res: i64 =
        unsafe { vmread_sys::VMemRead(&native_ctx.process, dirbase, local_begin, begin, len) };
    if res < 0 {
        let chunksize = len / 2;
        res = _getmem(native_ctx, dirbase, local_begin, begin, begin + chunksize);
        if res < 0 {
            return res;
        }
        res = _getmem(
            native_ctx,
            dirbase,
            local_begin + chunksize,
            begin + chunksize,
            end,
        )
    }
    return res;
}

fn getmem(native_ctx: &WinCtx, dirbase: u64, begin: u64, end: u64) -> Option<Box<[u8]>> {
    let len = end - begin;
    let buffer: Box<[std::mem::MaybeUninit<u8>]> = Box::new_uninit_slice(len as usize);
    let buffer_begin = buffer.as_ptr() as u64;
    if _getmem(native_ctx, dirbase, buffer_begin, begin, end) > 0 {
        return Some(unsafe { buffer.assume_init() });
    }
    return None;
}

fn write_all_modules_to_fs(
    native_ctx: &WinCtx,
    proc: &mut WinProcess,
    path_prefix: Option<&str>,
    refresh: bool,
) -> Result<(), String> {
    if refresh {
        proc.refresh_modules(native_ctx.clone());
    }
    if let Some(dir) = path_prefix {
        std::fs::create_dir_all(dir).unwrap();
    }
    // native_ctx.process.mapsSize
    let module_list = proc.module_list.clone();
    for module in module_list.iter() {
        let info: &vmread_sys::WinModule = &module.info;
        match dump_process_vmem(&native_ctx, proc, info) {
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

fn main() {
    let ctx_ret = vmread::create_context(0);
    if ctx_ret.is_err() {
        let (eval, estr) = ctx_ret.err().unwrap();
        println!("Initialization error {}: {}", eval, estr);
        return;
    }

    let (mut ctx, native_ctx): (WinContext, WinCtx) = ctx_ret.unwrap();

    // let mut eac =
    //     find_kmod(&mut ctx, "EasyAntiCheat.sys", false, true).expect("Unable to find EAC kmod");
    // let mem = dump_kmod_vmem(&native_ctx, &eac.info, None).expect("Unable to read EAC kmod mem");
    // std::fs::write(eac.name, &mem).expect("Unable to write file");

    match find_process(&mut ctx, native_ctx, "ModernWarfare.exe", false, true, true) {
        Some(mut mw) => {
            match write_all_modules_to_fs(&native_ctx, &mut mw, Some("../steam.exe/"), true) {
                Ok(_) => println!("DUMPED OK"),
                Err(e) => println!("FAILED TO DUMP: {}", e),
            }
        }
        None => println!("Unable to find ModernWarfare.exe"),
    }

    ctx.refresh_kmods();
    for kmod in ctx.kmod_list.iter() {
        let res = dump_kmod_vmem(&native_ctx, &kmod.info);
        match res {
            Ok(data) => std::fs::write(format!("../kernel/{}", kmod.name), &data).unwrap(),
            Err(e) => println!("Failed to dump {}: {}", kmod.name, e),
        }
    }
}
