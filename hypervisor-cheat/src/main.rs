#![feature(new_uninit)]
extern crate hexdump;
extern crate vmread;
extern crate vmread_sys;

use vmread::WinContext;
use vmread_sys::WinCtx;

fn main() {
    let ctx_ret = vmread::create_context(0);
    if ctx_ret.is_err() {
        let (eval, estr) = ctx_ret.err().unwrap();
        println!("Initialization error {}: {}", eval, estr);
        return;
    }

    let (mut ctx, native_ctx): (WinContext, WinCtx) = ctx_ret.unwrap();

    ctx.refresh_processes();
    for proc in ctx.process_list.iter_mut() {
        if !proc.is_valid_pe(native_ctx) {
            continue;
        }
        if "ModernWarfare.exe".eq(&proc.name) {
            println!("Found ModernWarfare.exe");
            proc.refresh_modules(native_ctx);
            for proc_mod in proc.module_list.iter() {
                let mod_info: &vmread_sys::WinModule = &proc_mod.info;
                if proc_mod.name.eq(&proc.name) {
                    println!(
                        "Found mw.exe module in mw.exe process with len of {} bytes",
                        mod_info.sizeOfModule,
                    );
                    let ret = Box::new_uninit_slice(mod_info.sizeOfModule as usize);
                    let read = unsafe {
                        vmread_sys::VMemRead(
                            &native_ctx.process,
                            proc.proc.dirBase,
                            ret.as_ptr() as u64,
                            mod_info.baseAddress,
                            mod_info.sizeOfModule,
                        )
                    };
                    println!("Read {} bytes from mw.exe module in mw.exe", read);
                    if read > 0 {
                        let data: Box<[u8]> = unsafe { ret.assume_init() };
                        hexdump::hexdump(&data);
                    }
                }
            }
        }
    }

    ctx.refresh_kmods();
    for kmod in ctx.kmod_list.iter() {
        // println!("KMOD: {}", kmod.name);
        if "SleepStudyHelper.sys".eq(&kmod.name) {
            let _module: &vmread_sys::WinModule = &kmod.info;
            // let ret = Box::new_uninit_slice(module.sizeOfModule as usize);

            // let read = unsafe {
            //     vmread_sys::VMemRead(
            //         &native_ctx.process,
            //         native_ctx.initialProcess.dirBase,
            //         ret.as_ptr() as u64,
            //         module.baseAddress,
            //         module.sizeOfModule,
            //     )
            // };
            // println!("Read {} bytes from SleepStudyHelper.sys", read);
            // if read > 0 {
            //     let data: Box<[u8]> = unsafe { ret.assume_init() };
            //     hexdump::hexdump(&data);
            // }
        }
    }
}
