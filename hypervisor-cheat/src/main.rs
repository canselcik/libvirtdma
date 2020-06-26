#![feature(new_uninit)]
extern crate bsdiff;
extern crate hex;
extern crate hexdump;

extern crate sha2;
extern crate vmread;
extern crate vmread_sys;

mod vmsession;

use crate::vmsession::VMSession;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::mem::ManuallyDrop;
use std::time::Instant;
use vmread::{WinContext, WinDll, WinProcess};
use vmread_sys::{WinCtx, WinModule};

macro_rules! max {
    ($x:expr) => ( $x );
    ($x:expr, $($xs:expr),+) => {
        {
            use std::cmp::max;
            max($x, max!( $($xs),+ ))
        }
    };
}
macro_rules! min {
    ($x:expr) => ( $x );
    ($x:expr, $($xs:expr),+) => {
        {
            use std::cmp::min;
            min($x, min!( $($xs),+ ))
        }
    };
}

fn main() {
    let mut vm = vmsession::VMSession::new().expect("Failed to initialize");

    match vm.find_kmod("EasyAntiCheat.sys", false, false) {
        Some(eac) => {
            let mem = vm
                .dump_kmod_vmem(&eac.info)
                .expect("Unable to read EAC kmod memory");
            std::fs::write(eac.name, &mem).expect("Unable to write file");
        }
        None => {}
    };

    let bufsize: usize = vm.native_ctx.process.mapsSize as usize;
    let mut whole: ManuallyDrop<Box<[u8]>> = ManuallyDrop::new(unsafe {
        let ptr: *mut [u8] = std::mem::transmute_copy(&vm.native_ctx.process.mapsStart);
        std::boxed::Box::from_raw(ptr)
    });
    let needle = "Spectre".as_bytes();
    let mut last_match_offset: usize = 0;
    let context_len = 50;
    let mut now = Instant::now();
    loop {
        if let Some(sample_offset) = VMSession::memmem(&whole[last_match_offset..], needle) {
            let rate =
                sample_offset as f64 / (now.elapsed().as_millis() as f64 / 1000f64) / 100000f64;
            now = Instant::now();

            let match_offset = last_match_offset + sample_offset;
            let from = max!(0, match_offset - context_len);
            let to = min!(bufsize - 1, match_offset + context_len);
            println!("MATCH AT: {:x} ({:.2} MB/sec)", match_offset, rate);
            hexdump::hexdump(&whole[from..to]);
            last_match_offset = match_offset + needle.len();
        } else {
            break;
        }
    }

    match vm.find_process("ModernWarfare.exe", false, true, true) {
        Some(mut mw) => vm
            .write_all_modules_to_fs(&mut mw, Some("../mw.exe/fast/"), true)
            .expect("failed to write"),
        None => println!("Unable to find ModernWarfare.exe"),
    };

    // vm.ctx.refresh_kmods();
    // println!("Reading kmods...");
    // let mut hasher = Sha256::new();
    // for kmod in vm.ctx.kmod_list.iter() {
    //     let res1 = dump_kmod_vmem(&vm.native_ctx, &kmod.info, false).expect("failed fast dump");
    //     let res2 = dump_kmod_vmem(&vm.native_ctx, &kmod.info, true).expect("failed slow dump");
    //
    //     hasher.update(&res1);
    //     let hash1 = hex::encode(hasher.finalize_reset());
    //
    //     hasher.update(&res2);
    //     let hash2 = hex::encode(hasher.finalize_reset());
    //
    //     if hash1 != hash2 {
    //         println!(
    //             "DIFF {} (lenMismatch: {})",
    //             kmod.name,
    //             res1.len() - res2.len(),
    //         );
    //     }
    // }
}
