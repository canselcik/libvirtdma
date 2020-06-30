#![feature(new_uninit)]
#![allow(unused_macros, non_snake_case)]
extern crate bsdiff;
extern crate byteorder;
extern crate hex;
extern crate hexdump;
extern crate linefeed;
extern crate shlex;

use linefeed::{Interface, ReadResult};

extern crate vmread;
extern crate vmread_sys;

use crate::rust_external::*;
use crate::vmsession::VMSession;
use byteorder::ByteOrder;
use vmread::{WinDll, WinProcess};

mod rust_external;
mod vmsession;

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

fn parse_u64(s: &str, le: bool) -> Option<u64> {
    match s.strip_prefix("0x") {
        None => match s.parse::<u64>() {
            Ok(r) => Some(r),
            Err(_) => None,
        },
        Some(h) => match hex::decode(format!("{}{}", "0".repeat(16 - h.len()), h)) {
            Ok(r) => Some(if le {
                byteorder::LittleEndian::read_u64(&r)
            } else {
                byteorder::BigEndian::read_u64(&r)
            }),
            Err(_) => None,
        },
    }
}

#[test]
fn test_parse_u64() {
    // LE flag is invariant over decimal input
    assert_eq!(parse_u64("123", false), Some(123));
    assert_eq!(parse_u64("123", true), Some(123));

    // Prefix works as expected in BE mode
    assert_eq!(parse_u64("0x4A", false), Some(74));

    assert_eq!(
        parse_u64("0xCAFEBABEDEADBEEF", false),
        Some(14627333968688430831)
    );
    assert_eq!(
        parse_u64("0x0000000004a3f6e1", false),
        parse_u64("0x4a3f6e1", false),
    );
    assert_eq!(parse_u64("0x0000000004a3f6e1", false), Some(77854433));
}

fn kmod_to_file(vm: &mut VMSession, cmd: &[String]) {
    if cmd.len() != 2 {
        println!("Usage: kmod_to_file EasyAntiCheat.sys");
        return;
    }
    match vm.find_kmod(&cmd[1], false, false) {
        Some(eac) => match vm.dump_kmod_vmem(&eac.info) {
            Err(e) => println!("Unable to read kernel module memory: {}", e),
            Ok(mem) => match std::fs::write(eac.name.clone(), &mem) {
                Ok(_) => println!("Module dumped to {}", eac.name),
                Err(e) => println!("Unable to write file: {}", e.to_string()),
            },
        },
        None => {}
    };
}

fn rust_unity_player_module(
    vm: &mut VMSession,
    rust: &mut WinProcess,
    unityPlayerModule: &mut WinDll,
) {
    let all = vm
        .dump_process_vmem(rust, &unityPlayerModule.info)
        .expect("failed to read");

    match VMSession::pmemmem(
        &all,
        "488905????????4883c438c348c705????????????????4883c438c3cccccccccc48",
    ) {
        Ok(res) => {
            if res.len() != 1 {
                println!(
                    "Found {} matches for GameObjectManager instead of 1",
                    res.len()
                );
                return;
            }
            // UInt64 taggedObjects = m.read<UInt64>(GOM + 0x8);
            // UInt64 gameObject = m.read<UInt64>(taggedObjects + 0x10);
            let gomsig_offset: u64 = *res.get(0).unwrap() as u64;
            let gomsig_addr = unityPlayerModule.info.baseAddress + gomsig_offset;
            println!(
                "gomsig found at 0x{:x} (in proc space: 0x{:x})",
                gomsig_offset, gomsig_addr,
            );
            match vm.find_module_from_addr(&rust.module_list, gomsig_addr) {
                Some(m) => println!("gomsig falls into {}", m.name),
                None => println!("gomsig fall into any module"),
            };

            let offsetA: i32 = rust.read(&vm.native_ctx, gomsig_addr + 3);
            let gom_addr_offset =
                gomsig_addr + 7 - unityPlayerModule.info.baseAddress + offsetA as u64;
            let gom_addr = unityPlayerModule.info.baseAddress + gom_addr_offset;

            assert_eq!(unityPlayerModule.info.baseAddress + 0x17a6ad8, gom_addr);

            println!(
                "gomaddr in proc space: 0x{:x} (offset: 0x{:x})",
                gom_addr, gom_addr_offset,
            );
            match vm.find_module_from_addr(&rust.module_list, gom_addr) {
                Some(m) => println!("gom falls into {}", m.name),
                None => println!("gom doesnt fall into any module"),
            };

            let gomdata: [u8; 0x20] = rust.read(&vm.native_ctx.clone(), gom_addr);
            let gom: GameObjectManager = unsafe { std::mem::transmute(gomdata) };

            println!("GOM: {:#?}", gom);
            hexdump::hexdump(&gomdata);

            let lto: LastObjectBase =
                rust.read(&vm.native_ctx.clone(), gom.lastTaggedObject as u64);
            println!("LTO: {:#?}", lto);
        }
        Err(e) => println!("Error while searching GOM: {}", e),
    };
}

fn rust_game_assembly_module(
    vm: &mut VMSession,
    rust: &mut WinProcess,
    gameAssemblyModule: &mut WinDll,
) {
    /* possible patterns:
         BaseNetworkable: 488b05????????488b88????????488b094885c974????33c08bd5
         CanAttack: E8????????488B8F????????0FB6F0
         CreateProjectile: 48895C24??48896C24??48897424??48897C24??41564883EC50803D??????????498BD9498BE8
         SendProjectileAttack: E8????????F20F1083????????F20F1183????????8B83????????8983????????80BB??????????
    */
    let bnaddr = gameAssemblyModule.info.baseAddress + 0x28861B0;

    match vm.find_module_from_addr(&rust.module_list, bnaddr) {
        Some(m) => println!("BN falls into {}", m.name),
        None => println!("BN doesnt into any module"),
    };
    let networkable: [u8; std::mem::size_of::<BaseNetworkable>()] =
        rust.read(&vm.native_ctx.clone(), bnaddr);
    hexdump::hexdump(&networkable);

    let nb: BaseNetworkable = unsafe { std::mem::transmute(networkable) };
    println!("BaseNetworkable: {:#?}", nb);

    let parentData: [u8; std::mem::size_of::<EntityRef>()] = rust.read(
        &vm.native_ctx.clone(),
        nb.parentEntityRef + gameAssemblyModule.info.baseAddress,
    );

    let eref: EntityRef = unsafe { std::mem::transmute(parentData) };
    println!("EREF: {:#?}", eref);
}

fn rust_routine(vm: &mut VMSession) {
    match vm.find_process("RustClient.exe", false, true, true) {
        Some(mut rust) => {
            println!("Found RustClient.exe");
            rust.refresh_modules(vm.native_ctx.clone());
            let mut modules = rust.module_list.clone();
            for module in modules.iter_mut() {
                match module.name.as_ref() {
                    "UnityPlayer.dll" => rust_unity_player_module(vm, &mut rust, module),
                    "GameAssembly.dll" => rust_game_assembly_module(vm, &mut rust, module),
                    _ => {}
                }
            }
        }
        None => println!("Unable to find RustClient.exe"),
    }
}

fn show_usage() {
    println!(
        r#"Available commands:
    rust:                 runs the rust subroutine
    kmod_to_file:         dump kernel module with the name $1 to disk
    list_kmods:           list loaded kernel modules
    memread:              read $2 bytes of physical memory from $1
    pmemread:             read $2 bytes of process memory from process named $1
    list_processes:       list all running processes
    list_process_modules: list all modules of process named $1
    heaps:                list all heaps of process named $1
    peb:                  print the full PEB of process named $1
    pinspect:             inspect process named $1
    quit | exit:          exit the program
    usage:                print this message"#
    );
}

fn dispatch_commands(vm: std::sync::Arc<VMSession>, parts: Vec<String>) {
    match parts[0].as_ref() {
        "rust" => rust_routine(vm.as_mut()),
        "quit" | "exit" => std::process::exit(0),
        "kmod_to_file" => kmod_to_file(vm.as_mut(), &parts),
        "list_kmods" => vm.as_mut().list_kmods(true),
        "memread" => {
            if parts.len() != 3 {
                println!("usage: pmemread <hPA> <hSize>");
            } else {
                let hPA = match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hPA");
                        return;
                    }
                };
                let hSize = match parse_u64(&parts[2], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hSize");
                        return;
                    }
                };
                let mut data = vec![0u8; hSize as usize];
                data = vm.read_physical(hPA);
                hexdump::hexdump(&data);
            }
        }
        "pmemread" => {
            if parts.len() != 4 {
                println!("usage: pmemread explorer.exe <hVA> <hSize>");
            } else {
                let procname = &parts[1];
                let hVA = match parse_u64(&parts[2], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hVA");
                        return;
                    }
                };
                let hSize = match parse_u64(&parts[3], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hSize");
                        return;
                    }
                };
                match vm.as_mut().find_process(procname, false, true, true) {
                    None => println!("Unable to find a process with matching name"),
                    Some(proc) => match vm.getvmem(proc.proc.dirBase, hVA, hVA + hSize) {
                        None => println!("Unable to read memory"),
                        Some(data) => hexdump::hexdump(&data),
                    },
                }
            }
        }
        "list_processes" => vm.as_mut().list_process(true, true),
        "list_process_modules" => {
            if parts.len() != 2 {
                println!("Usage: list_process_modules explorer.exe")
            } else {
                match vm.as_mut().find_process(&parts[1], false, true, true) {
                    None => println!("Unable to find a process with matching name"),
                    Some(mut proc) => vm.list_process_modules(&mut proc, true),
                }
            }
        }
        "heaps" => {
            if parts.len() != 2 {
                println!("Usage: heaps explorer.exe")
            } else {
                match vm.as_mut().find_process(&parts[1], false, true, true) {
                    None => println!("Unable to find a process with matching name"),
                    Some(proc) => vm.get_process_heaps(&proc),
                }
            }
        }
        "peb" => {
            if parts.len() != 2 {
                println!("Usage: peb explorer.exe")
            } else {
                match vm.as_mut().find_process(&parts[1], false, true, true) {
                    None => println!("Unable to find a process with matching name"),
                    Some(proc) => {
                        let peb = vm.get_full_peb(&proc);
                        println!("PEB: {:#?}", peb);

                        let loader = peb.read_loader(&vm, &proc);
                        println!("Loader: {:#?}", loader);

                        let mut idx = 0;
                        let mut module =
                            loader.getFirstInMemoryOrderModuleListForProcess(&vm.native_ctx, &proc);
                        loop {
                            if module.is_none() || idx >= loader.Length {
                                break;
                            }
                            let m = module.unwrap();
                            let name = match m.BaseDllName.resolve_in_process(
                                &vm.native_ctx,
                                &proc,
                                Some(512),
                            ) {
                                Some(n) => n,
                                None => "unknown".to_string(),
                            };
                            println!("  LOADED MODULE {}: {}", idx, name);
                            module =
                                m.getNextInMemoryOrderModuleListForProcess(&vm.native_ctx, &proc);
                            idx += 1;
                        }
                    }
                }
            }
        }
        "pinspect" => {
            if parts.len() != 2 {
                println!("Usage: list_process_sections explorer.exe")
            } else {
                match vm.as_mut().find_process(&parts[1], false, true, true) {
                    None => println!("Unable to find a process with matching name"),
                    Some(mut proc) => vm.pinspect(&mut proc, true),
                }
            }
        }
        "help" | "usage" => show_usage(),
        _ => {
            println!("Unknown command: {:?}", parts);
            show_usage()
        }
    }
}

fn main() {
    let vm = vmsession::VMSession::new().expect("Failed to initialize");
    println!("\n######################");
    println!("#  Hypervisor Shell   ");
    println!("######################\n");
    let interface = Interface::new("hypervisor").unwrap();
    let text = "hypervisor> ";
    interface
        .set_prompt(&format!(
            "\x01{prefix}\x02{text}\x01{suffix}\x02",
            prefix = "", //style.prefix(),
            text = text,
            suffix = "", //style.suffix()
        ))
        .unwrap();

    while let ReadResult::Input(line) = interface.read_line().unwrap() {
        match shlex::split(&line) {
            None => println!("Empty/None command invalid"),
            Some(parts) => {
                if parts.is_empty() {
                    println!("Empty command invalid")
                } else {
                    dispatch_commands(std::sync::Arc::clone(&vm), parts)
                }
            }
        }
        interface.add_history_unique(line);
    }
}
