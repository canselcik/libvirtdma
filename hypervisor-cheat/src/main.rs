#![feature(new_uninit)]
#![allow(unused_macros, non_snake_case)]
extern crate bsdiff;
extern crate hex;
extern crate hexdump;
extern crate shlex;

extern crate linefeed;
use linefeed::{Interface, ReadResult};

extern crate vmread;
extern crate vmread_sys;

use crate::rust_external::*;
use crate::vmsession::VMSession;

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

fn rust_routine(vm: &mut VMSession) {
    match vm.find_process("RustClient.exe", false, true, true) {
        Some(mut rust) => {
            println!("Found RustClient.exe");
            rust.refresh_modules(vm.native_ctx.clone());
            vm.get_process_sections(&mut rust, false);

            let mut modules = rust.module_list.clone();
            for module in modules.iter_mut() {
                match module.name.as_ref() {
                    "UnityPlayer.dll" => {
                        let all = vm
                            .dump_process_vmem(&mut rust, &module.info)
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
                                    continue;
                                }
                                // UInt64 taggedObjects = m.read<UInt64>(GOM + 0x8);
                                // UInt64 gameObject = m.read<UInt64>(taggedObjects + 0x10);
                                let gomsig_offset: u64 = *res.get(0).unwrap() as u64;
                                let gomsig_addr = module.info.baseAddress + gomsig_offset;
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
                                    gomsig_addr + 7 - module.info.baseAddress + offsetA as u64;
                                let gom_addr = module.info.baseAddress + gom_addr_offset;

                                assert_eq!(module.info.baseAddress + 0x17a6ad8, gom_addr);

                                println!(
                                    "gomaddr in proc space: 0x{:x} (offset: 0x{:x})",
                                    gom_addr, gom_addr_offset,
                                );
                                match vm.find_module_from_addr(&rust.module_list, gom_addr) {
                                    Some(m) => println!("gom falls into {}", m.name),
                                    None => println!("gom doesnt fall into any module"),
                                };

                                let gomdata: [u8; 0x20] =
                                    rust.read(&vm.native_ctx.clone(), gom_addr);
                                let gom: GameObjectManager =
                                    unsafe { std::mem::transmute(gomdata) };

                                println!("GOM: {:#?}", gom);
                                hexdump::hexdump(&gomdata);

                                let lto: LastObjectBase =
                                    rust.read(&vm.native_ctx.clone(), gom.lastTaggedObject as u64);
                                println!("LTO: {:#?}", lto);
                            }
                            Err(e) => println!("Error while searching GOM: {}", e),
                        };
                    }
                    "GameAssembly.dll" => {
                        /* possible patterns:
                             BaseNetworkable: 488b05????????488b88????????488b094885c974????33c08bd5
                             CanAttack: E8????????488B8F????????0FB6F0
                             CreateProjectile: 48895C24??48896C24??48897424??48897C24??41564883EC50803D??????????498BD9498BE8
                             SendProjectileAttack: E8????????F20F1083????????F20F1183????????8B83????????8983????????80BB??????????
                        */
                        let bnaddr = module.info.baseAddress + 0x28861B0;
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
                            nb.parentEntityRef + module.info.baseAddress,
                        );
                        let eref: EntityRef = unsafe { std::mem::transmute(parentData) };
                        println!("EREF: {:#?}", eref);
                    }
                    _ => {}
                }
            }
        }
        None => println!("Unable to find RustClient.exe"),
    }
}

fn main() {
    let mut vm = vmsession::VMSession::new().expect("Failed to initialize");
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
                    match parts[0].as_ref() {
                        "rust" => rust_routine(&mut vm),
                        "quit" | "exit" => std::process::exit(0),
                        "kmod_to_file" => kmod_to_file(&mut vm, &parts),
                        "list_kmods" => vm.list_kmods(true),
                        "list_processes" => vm.list_process(true, true),
                        _ => println!("Unknown command: {:?}", parts),
                    }
                }
            }
        }
        interface.add_history_unique(line);
    }
}
