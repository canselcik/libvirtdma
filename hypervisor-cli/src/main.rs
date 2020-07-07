#![allow(non_snake_case)]
use byteorder::ByteOrder;
use hypervisor::proc_kernelinfo::ProcKernelInfo;
use hypervisor::vm::VMBinding;
use hypervisor::win::teb::TEB;
use linefeed::{Interface, ReadResult};

mod rust_structs;

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

fn kmod_to_file(vm: &VMBinding, cmd: &[String]) {
    if cmd.len() != 2 {
        println!("Usage: kmod_to_file EasyAntiCheat.sys");
        return;
    }
    let name = &cmd[1];
    match vm.find_kmod(name) {
        Some(eac) => match vm.dump_kmod_vmem(&eac) {
            Err(e) => println!("Unable to read kernel module memory: {}", e),
            Ok(mem) => match std::fs::write(name, &mem) {
                Ok(_) => println!("Module dumped to {}", name),
                Err(e) => println!("Unable to write file: {}", e.to_string()),
            },
        },
        None => {}
    };
}

// fn rust_unity_player_module(
//     vm: &mut VMBinding,
//     rust: &mut WinProcess,
//     unityPlayerModule: &mut WinDll,
// ) {
//     let all = vm
//         .dump_process_vmem(rust, &unityPlayerModule.info)
//         .expect("failed to read");
//
//     match VMBinding::pmemmem(
//         &all,
//         "488905????????4883c438c348c705????????????????4883c438c3cccccccccc48",
//     ) {
//         Ok(res) => {
//             if res.len() != 1 {
//                 println!(
//                     "Found {} matches for GameObjectManager instead of 1",
//                     res.len()
//                 );
//                 return;
//             }
//             // UInt64 taggedObjects = m.read<UInt64>(GOM + 0x8);
//             // UInt64 gameObject = m.read<UInt64>(taggedObjects + 0x10);
//             let gomsig_offset: u64 = *res.get(0).unwrap() as u64;
//             let gomsig_addr = unityPlayerModule.info.baseAddress + gomsig_offset;
//             println!(
//                 "gomsig found at 0x{:x} (in proc space: 0x{:x})",
//                 gomsig_offset, gomsig_addr,
//             );
//             match vm.find_module_from_addr(&rust.module_list, gomsig_addr) {
//                 Some(m) => println!("gomsig falls into {}", m.name),
//                 None => println!("gomsig fall into any module"),
//             };
//
//             let offsetA: i32 = rust.read(&vm.native_ctx, gomsig_addr + 3);
//             let gom_addr_offset =
//                 gomsig_addr + 7 - unityPlayerModule.info.baseAddress + offsetA as u64;
//             let gom_addr = unityPlayerModule.info.baseAddress + gom_addr_offset;
//
//             assert_eq!(unityPlayerModule.info.baseAddress + 0x17a6ad8, gom_addr);
//
//             println!(
//                 "gomaddr in proc space: 0x{:x} (offset: 0x{:x})",
//                 gom_addr, gom_addr_offset,
//             );
//             match vm.find_module_from_addr(&rust.module_list, gom_addr) {
//                 Some(m) => println!("gom falls into {}", m.name),
//                 None => println!("gom doesnt fall into any module"),
//             };
//
//             let gomdata: [u8; 0x20] = rust.read(&vm.native_ctx.clone(), gom_addr);
//             let gom: GameObjectManager = unsafe { std::mem::transmute(gomdata) };
//
//             println!("GOM: {:#?}", gom);
//             hexdump::hexdump(&gomdata);
//
//             let lto: LastObjectBase =
//                 rust.read(&vm.native_ctx.clone(), gom.lastTaggedObject as u64);
//             println!("LTO: {:#?}", lto);
//         }
//         Err(e) => println!("Error while searching GOM: {}", e),
//     };
// }
//
// fn rust_game_assembly_module(
//     vm: &mut VMBinding,
//     rust: &mut WinProcess,
//     gameAssemblyModule: &mut WinDll,
// ) {
//     /* possible patterns:
//          BaseNetworkable: 488b05????????488b88????????488b094885c974????33c08bd5
//          CanAttack: E8????????488B8F????????0FB6F0
//          CreateProjectile: 48895C24??48896C24??48897424??48897C24??41564883EC50803D??????????498BD9498BE8
//          SendProjectileAttack: E8????????F20F1083????????F20F1183????????8B83????????8983????????80BB??????????
//     */
//     let bnaddr = gameAssemblyModule.info.baseAddress + 0x28861B0;
//
//     match vm.find_module_from_addr(&rust.module_list, bnaddr) {
//         Some(m) => println!("BN falls into {}", m.name),
//         None => println!("BN doesnt into any module"),
//     };
//     let networkable: [u8; std::mem::size_of::<BaseNetworkable>()] =
//         rust.read(&vm.native_ctx.clone(), bnaddr);
//     hexdump::hexdump(&networkable);
//
//     let nb: BaseNetworkable = unsafe { std::mem::transmute(networkable) };
//     println!("BaseNetworkable: {:#?}", nb);
//
//     let parentData: [u8; std::mem::size_of::<EntityRef>()] = rust.read(
//         &vm.clone(),
//         nb.parentEntityRef + gameAssemblyModule.info.baseAddress,
//     );
//
//     let eref: EntityRef = unsafe { std::mem::transmute(parentData) };
//     println!("EREF: {:#?}", eref);
// }
//
// fn rust_routine(vm: &mut VMBinding) {
//     match vm.find_process("RustClient.exe", false, true, true) {
//         Some(mut rust) => {
//             println!("Found RustClient.exe");
//             rust.refresh_modules(vm.native_ctx.clone());
//             let mut modules = rust.module_list.clone();
//             for module in modules.iter_mut() {
//                 match module.name.as_ref() {
//                     "UnityPlayer.dll" => rust_unity_player_module(vm, &mut rust, module),
//                     "GameAssembly.dll" => rust_game_assembly_module(vm, &mut rust, module),
//                     _ => {}
//                 }
//             }
//         }
//         None => println!("Unable to find RustClient.exe"),
//     }
// }

fn show_usage() {
    println!(
        r#"
Process Context Commands:
    pmemread              read $2 bytes from PVA $1
    eprocess              show full EPROCESS for the open process [or process with PID $1]
    peb                   print the full PEB of the open process
    pinspect              inspect process named
    tebs
    threads
    loader
    modules
    heaps

General Context Commands:
    openpid               enter process context for PID $1

    openproc              enter process context for the first process with name $1
    openprocess

    close                 leave the process context 

    listproc              list all running processes (walk eprocess)
    listprocs
    listprocess           
    listprocesses

    listkmod              list loaded kernel modules
    listkmods

    winexports            lists kernel exports and their addresses
    kernelexports
    kexports

Legacy Commands:
    rust:                 runs the rust subroutine
    kmod_to_file:         dump kernel module with the name $1 to disk
    memread:              read $2 bytes of physical memory from $1
    mem2file              read $2 bytes of physical memory from $1 to $3

Other Commands:
    quit | exit:          exit the program
    usage:                print this message\n"#
    );
}

fn dispatch_commands(
    vm: &VMBinding,
    parts: Vec<String>,
    context: &mut Option<ProcKernelInfo>,
) -> Option<DispatchCommandReturnAction> {
    match parts[0].as_ref() {
        // TODO: Bring back rust experiment support
        // "rust" => rust_routine(vm.as_mut()),
        "winexports" | "kernelexports" | "kexports" => vm.list_kernel_exports(),
        "listkmod" | "listkmods" => vm.list_kmods(),
        "listproc" | "listprocs" | "listprocess" | "listprocesses" => vm.list_processes(true),
        "close" => {
            return match context {
                None => {
                    println!("You are not in any context");
                    None
                }
                Some(proc) => {
                    println!(
                        "Leaving context of process with PID {}...",
                        proc.eprocess.UniqueProcessId
                    );
                    Some(DispatchCommandReturnAction::ExitContext)
                }
            }
        }
        "openpid" => {
            if parts.len() != 2 {
                println!("usage: openpid <PID>");
            } else {
                let pid = match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse PID");
                        return None;
                    }
                };
                return match vm.find_process_by_pid(pid, true) {
                    None => {
                        println!("Unable to find a kernel EPROCESS entry for PID {}", pid);
                        None
                    }
                    Some(info) => Some(DispatchCommandReturnAction::EnterProcessContext(info)),
                };
            }
        }
        "openproc" | "openprocess" => {
            if parts.len() != 2 {
                println!("usage: openprocess <ProcessName>");
            } else {
                return match vm.find_process_by_name(&parts[1], true) {
                    None => {
                        println!("Unable to find a process with name '{}'", &parts[1]);
                        None
                    }
                    Some(info) => Some(DispatchCommandReturnAction::EnterProcessContext(info)),
                };
            }
        }
        "pmemread" => {
            if parts.len() != 3 {
                println!("usage: pmemread <hVA> <hSize>");
            } else {
                let hVA = match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hVA");
                        return None;
                    }
                };
                let hSize = match parse_u64(&parts[2], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hSize");
                        return None;
                    }
                };
                match context {
                    None => {
                        println!("You need to enter a context using an open command first");
                        return None;
                    }
                    Some(proc) => {
                        match vm.vreadvec(proc.eprocess.Pcb.DirectoryTableBase, hVA, hVA + hSize) {
                            None => println!("Unable to read memory"),
                            Some(data) => hexdump::hexdump(&data),
                        }
                    }
                }
            }
        }
        "loader" => match context {
            Some(info) => {
                let peb =
                    vm.get_full_peb(info.eprocess.Pcb.DirectoryTableBase, info.eprocessPhysAddr);
                let loader =
                    peb.read_loader_with_dirbase(&vm, info.eprocess.Pcb.DirectoryTableBase);
                println!("{:#?}", loader);
            }
            None => println!("usage: loader (after entering a process context"),
        },
        "threads" => match context {
            Some(info) => {
                let threads = vm.threads_from_eprocess(info);
                if threads.is_empty() {
                    println!("Unable to find any threads");
                }
                for t in threads.iter() {
                    println!("{:#?}", t);
                }
            }
            None => println!("usage: threads (after entering a process context"),
        },
        "heaps" => match context {
            Some(info) => {
                // physProcess is the physical address of EPROCESS
                for heap in vm
                    .get_heaps_with_dirbase(
                        info.eprocess.Pcb.DirectoryTableBase,
                        info.eprocessPhysAddr,
                    )
                    .iter()
                {
                    println!("Heap Entry: {:#?}", heap);
                }
            }
            None => println!("usage: heaps (after entering a process context"),
        },
        "modules" => match context {
            Some(info) => vm.list_process_modules(info),
            None => println!("usage: modules (after entering a process context"),
        },
        "pinspect" => match context {
            Some(info) => vm.pinspect(info),
            None => println!("usage: pinspect (after entering a process context"),
        },
        "eprocess" => {
            let pid = if parts.len() != 2 && context.is_none() {
                println!("usage: eprocess <PID> or enter a process context first");
                return None;
            } else if let Some(proc) = context {
                proc.eprocess.UniqueProcessId
            } else {
                match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse PID");
                        return None;
                    }
                }
            };
            match vm.find_process_by_pid(pid, true) {
                None => println!("Unable to find a kernel EPROCESS entry for PID {}", pid),
                Some(info) => {
                    println!(
                        "Found EPROCESS at VA 0x{:x}\n{:#?}",
                        info.eprocessVirtAddr, info.eprocess
                    );
                }
            };
        }
        "peb" => match context {
            Some(info) => println!(
                "{:#?}",
                vm.get_full_peb(info.eprocess.Pcb.DirectoryTableBase, info.eprocessPhysAddr)
            ),
            None => println!("usage: peb (after entering a process context"),
        },
        "tebs" => match context {
            Some(info) => {
                let threads = vm.threads_from_eprocess(&info);
                println!("Found {} linked ETHREADs", threads.len());
                for thread in threads.iter() {
                    let moniker = if thread.ThreadName != 0 {
                        vm.read_cstring_from_physical_mem(
                            vm.native_translate(vm.initial_process.dirbase, thread.ThreadName),
                            Some(32),
                        )
                    } else {
                        format!("0x{:x}", thread.CidUniqueThread)
                    };
                    let teb: TEB = vm.read(
                        vm.native_translate(info.eprocess.Pcb.DirectoryTableBase, thread.Tcb.Teb),
                    );
                    println!(
                        "  Found Thread '{}' ({} + {}) with TEB PVA @ 0x{:x}",
                        moniker,
                        teb.ClientId.UniqueProcess,
                        teb.ClientId.UniqueThread,
                        thread.Tcb.Teb
                    );
                }
            }
            None => println!("usage: threads (after entering a process context)"),
        },

        "mem2file" => {
            if parts.len() != 4 {
                println!("usage: mem2file <hPA> <hSize> <sFile>");
            } else {
                let hPA = match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hPA");
                        return None;
                    }
                };
                let hSize = match parse_u64(&parts[2], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hSize");
                        return None;
                    }
                };
                match vm.readvec(hPA, hPA + hSize) {
                    Some(data) => match std::fs::write(&parts[3], &data) {
                        Ok(_) => println!("{} bytes written to file '{}'", hSize, parts[3]),
                        Err(e) => println!(
                            "Error while writing to file '{}': {}",
                            parts[3],
                            e.to_string(),
                        ),
                    },
                    None => println!("Unable to read memory"),
                };
            }
        }
        "quit" | "exit" => std::process::exit(0),
        "kmod_to_file" => kmod_to_file(&vm, &parts),
        "memread" => {
            if parts.len() != 3 {
                println!("usage: pmemread <hPA> <hSize>");
            } else {
                let hPA = match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hPA");
                        return None;
                    }
                };
                let hSize = match parse_u64(&parts[2], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hSize");
                        return None;
                    }
                };
                match vm.readvec(hPA, hPA + hSize) {
                    Some(data) => hexdump::hexdump(&data),
                    None => println!("Unable to read memory"),
                };
            }
        }
        "help" | "usage" => show_usage(),
        _ => {
            println!("Unknown command: {:?}", parts);
            show_usage()
        }
    }
    return None;
}

#[allow(dead_code)]
enum DispatchCommandReturnAction {
    EnterProcessContext(ProcKernelInfo),
    ExitContext,
    EnterKernelContext,
}

fn main() {
    ctrlc::set_handler(move || {
        println!("Exiting gracfully...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let vm = VMBinding::new().expect("failed to bind");
    let histfile = format!(
        "{}/.vmread_hist",
        match dirs::home_dir() {
            Some(h) => h.as_path().display().to_string(),
            None => ".".to_string(),
        }
    );
    println!("\n######################");
    println!("#  Hypervisor Shell   ");
    println!("######################\n");
    let interface = Interface::new("hypervisor").unwrap();
    if let Err(e) = interface.load_history(histfile.clone()) {
        if e.kind() == std::io::ErrorKind::NotFound {
            println!(
                "History file {} doesn't exist, not loading history.",
                histfile.clone(),
            );
        } else {
            eprintln!("Could not load history file {}: {}", histfile.clone(), e);
        }
    }
    let set_interface_text = |s: &str| {
        interface
            .set_prompt(&format!(
                "\x01{prefix}\x02{text}\x01{suffix}\x02",
                prefix = "", //style.prefix(),
                text = format!("hypervisor{}> ", s),
                suffix = "", //style.suffix()
            ))
            .unwrap();
    };

    set_interface_text("");

    let mut open_process: Option<ProcKernelInfo> = None;
    while let ReadResult::Input(line) = interface.read_line().unwrap() {
        match shlex::split(&line) {
            None => println!("Empty/None command invalid"),
            Some(parts) => {
                if parts.is_empty() {
                    println!("Empty command invalid")
                } else {
                    if let Some(context_action) = dispatch_commands(&vm, parts, &mut open_process) {
                        match context_action {
                            DispatchCommandReturnAction::EnterKernelContext => {
                                println!("not implemented yet");
                            }
                            DispatchCommandReturnAction::ExitContext => {
                                set_interface_text("");
                                open_process = None;
                            }
                            DispatchCommandReturnAction::EnterProcessContext(pki) => {
                                set_interface_text(&format!(
                                    "[pid={}]",
                                    pki.eprocess.UniqueProcessId
                                ));
                                open_process = Some(pki);
                            }
                        }
                    }
                }
            }
        }
        interface.add_history_unique(line);
        if let Err(e) = interface.save_history(histfile.clone()) {
            eprintln!("Could not save history file {}: {}", histfile.clone(), e);
        }
    }
}