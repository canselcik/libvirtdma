#![allow(non_snake_case)]
use byteorder::ByteOrder;
use libvirtdma::proc_kernelinfo::ProcKernelInfo;
use libvirtdma::vm::VMBinding;
use libvirtdma::win::teb::TEB;
use linefeed::{Interface, ReadResult};
use libvirtdma::win::peb_ldr_data::LdrModule;
use crate::rust_structs::{BaseNetworkable, EntityRef, GameObjectManager, LastObjectBase};

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

fn rust_unity_player_module(
    vm: &VMBinding,
    rust: &mut ProcKernelInfo,
    unity_player: &LdrModule,
) {
    let rust_dirbase = rust.eprocess.Pcb.DirectoryTableBase;
    let module_mem = match vm.dump_module_vmem(rust_dirbase, unity_player) {
        Err(e) => {
            println!("Failed to dump memory of UnityPlayer.dll: {}", e);
            return;
        }
        Ok(m) => m,
    };

    let matches = match VMBinding::pmemmem(
        &module_mem,
        "488905????????4883c438c348c705????????????????4883c438c3cccccccccc48",
    ) {
        Err(e) => {
            println!("Failed to find a match for the GOM signature: {}", e);
            return;
        },
        Ok(o) => o,
    };
    let gomsig_offset: u64 = if matches.len() != 1 {
        println!(
            "Found {} matches for GameObjectManager instead of 1",
            matches.len()
        );
        return;
    } else {
        *matches.get(0).unwrap() as u64
    };

    // UInt64 taggedObjects = m.read<UInt64>(GOM + 0x8);
    // UInt64 gameObject = m.read<UInt64>(taggedObjects + 0x10);
    let gomsig_addr = unity_player.BaseAddress + gomsig_offset;
    println!(
        "gomsig found at 0x{:x} (in proc space: 0x{:x})",
        gomsig_offset, gomsig_addr,
    );

    let offsetA: i32 = vm.vread(rust_dirbase, gomsig_addr + 3);
    let gom_addr_offset =
        gomsig_addr + 7 - unity_player.BaseAddress + offsetA as u64;
    let gom_addr = unity_player.BaseAddress + gom_addr_offset;

    assert_eq!(unity_player.BaseAddress + 0x17a6ad8, gom_addr);

    println!(
        "gomaddr in proc space: 0x{:x} (offset: 0x{:x})",
        gom_addr, gom_addr_offset,
    );

    let gom: GameObjectManager = vm.vread(rust_dirbase, gom_addr);
    println!("GOM: {:#?}", gom);

    let lto: LastObjectBase = vm.vread(rust_dirbase, gom.lastTaggedObject as u64);
    println!("LTO: {:#?}", lto);
}

fn rust_game_assembly_module(
    vm: &VMBinding,
    rust: &mut ProcKernelInfo,
    game_assembly: &LdrModule,
) {
    /* possible patterns:
         BaseNetworkable: 488b05????????488b88????????488b094885c974????33c08bd5
         CanAttack: E8????????488B8F????????0FB6F0
         CreateProjectile: 48895C24??48896C24??48897424??48897C24??41564883EC50803D??????????498BD9498BE8
         SendProjectileAttack: E8????????F20F1083????????F20F1183????????8B83????????8983????????80BB??????????
    */
    let bnaddr = game_assembly.BaseAddress + 0x28861B0;
    let dirbase = rust.eprocess.Pcb.DirectoryTableBase;
    let nb: BaseNetworkable = vm.vread(dirbase, bnaddr);
    println!("BaseNetworkable: {:#?}", nb);

    let erefaddr = game_assembly.BaseAddress + nb.parentEntityRef;
    let eref: EntityRef = vm.vread(dirbase, erefaddr);
    println!("EREF: {:#?}", eref);
}

fn rust_routine(vm: &VMBinding, rust: &mut ProcKernelInfo) {
    if !"RustClient.exe".eq(&rust.name){
        println!("The current open process is not called RustClient.exe");
        return;
    }

    let modules = vm.get_process_modules_map(&rust);
    let unity_player = match modules.get("UnityPlayer.dll") {
        Some(up) => up,
        None => {
            println!("Unable to find UnityPlayer.dll module in RustClient.exe");
            return;
        }
    };
    let game_assembly = match modules.get("GameAssembly.dll") {
        Some(up) => up,
        None => {
            println!("Unable to find GameAssembly.dll module in GameAssembly.exe");
            return;
        }
    };

    println!("Found UnityPlayer.dll at 0x{:x}", unity_player.BaseAddress);
    println!("Found GameAssembly.dll at 0x{:x}", game_assembly.BaseAddress);


    println!("Processing UnityPlayer.dll module...");
    rust_unity_player_module(vm, rust, &unity_player);

    println!("Processing GameAssembly.dll module...");
    rust_game_assembly_module(vm, rust, &game_assembly);
}

fn show_usage() {
    println!(
        r#"
Process Context Commands:
    pmemread              read $2 bytes from PVA $1
    rust                  runs the RustClient.exe subroutine
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
        "rust" => match context {
            Some(info) => rust_routine(vm, info),
            None => println!("usage: rust (after entering a process context)"),
        },
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
        "{}/.lvdmacli_hist",
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
