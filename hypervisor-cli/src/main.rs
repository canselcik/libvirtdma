#![allow(non_snake_case, incomplete_features)]
#![feature(const_generics)]
use crate::rust_structs::il2cpp::{DotNetArray, DotNetDict, DotNetList, DotNetString};
use crate::rust_structs::{
    BaseNetworkable, EntityRef, GameObjectManager, PoolableObject, PrefabPreProcess,
};
use colored::*;
use libvirtdma::proc_kernelinfo::ProcKernelInfo;
use libvirtdma::vm::mlayout::parse_u64;
use libvirtdma::vm::VMBinding;
use libvirtdma::win::eprocess::{PsProtectedSigner, PsProtectedType};
use libvirtdma::win::peb_ldr_data::LdrModule;
use libvirtdma::win::teb::TEB;
use libvirtdma::RemotePtr;
use linefeed::{Interface, ReadResult};

mod asm;
mod rust_structs;

fn kmod_to_file(vm: &VMBinding, cmd: &[String]) {
    if cmd.len() != 2 {
        println!("Usage: kmod_to_file EasyAntiCheat.sys");
        return;
    }
    let name = &cmd[1];
    match vm.find_kmod(name) {
        Some(kmod) => {
            let mem = vm.dump_kmod_vmem(&kmod);
            match std::fs::write(name, &mem) {
                Ok(_) => println!("Module dumped to {}", name),
                Err(e) => println!("Unable to write file: {}", e.to_string()),
            };
        }
        None => {
            println!("Unable to find the kernel module of interest");
        }
    };
}

fn rust_unity_player_module(vm: &VMBinding, rust: &mut ProcKernelInfo, unity_player: &LdrModule) {
    let rust_dirbase = rust.eprocess.Pcb.DirectoryTableBase;
    let module_mem = match vm.dump_module_vmem(rust, unity_player) {
        Some(mem) => mem,
        None => {
            println!("Unable to dump module memory");
            return;
        }
    };

    let matches = match VMBinding::pmemmem(
        &module_mem,
        "488905????????4883c438c348c705????????????????4883c438c3cccccccccc48",
    ) {
        Err(e) => {
            println!("Failed to find a match for the GOM signature: {}", e);
            return;
        }
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
    let gom_addr_offset = gomsig_addr + 7 - unity_player.BaseAddress + offsetA as u64;
    assert_eq!(gom_addr_offset, 0x17a6ad8);

    let gom_addr = unity_player.BaseAddress + gom_addr_offset;
    println!(
        "gomaddr in proc space: 0x{:x} (offset: 0x{:x})",
        gom_addr, gom_addr_offset,
    );

    let gom: GameObjectManager = vm.vread(rust_dirbase, gom_addr);
    println!("GOM: {:#?}", gom);

    let preprocessed = gom.preProcessed.vread(vm, rust_dirbase, 0);
    println!("PrefabPreProcess: {:#?}", preprocessed);

    let prefabList = preprocessed.prefabList.vread(vm, rust_dirbase, 0);
    println!(
        "PREFABLIST AT {}: {:#?}",
        preprocessed.prefabList, prefabList
    );

    // prefabList.values

    // let game_obj: GameObject = vm.vread(rust_dirbase, lto.lastObject as u64)`;
    // println!(
    //     "GameObject at 0x{:x}: {:#?}",
    //     lto.lastObject as u64, game_obj
    // );
}

fn rust_game_assembly_module(vm: &VMBinding, rust: &mut ProcKernelInfo, game_assembly: &LdrModule) {
    /* possible patterns:
         BaseNetworkable: 488b05????????488b88????????488b094885c974????33c08bd5
         CanAttack: E8????????488B8F????????0FB6F0
         CreateProjectile: 48895C24??48896C24??48897424??48897C24??41564883EC50803D??????????498BD9498BE8
         SendProjectileAttack: E8????????F20F1083????????F20F1183????????8B83????????8983????????80BB??????????
    */
    let dirbase = rust.eprocess.Pcb.DirectoryTableBase;
    let module_mem = match vm.dump_module_vmem(rust, game_assembly) {
        Some(mem) => mem,
        None => {
            println!("Unable to dump module memory");
            return;
        }
    };

    let bnaddr = game_assembly.BaseAddress + 0x28FFD20;
    let nb: BaseNetworkable = vm.vread(dirbase, bnaddr);
    println!("BaseNetworkable at 0x{:x}: {:#?}", bnaddr, nb);
}

fn rust_routine(vm: &VMBinding, rust: &mut ProcKernelInfo) {
    if !"RustClient.exe".eq(&rust.name) {
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
            println!("Unable to find GameAssembly.dll module in RustClient.exe");
            return;
        }
    };

    println!("Found UnityPlayer.dll at 0x{:x}", unity_player.BaseAddress);
    println!(
        "Found GameAssembly.dll at 0x{:x}",
        game_assembly.BaseAddress
    );

    println!("===================");

    println!("Processing UnityPlayer.dll module...");
    rust_unity_player_module(vm, rust, &unity_player);

    println!("===================");

    println!("Processing GameAssembly.dll module...");
    rust_game_assembly_module(vm, rust, &game_assembly);

    println!("===================");
}

fn show_usage() {
    println!(
        r#"
Process Context Commands:
    pmemread              read $2 bytes from PVA $1
    setprotected          set or unset protected status for process
    pmemmem               search hexstring $3 in PVA[$1, $1+$2]
    pmem2file             read $2 bytes from PVA $1 to $3
    rust                  runs the RustClient.exe subroutine
    eprocess              show full EPROCESS for the open process [or process with PID $1]
    peb                   print the full PEB of the open process
    sections              get sections for module $1
    dumpmodules           dumps all modules into path $1
    whereis               displays which section of which module the PVA $1 falls into
    deref                 grab a 64-bit pointer from expression PVA $1
    transmute
    pmemdumpall
    patch
    vpdisasm
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
        "pmemmem" => match context {
            Some(info) => {
                if parts.len() != 4 {
                    println!("usage: pmemmem <hVA> <hSize> <hexNeedle>")
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
                    let hexNeedle = parts[3].clone();
                    let data = vm.vreadvec(info.eprocess.Pcb.DirectoryTableBase, hVA, hSize);
                    match VMBinding::pmemmem(&data, &hexNeedle) {
                        Ok(results) => {
                            let mut i: u64 = 0;
                            for result in results.iter() {
                                println!(
                                    "Match {} at offset {} (hVA: 0x{:x})",
                                    i,
                                    *result,
                                    hVA + *result as u64
                                );
                                i += 1;
                            }
                        }
                        Err(e) => println!(
                            "Error while searching the dumped section of interest: {}",
                            e
                        ),
                    }
                }
            }
            None => println!(
                "usage: pmemmem <hVA> <hSize> <hexNeedle> (after entering a process context)"
            ),
        },
        "dumpmodules" => match context {
            Some(info) => {
                let pathstr = match parts.get(1) {
                    None => {
                        println!("usage: dumpmodules <outputPath>");
                        return None;
                    }
                    Some(p) => p,
                };
                let p = std::path::Path::new(pathstr);
                if !p.exists() || !p.is_dir() {
                    println!("Make sure path {} exists and is a directory", pathstr);
                    return None;
                }
                let dtb = info.eprocess.Pcb.DirectoryTableBase;
                for module in vm.get_process_modules(info).iter() {
                    let name = match module.BaseDllName.resolve(&vm, Some(dtb), Some(64)) {
                        None => format!("{:#18x}", module.BaseAddress),
                        Some(n) => {
                            if n.is_empty() || n.contains('\0') {
                                format!("{:#18x}", module.BaseAddress)
                            } else {
                                n
                            }
                        }
                    }
                    .trim()
                    .to_string();
                    let outfile = p.join(format!("{},0x{:x}.bin", name, module.BaseAddress));
                    let modulemem = match vm.dump_module_vmem(info, module) {
                        None => {
                            println!("Unable to read module mem for {}", name);
                            continue;
                        }
                        Some(m) => m,
                    };
                    match std::fs::write(&outfile, &modulemem) {
                        Ok(_) => {
                            println!("{} bytes written to file '{:?}'", modulemem.len(), outfile)
                        }
                        Err(e) => println!(
                            "Error while writing to file '{:?}': {}",
                            &outfile,
                            e.to_string(),
                        ),
                    }
                }
            }
            None => println!("usage: dumpmodules <outputPath> (after entering a process context"),
        },
        "pmemdumpall" => match context {
            Some(info) => {
                let p = std::path::Path::new(match parts.get(1) {
                    None => {
                        println!(
                            "usage: pmemdumpall <pathMemSectionMapFile> (after entering a process context)"
                        );
                        return None;
                    }
                    Some(p) => p,
                });
                let parent_dir = match p.parent() {
                    Some(pa) => pa,
                    None => {
                        println!("No parent dir exists on that path -- specify a file");
                        return None;
                    }
                };
                let m = match std::fs::read_to_string(p) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("failed to read map file: {}", e);
                        return None;
                    }
                };
                let layout = match libvirtdma::vm::mlayout::MemoryLayout::from_x64dbg_table(&m) {
                    Ok(l) => l,
                    Err(e) => {
                        println!("failed to parse layout: {}", e);
                        return None;
                    }
                };
                let dtb = info.eprocess.Pcb.DirectoryTableBase;
                for (begin, section) in layout.sections.iter() {
                    let len = section.range.end - section.range.start;
                    print!("Dumping {} bytes from 0x{:x}...", len, begin);
                    let output = vm.vreadvec(dtb, section.range.start, len);
                    match std::fs::write(parent_dir.join(format!("{:x}.bin", begin)), output) {
                        Ok(_) => println!("OK"),
                        Err(e) => println!("ERR({})", e.to_string()),
                    };
                }
            }
            None => println!(
                "usage: pmemdumpall <pathMemSectionMapFile> (after entering a process context)"
            ),
        },
        "transmute" | "tr" | "struct" => match context {
            Some(info) => {
                if parts.len() != 3 {
                    println!("usage: transmute <hVA> <transmuteString>")
                } else {
                    let hVA = match parse_u64(&parts[1], false) {
                        Some(h) => h,
                        None => {
                            println!("unable to parse hVA");
                            return None;
                        }
                    };
                    let dtb = info.eprocess.Pcb.DirectoryTableBase;
                    let mut last_type = "";
                    macro_rules! dbgstruct {
                        ($typ: ty, $i: expr, $offset: expr) => {{
                            let data: $typ = vm.vread(dtb, hVA + $offset);
                            println!("  (+0x{:x}) ${} = {:#?}", $offset, $i, data);
                            println!("\x1b[F  }}");
                            Ok(std::mem::size_of::<$typ>() as i64)
                        }};
                    }
                    let eval = |i, component, offset| -> Result<i64, ()> {
                        match component {
                            "prefabpreprocess" => dbgstruct!(PrefabPreProcess, i, offset),
                            "poolableobject" => dbgstruct!(PoolableObject, i, offset),
                            ".netarray" => dbgstruct!(DotNetArray<RemotePtr>, i, offset),
                            ".netstr16" => dbgstruct!(DotNetString<16>, i, offset),
                            ".netstr32" => dbgstruct!(DotNetString<32>, i, offset),
                            ".netlist" => dbgstruct!(DotNetList<RemotePtr>, i, offset),
                            ".netdict" => dbgstruct!(DotNetDict<RemotePtr, RemotePtr>, i, offset),
                            "bn" => dbgstruct!(BaseNetworkable, i, offset),
                            "gom" => dbgstruct!(GameObjectManager, i, offset),
                            "u8" | "uint8_t" | "byte" => {
                                let data: u8 = vm.vread(dtb, hVA + offset);
                                println!("  (+0x{:x}) ${} = 0x{:0>2x}", offset, i, data);
                                Ok(1)
                            }
                            "u16" | "uint16_t" | "ushort" => {
                                let data: u8 = vm.vread(dtb, hVA + offset);
                                println!("  (+0x{:x}) ${} = {}", offset, i, data);
                                Ok(2)
                            }
                            "u32" | "uint32_t" | "uint" => {
                                let data: u32 = vm.vread(dtb, hVA + offset);
                                println!("  (+0x{:x}) ${} = {}", offset, i, data);
                                Ok(4)
                            }
                            "bool" => {
                                let data: bool = vm.vread(dtb, hVA + offset);
                                println!("  (+0x{:x}) ${} = {}", offset, i, data);
                                Ok(1)
                            }
                            "u64" | "uint64_t" | "ptr" | "pointer" => {
                                let data: u64 = vm.vread(dtb, hVA + offset);
                                println!("  (+0x{:x}) ${} = 0x{:0>16x}", offset, i, data);
                                Ok(8)
                            }
                            unk => {
                                if unk.starts_with("*") {
                                    let num: Result<u64, _> = (&unk[1..]).parse();
                                    match num {
                                        Ok(times) => Ok(times as i64 * -1),
                                        Err(e) => {
                                            println!(
                                                "Failed to parse the repeated member: {}",
                                                e.to_string()
                                            );
                                            Err(())
                                        }
                                    }
                                } else {
                                    println!("Aborting due to unknown type: {}", unk);
                                    Err(())
                                }
                            }
                        }
                    };
                    let mut repeated_so_far = 0usize;
                    let mut current_offset = 0u64;
                    println!("0x{:0>16x} {{", hVA);
                    for (i, component) in parts[2].split(",").enumerate() {
                        match eval(i + repeated_so_far, component, current_offset) {
                            Ok(fwd) => {
                                if fwd > 0 {
                                    current_offset += fwd as u64;
                                    last_type = component;
                                } else {
                                    for _ in 0..(-1 * fwd) {
                                        current_offset +=
                                            eval(i + repeated_so_far, last_type, current_offset)
                                                .unwrap()
                                                as u64;
                                        repeated_so_far += 1;
                                    }
                                }
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                    println!("}}");
                }
            }
            None => {
                println!("usage: deref <hVA> <transmuteString>(after entering a process context)")
            }
        },
        "deref" => match context {
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: deref <hVA>")
                } else {
                    let hVA = match parse_u64(&parts[1], false) {
                        Some(h) => h,
                        None => {
                            println!("unable to parse hVA");
                            return None;
                        }
                    };
                    let data: RemotePtr = vm.vread(info.eprocess.Pcb.DirectoryTableBase, hVA);
                    println!("{}", data);
                }
            }
            None => println!("usage: deref <hVA>(after entering a process context)"),
        },
        "pmem2file" => {
            if parts.len() != 4 {
                println!("usage: pmem2file <hVA> <hSize> <file>");
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
                    None => println!(
                        "usage: pmem2file <hVA> <hSize> <file> (after entering a process context)"
                    ),
                    Some(proc) => {
                        let data = vm.vreadvec(proc.eprocess.Pcb.DirectoryTableBase, hVA, hSize);
                        match std::fs::write(&parts[3], &data) {
                            Ok(_) => println!("{} bytes written to file '{}'", hSize, parts[3]),
                            Err(e) => println!(
                                "Error while writing to file '{}': {}",
                                parts[3],
                                e.to_string(),
                            ),
                        }
                    }
                }
            }
        }
        "vpdisasm" | "vpdisas" | "dis" | "disas" => match context {
            Some(info) => {
                if parts.len() != 3 {
                    println!("usage: vpdisasm <hVA> <hSize>")
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
                    vm.vpdisasm(info.eprocess.Pcb.DirectoryTableBase, hVA, hSize, hVA);
                }
            }
            None => println!("usage: vpdisasm <hVA> <hSize> (after entering a process context)"),
        },
        "rust" => match context {
            Some(info) => rust_routine(vm, info),
            None => println!("usage: rust (after entering a process context)"),
        },
        "findexports" | "searchexports" | "findexport" | "searchexport" => match context {
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: findmem <hexNeedle>");
                    return None;
                }
                let hexNeedle = parts[1].to_lowercase();
                for (module_name, module) in vm.get_process_modules_map(info).iter() {
                    match vm.get_module_exports(
                        info.eprocess.Pcb.DirectoryTableBase,
                        module.BaseAddress,
                    ) {
                        Err(e) => println!(
                            "WARN: Unable to get module exports for {}: {}",
                            module_name, e
                        ),
                        Ok(exports) => {
                            for (name, export) in exports.iter() {
                                if name.to_ascii_lowercase().contains(&hexNeedle) {
                                    println!("[0x{:x}]@{} {}", export.address, module_name, name);
                                }
                            }
                        }
                    };
                }
            }
            None => println!("usage: findexports <keyword> (after entering a process context"),
        },
        "findmem" | "searchmem" => match context {
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: findmem <keyword>");
                    return None;
                }
                let keyword = parts[1].to_lowercase();
                let dtb = info.eprocess.Pcb.DirectoryTableBase;
                for module in vm.get_process_modules(info).iter() {
                    let data = match vm.dump_module_vmem(info, module) {
                        None => {
                            println!("Unable to read module mem");
                            return None;
                        }
                        Some(m) => m,
                    };
                    match VMBinding::pmemmem(&data, &keyword) {
                        Ok(results) => {
                            let mut i: u64 = 0;
                            for result in results.iter() {
                                println!(
                                    "Match {} at offset {} (0x{:x}) of {} (hVA: 0x{:x})",
                                    i,
                                    *result,
                                    *result,
                                    module
                                        .BaseDllName
                                        .resolve(&vm, Some(dtb), Some(255))
                                        .unwrap_or("unknown".to_string()),
                                    module.BaseAddress + *result as u64
                                );
                                i += 1;
                            }
                        }
                        Err(e) => println!(
                            "Error while searching the dumped section of interest: {}",
                            e
                        ),
                    };
                }
            }
            None => println!("usage: findmem <keyword> (after entering a process context"),
        },
        "exports" => match context {
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: exports <moduleName>");
                    return None;
                }
                let modules = vm.get_process_modules_map(info);
                let module = match modules.get(&parts[1]) {
                    None => {
                        println!("Unable to find a module with name {}", &parts[1]);
                        return None;
                    }
                    Some(m) => m,
                };
                match vm
                    .get_module_exports(info.eprocess.Pcb.DirectoryTableBase, module.BaseAddress)
                {
                    Err(e) => println!("Unable to get module exports: {}", e),
                    Ok(exports) => {
                        for (name, export) in exports.iter() {
                            println!("[0x{:x}] {}", export.address, name);
                        }
                    }
                };
            }
            None => println!("usage: exports <moduleName> (after entering a process context"),
        },
        "autopatch" => match context {
            Some(info) => {
                let modules = vm.get_process_modules_map(info);
                let dirbase = info.eprocess.Pcb.DirectoryTableBase;
                let peb = vm.get_full_peb(dirbase, info.eprocessPhysAddr);
                let base_module = match modules
                    .iter()
                    .find(|(_, module)| module.BaseAddress == peb.ImageBaseAddress)
                {
                    Some(bm) => bm.1,
                    None => {
                        println!("Unable to determine base module");
                        return None;
                    }
                };
                println!("Found base module at 0x{:x}", base_module.BaseAddress);

                let user32module = match modules.iter().find(|(name, _)| "User32.dll".eq(*name)) {
                    Some(u32module) => u32module.1,
                    None => {
                        println!("Unable to find the User32.dll module");
                        return None;
                    }
                };
                println!(
                    "Found User32.dll with base address 0x{:x}",
                    user32module.BaseAddress
                );

                let va_msgboxa = match vm.get_module_exports(dirbase, user32module.BaseAddress) {
                    Err(e) => {
                        println!("Failed to get the exports of User32.dll: {}", e);
                        return None;
                    }
                    Ok(u32exports) => match u32exports.get("MessageBoxA") {
                        Some(m) => m.address,
                        None => {
                            println!("Unable to find MessageBoxA in User32.dll");
                            return None;
                        }
                    },
                };
                println!("Found MessageBoxA at 0x{:x}", va_msgboxa);

                let main_module_mem = match vm.dump_module_vmem(info, base_module) {
                    None => {
                        println!("Unable to read module mem");
                        return None;
                    }
                    Some(m) => m,
                };
                let secretaddr = base_module.BaseAddress
                    + match VMBinding::pmemmem(&main_module_mem, "736563726574") {
                        Ok(m) => {
                            if m.len() == 1 {
                                m[0]
                            } else {
                                println!("Found {} matches. Not patching.", m.len());
                                return None;
                            }
                        }
                        Err(e) => {
                            println!("Failed to find matches: {}", e);
                            return None;
                        }
                    } as u64;
                let sigaddr = match VMBinding::pmemmem(&main_module_mem, "eb051bc083c80185c0") {
                    Ok(m) => {
                        if m.len() == 1 {
                            m[0]
                        } else {
                            println!("Found {} matches. Not patching.", m.len());
                            return None;
                        }
                    }
                    Err(e) => {
                        println!("Failed to find matches: {}", e);
                        return None;
                    }
                };
                let patchaddr = base_module.BaseAddress + sigaddr as u64 + 0x9;
                println!(
                    "Found the signature {} bytes from the base module base address, will patch at 0x{:x}",
                    sigaddr, patchaddr
                );

                let mut body = asm::MessageBoxA(va_msgboxa, 0, secretaddr);
                while body.len() < 81 {
                    body.push(0x90);
                }
                println!(
                    "Generated following payload to call MessageBoxA (len={} bytes)",
                    body.len()
                );
                libvirtdma::disasm(&body, 0);
                vm.vwrite(dirbase, patchaddr, &body);
                println!("Patched");
            }
            None => println!("usage: autopatch (after entering a process context)"),
        },
        "patch" => match context {
            Some(info) => {
                if parts.len() != 3 {
                    println!("usage: patch <hVA> <hexReplacement>");
                    return None;
                }
                let hVA = match parse_u64(&parts[1], false) {
                    Some(h) => h,
                    None => {
                        println!("unable to parse hVA");
                        return None;
                    }
                };
                let replacement = match hex::decode(&parts[2]) {
                    Ok(r) => r,
                    Err(e) => {
                        println!(
                            "Failed to parse the hexReplacement as a hex string: {}",
                            e.to_string()
                        );
                        return None;
                    }
                };
                vm.vwrite(info.eprocess.Pcb.DirectoryTableBase, hVA, &replacement);
                println!("Performed patch at module offset 0x{:x}", hVA);
            }
            None => {
                println!("usage: patch <hVA> <hexReplacement> (after entering a process context")
            }
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
        "setprotected" => match context {
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: setprotected <true|false>")
                } else {
                    if "true".eq(&parts[1]) {
                        vm.set_process_security(
                            info,
                            PsProtectedType::Protected,
                            PsProtectedSigner::WinTcb,
                        );
                        println!("Enabled Protection");
                    } else if "false".eq(&parts[1]) {
                        vm.set_process_security(
                            info,
                            PsProtectedType::None,
                            PsProtectedSigner::None,
                        );
                        println!("Disabled Protection");
                    } else {
                        println!("usage: setprotected <true|false>");
                    }
                }
            }
            None => println!("usage: setprotected <true|false> (after entering a process context)"),
        },
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
                        let data = vm.vreadvec(proc.eprocess.Pcb.DirectoryTableBase, hVA, hSize);
                        hexdump::hexdump(&data);
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
        "whereis" => match context {
            None => println!("usage: whereis <hVA> (after entering a process context)"),
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: whereis <hVA>")
                } else {
                    let dtb = info.eprocess.Pcb.DirectoryTableBase;
                    let hva = match parse_u64(&parts[1], false) {
                        Some(h) => h,
                        None => {
                            println!("unable to parse the hVA");
                            return None;
                        }
                    };
                    for module in vm.get_process_modules(info).iter() {
                        for section in vm.get_module_sections(info, module).iter() {
                            let begin = module.BaseAddress + section.VirtualAddress as u64;
                            let end = begin + section.SizeOfRawData as u64; // section.PhysicalAddressOrVirtualSize
                            if hva >= begin && hva < end {
                                println!(
                                    "0x{:x} is in the {} section of module {}",
                                    hva,
                                    section.get_name(),
                                    module
                                        .BaseDllName
                                        .resolve(&vm, Some(dtb), Some(128))
                                        .unwrap_or("unknown".to_string())
                                );
                                return None;
                            }
                        }
                    }
                    // todo: heaps
                    for heap in vm.get_heaps_with_dirbase(dtb, info.eprocessPhysAddr).iter() {
                        // heap
                    }
                    // todo: stacks
                }
            }
        },
        "sections" => match context {
            Some(info) => {
                if parts.len() != 2 {
                    println!("usage: sections <moduleName>")
                } else {
                    match vm.get_process_modules_map(info).get(&parts[1]) {
                        Some(module) => {
                            for section in vm.get_module_sections(info, module).iter() {
                                let section_name = section.get_name();
                                println!("Section {}", section_name);
                                println!(
                                    "  VA: 0x{:x}\n  Size: 0x{:x}",
                                    module.BaseAddress + section.VirtualAddress as u64,
                                    section.SizeOfRawData,
                                );
                                println!(
                                    "  PhysicalAddrOrVSize:  0x{:x}",
                                    section.PhysicalAddressOrVirtualSize
                                );
                                // TODO: needs fixing
                                // if section_name.starts_with(".reloc") {
                                //     let dtb = info.eprocess.Pcb.DirectoryTableBase;
                                //     let va_reloc =
                                //         module.BaseAddress + section.VirtualAddress as u64;
                                //     let reloc: ImageBaseRelocation = vm.vread(dtb, va_reloc);
                                //     for type_offset in
                                //         reloc.get_type_offsets(&vm, dtb, va_reloc).iter()
                                //     {
                                //         println!("Type offset in .reloc: {:?}", type_offset);
                                //     }
                                // }
                            }
                        }
                        None => println!("Failed to find a module with the given name"),
                    }
                }
            }
            None => println!("usage: sections <moduleName> (after entering a process context)"),
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
                let data = vm.readvec(hPA, hSize);
                match std::fs::write(&parts[3], &data) {
                    Ok(_) => println!("{} bytes written to file '{}'", hSize, parts[3]),
                    Err(e) => println!(
                        "Error while writing to file '{}': {}",
                        parts[3],
                        e.to_string(),
                    ),
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
                let data = vm.readvec(hPA, hSize);
                hexdump::hexdump(&data);
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

#[macro_use]
extern crate rouille;

fn main() {
    ctrlc::set_handler(move || {
        println!("Exiting gracefully...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let vm = std::sync::Arc::new(VMBinding::new().expect("failed to bind"));
    let histfile = format!(
        "{}/.lvdmacli_hist",
        match dirs::home_dir() {
            Some(h) => h.as_path().display().to_string(),
            None => ".".to_string(),
        }
    );

    let apivmref = std::sync::Arc::clone(&vm);
    let _api_handle = std::thread::spawn(move || {
        rouille::start_server("0.0.0.0:2222", move |request| {
            let reqvmref = std::sync::Arc::clone(&apivmref);
            router!(request,
                (GET) (/) => {
                     rouille::Response::text("DMA_OK")
                },
                (GET) (/dma/pmemread/{dirbase: u64}/{va: u64}/{len: u64}) => {
                    println!("[api] pmemread(dirbase={}, va={}, len={})", dirbase, va, len);
                    rouille::Response::text(hex::encode(&reqvmref.vreadvec(dirbase, va, len))).with_no_cache()
                },
                _ => rouille::Response::empty_404()
            )
        });
    });

    println!("{}", "######################".blue());
    println!("{}", "#  Hypervisor Shell   ".blue());
    println!("{}", "######################\n".blue());

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
                prefix = "",
                text = format!("hypervisor{}> ", s).yellow(),
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
