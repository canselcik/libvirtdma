extern crate vmread;

use std::process::Command;

fn main() {
    let pid = std::str::from_utf8(Command::new("sh")
        .arg("-c")
        .arg("pidof qemu-system-x86_64")
        .output()
        .unwrap()
        .stdout
        .as_slice())
        .unwrap()
        .trim()
        .to_string()
        .parse::<i32>()
        .unwrap_or(0);
    
    let ctx_ret = vmread::create_context(pid);

    if ctx_ret.is_ok() {
        let (mut ctx, c_ctx) = ctx_ret.unwrap();
        println!("VMRead initialized!");

        loop {
            let mut proc_name = String::new();
            println!("Enter process name");
            match std::io::stdin().read_line(&mut proc_name) {
                Ok(_) => {
                    match proc_name.trim() {
                        "q" => break,
                        s => {
                            match ctx.refresh_processes().process_list.iter_mut().find(|a| a.name == s) {
                                Some(p) => {
                                    println!("Module list for {}", s);
                                    println!("{:#14} {:#14} {:#8} {:#6} {}", "BASE ADDRESS", "ENTRY POINT", "SIZE", "LOADC", "NAME");
                                    for i in &(p.refresh_modules(c_ctx).module_list) {
                                        println!("{:#14x} {:#14x} {:#8x} {:#6x} {}", i.info.baseAddress, i.info.entryPoint, i.info.sizeOfModule, i.info.loadCount, i.name);
                                    }
                                },
                                _ => println!("Process {} not found!", s)
                            }
                        }
                    }
                },
                Err(error) => println!("error: {}", error)
            }
        }
    } else {
        let (eval, estr) = ctx_ret.err().unwrap();
        println!("Initialization error {}: {}", eval, estr);
    }
}
