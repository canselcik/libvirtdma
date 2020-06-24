extern crate vmread;

fn main() {
    let ctx_ret = vmread::create_context(0);
    if ctx_ret.is_ok() {
        let (mut ctx, native_ctx) = ctx_ret.unwrap();
        println!("VMRead initialized!");

        ctx.refresh_processes();

        println!("Process List:\nPID\tVIRT\t\t\tPHYS\t\tBASE\t\tNAME");
        for i in ctx.process_list.iter() {
            if i.is_valid_pe(native_ctx) {
                println!(
                    "{:#4x}\t{:#16x}\t{:#9x}\t{:#9x}\t{}",
                    i.proc.pid, i.proc.process, i.proc.physProcess, i.proc.dirBase, i.name
                );
            }
        }
        ctx.refresh_kmods();
        for kmod in ctx.kmod_list.iter() {
            println!("KMOD: {}", kmod.name);
        }
    } else {
        let (eval, estr) = ctx_ret.err().unwrap();
        println!("Initialization error {}: {}", eval, estr);
    }
}
