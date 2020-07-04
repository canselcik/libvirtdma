use byteorder::ByteOrder;
use itertools::Itertools;
use nix::fcntl::open;
use nix::unistd::close;
use pelite::image::IMAGE_DOS_SIGNATURE;
use proc_maps::{MapRange, Pid};
use regex::bytes::Regex;
use std::io::Read;
use std::process::Stdio;
use vmread_sys::ProcessData;

pub struct VMProcessInfo {
    dirbase: u64,
}

pub struct VMBinding {
    initialProcess: VMProcessInfo,
    ntKernel: u64, // kernel base
    kernelEntry: u64,
    process_data: ProcessData,
}

const PAGE_OFFSET_SIZE: u64 = 12;
const PMASK: u64 = (!0xfu64 << 8) & 0xfffffffffu64;

const VMREAD_IOCTL_MAGIC: u8 = 0x42;

ioctl_readwrite!(vmread_bind, VMREAD_IOCTL_MAGIC, 0, ProcessData);

impl VMBinding {
    pub fn new() -> Option<VMBinding> {
        let mut binding = VMBinding {
            ntKernel: 0,
            kernelEntry: 0,
            initialProcess: VMProcessInfo { dirbase: 0 },
            process_data: match Self::create_process_data() {
                None => return None,
                Some(s) => s,
            },
        };
        if !binding.init_device() {
            return None;
        }
        match binding.find_initial_process() {
            Some((pml4, kernel_entry)) => {
                binding.initialProcess.dirbase = pml4;
                binding.kernelEntry = kernel_entry;
                binding.ntKernel = match binding.find_nt_kernel(kernel_entry) {
                    Some(ntk) => ntk,
                    None => {
                        /* Test in case we are running XP (QEMU AddressSpace is different) */
                        // #if (LMODE() != MODE_DMA())
                        //   KFIXC = 0x40000000ll * 4;
                        //   KFIXO = 0x40000000;
                        //   FindNTKernel(ctx, kernelEntry);
                        // #endif
                        return None;
                    }
                };
            }
            None => return None,
        };

        // TODO: STUFF
        // vmread_sys::FindProcAddress()
        // uint64_t initialSystemProcess = FindProcAddress(ctx->ntExports, "PsInitialSystemProcess");

        // VMemRead(&ctx->process, ctx->initialProcess.dirBase, (uint64_t)&ctx->initialProcess.process, initialSystemProcess, sizeof(uint64_t));
        // ctx->initialProcess.physProcess = VTranslate(&ctx->process, ctx->initialProcess.dirBase, ctx->initialProcess.process);
        // ctx->ntVersion = GetNTVersion(ctx);
        // ctx->ntBuild = GetNTBuild(ctx);
        // if (SetupOffsets(ctx))
        //   return 9;
        Some(binding)
    }

    pub fn vread<T>(&self, dirbase: u64, address: u64) -> T {
        self.read_physical(self.native_translate(dirbase, address))
    }

    fn find_nt_kernel(&self, kernelEntry: u64) -> Option<u64> {
        let mut mask = 0xfffffu64;
        while mask >= 0xfff {
            let mut i = (kernelEntry & !0x1fffff) + 0x20000000;
            while i > kernelEntry - 0x20000000 {
                for o in 0..0x20 {
                    let buf: [u8; 0x10000] =
                        self.vread(self.initialProcess.dirbase, i + 0x10000 * o);
                    let mut p = 0;
                    while p < 0x10000 {
                        if ((i + 0x1000 * o + p) & mask) != 0 {
                            p += 0x1000;
                            continue;
                        }
                        if byteorder::LittleEndian::read_u16(&buf[p as usize..])
                            != IMAGE_DOS_SIGNATURE
                        {
                            p += 0x1000;
                            continue;
                        }
                        let mut kdbg: bool = false;
                        let mut poolCode: bool = false;
                        for u in 0..0x1000u64 {
                            let puOffset = &buf[p as usize + u as usize..];
                            if puOffset.len() < 8 {
                                continue;
                            }
                            kdbg = kdbg
                                || byteorder::LittleEndian::read_u64(puOffset)
                                    == 0x4742444b54494e49;
                            poolCode = poolCode
                                || byteorder::LittleEndian::read_u64(puOffset)
                                    == 0x45444f434c4f4f50;
                            if kdbg && poolCode {
                                // TODO: Check if export list could be generated using this etc.
                                // if (GenerateExportList(ctx, &ctx->initialProcess, i + 0x10000 * o + p, &ctx->ntExports)) {
                                //   ctx->ntKernel = 0;
                                //   break;
                                // }
                                return Some(i + 0x10000 * o + p);
                            }
                        }
                        p += 0x1000;
                    }
                }
                i -= 0x200000;
            }
            mask = mask >> 4;
        }
        return None;
    }

    pub fn read_physical<T>(&self, address: u64) -> T {
        let mut ret: T = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        unsafe {
            vmread_sys::MemRead(
                &self.process_data,
                &mut ret as *mut T as u64,
                address,
                std::mem::size_of::<T>() as u64,
            );
        }
        ret
    }

    pub fn native_translate(&self, dirbase: u64, address: u64) -> u64 {
        let dirBase = dirbase & !0xfu64;
        let pageOffset = address & !(!0u64 << PAGE_OFFSET_SIZE);
        let pte = (address >> 12) & 0x1ffu64;
        let pt = (address >> 21) & 0x1ffu64;
        let pd = (address >> 30) & 0x1ffu64;
        let pdp = (address >> 39) & 0x1ffu64;

        let pdpe: u64 = self.read_physical(dirBase + 8 * pdp);
        if !pdpe & 1u64 != 0 {
            return 0;
        }

        let pde: u64 = self.read_physical((pdpe & PMASK) + 8 * pd);
        if !pde & 1u64 != 0 {
            return 0;
        }

        // 1GB large page, use pde's 12-34 bits
        if pde & 0x80u64 != 0 {
            return (pde & (!0u64 << 42 >> 12)) + (address & !(!0u64 << 30));
        }

        let pteAddr: u64 = self.read_physical((pde & PMASK) + 8 * pt);
        if !pteAddr & 1u64 != 0 {
            return 0;
        }

        // 2MB large page
        if pteAddr & 0x80u64 != 0 {
            return (pteAddr & PMASK) + (address & !(!0u64 << 21));
        }

        let resolved_addr: u64 = self.read_physical::<u64>((pteAddr & PMASK) + 8 * pte) & PMASK;
        if resolved_addr == 0 {
            return 0;
        }
        return resolved_addr + pageOffset;
    }

    fn find_initial_process(&self) -> Option<(u64, u64)> {
        for i in 0..10 {
            let buf: [u8; 0x10000] = self.read_physical(i * 0x10000);
            let mut o: usize = 0;
            loop {
                if o >= 0x10000 {
                    break;
                }
                let ulonglong = byteorder::LittleEndian::read_u64(&buf[o..]);
                if 0x00000001000600E9 ^ (0xffffffffffff00ff & ulonglong) != 0 {
                    o += 0x1000;
                    continue;
                }
                let x70_ulonglong: u64 = byteorder::LittleEndian::read_u64(&buf[o + 0x70..]);
                if 0xfffff80000000000 ^ (0xfffff80000000000 & x70_ulonglong) != 0 {
                    o += 0x1000;
                    continue;
                }
                let xa0_ulonglong: u64 = byteorder::LittleEndian::read_u64(&buf[o + 0xa0..]);
                if 0xffffff0000000fff & xa0_ulonglong != 0 {
                    o += 0x1000;
                    continue;
                }
                let pml4 = xa0_ulonglong;
                let kernelEntry = x70_ulonglong;
                return Some((pml4, kernelEntry));
            }
        }
        return None;
    }

    fn create_process_data() -> Option<ProcessData> {
        let pid = match Self::find_kvm_user_pid() {
            Some(p) => p,
            None => return None,
        };
        let maps = match Self::find_largest_kvm_maps() {
            Some(m) => m,
            None => return None,
        };
        let largest_map = match maps.first() {
            None => return None,
            Some(l) => l,
        };
        return Some(ProcessData {
            mapsStart: largest_map.start() as u64,
            mapsSize: largest_map.size() as u64,
            pid: pid as i32,
        });
    }

    fn init_device(&mut self) -> bool {
        let fd: i32 = match open(
            "/proc/vmread",
            nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::S_IRWXO,
        ) {
            Ok(f) => f,
            Err(_) => {
                println!("Failed to open /proc/vmread");
                return false;
            }
        };
        let res = match unsafe { vmread_bind(fd, &mut self.process_data as *mut ProcessData) } {
            Ok(res) => res == 0,
            Err(e) => {
                println!("Failed to call vmread ioctl: {}", e.to_string());
                false
            }
        };
        match close(fd) {
            Ok(()) => {}
            Err(e) => println!(
                "Error while closing the file descriptor to /proc/vmread: {}",
                e.to_string()
            ),
        };
        return res;
    }

    fn find_largest_kvm_maps() -> Option<Vec<MapRange>> {
        match Self::find_kvm_user_pid() {
            Some(pid) => {
                let pmaps = match proc_maps::get_process_maps(pid as Pid) {
                    Ok(pm) => pm,
                    Err(e) => {
                        println!("Unable to list process maps of qemu-kvm: {}", e.to_string());
                        return None;
                    }
                };
                Some(
                    pmaps
                        .iter()
                        .cloned()
                        .sorted_by(|a, b| Ord::cmp(&b.size(), &a.size()))
                        .collect_vec(),
                )
            }
            None => {
                println!("Unable to find KVM PID");
                None
            }
        }
    }

    fn find_kvm_user_pid() -> Option<u64> {
        let mut lsof_output: String = String::new();
        match std::process::Command::new("lsof")
            .arg("-Fp")
            .arg("/dev/kvm")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Err(e) => {
                println!("Failed to run lsof to find qemu-kvm pid: {}", e.to_string());
                return None;
            }
            Ok(child) => {
                match child.wait_with_output() {
                    Err(e) => {
                        println!("Failed to run lsof to find qemu-kvm pid: {}", e.to_string());
                        return None;
                    }
                    Ok(output) => match output.stdout.as_slice().read_to_string(&mut lsof_output) {
                        Err(e) => {
                            println!("Failed to read from lsof stdout while determining qemu-kvm pid: {}", e.to_string());
                            return None;
                        }
                        Ok(readlen) => {
                            if readlen == 0 || lsof_output.is_empty() {
                                println!("lsof yielded empty stdout when determining qemu-kvm pid");
                                return None;
                            }
                        }
                    },
                }
            }
        }
        let re = Regex::new(r"p(?P<pid>\d+)\n").unwrap();
        match re.captures(lsof_output.as_bytes()) {
            None => {
                println!("No captures in lsof output when determining qemu-kvm pid");
                None
            }
            Some(captures) => {
                let valid_caps: Vec<&[u8]> = captures
                    .iter()
                    .filter(|cap| cap.is_some())
                    .map(|cap| cap.unwrap().as_bytes())
                    .collect();
                if valid_caps.len() != 2 {
                    None
                } else {
                    let st: String = std::str::from_utf8(valid_caps.get(1).unwrap())
                        .unwrap()
                        .to_string();
                    Result::ok(st.parse::<u64>())
                }
            }
        }
    }
}
