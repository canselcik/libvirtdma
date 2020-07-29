use crate::vm::vmread_bind;
use crate::vm::{NtHeaders, ProcessData, VMBinding, WinExport, WinProc};
use crate::win::Offsets;
use byteorder::ByteOrder;
use itertools::Itertools;
use nix::fcntl::open;
use nix::unistd::close;
use pelite::image::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use pelite::pe64::image::{IMAGE_NT_HEADERS, IMAGE_NT_HEADERS_SIGNATURE};
use proc_maps::{MapRange, Pid};
use regex::bytes::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::process::Stdio;

impl VMBinding {
    pub fn new() -> Option<VMBinding> {
        let mut binding = VMBinding {
            offsets: None,
            cached_nt_exports: HashMap::new(),
            nt_kernel_entry: 0,
            nt_kernel_modulebase: 0,
            nt_version: 0,
            nt_build: 0,
            process: match Self::create_process_data() {
                None => return None,
                Some(s) => s,
            },
            initial_process: WinProc {
                eprocess_va: 0,
                eprocess_addr: 0,
                dirbase: 0,
                pid: 0,
                name: "".to_string(),
            },
        };
        if !binding.init_device() {
            return None;
        }
        let (pml4, kernel_entry) = match binding.find_initial_process() {
            Some(s) => s,
            None => return None,
        };

        binding.initial_process.dirbase = pml4;
        println!("PML4: 0x{:x}", pml4);

        binding.nt_kernel_entry = kernel_entry;
        println!("Kernel EntryPoint: 0x{:x}", kernel_entry);

        match binding.find_nt_kernel(kernel_entry) {
            Some((ntk, kexports)) => {
                binding.nt_kernel_modulebase = ntk;
                println!("NTKernel ModuleBase: 0x{:x}", ntk);

                // Less than ideal but we do it once. Better than having optionals or mutexes everywhere
                for (k, v) in kexports.iter() {
                    binding.cached_nt_exports.insert(k.clone(), v.clone());
                }
            }
            None => {
                // Test in case we are running XP (QEMU AddressSpace is different)
                //   KFIXC = 0x40000000ll * 4;
                //   KFIXO = 0x40000000;
                //   FindNTKernel(ctx, kernelEntry);
                return None;
            }
        };

        let init_proc_addr = match binding.find_kernel_export("PsInitialSystemProcess") {
            Some(0) | None => return None,
            Some(addr) => addr,
        };
        binding.initial_process.eprocess_va =
            binding.vread(binding.initial_process.dirbase, init_proc_addr);
        binding.initial_process.eprocess_addr = binding.native_translate(
            binding.initial_process.dirbase,
            binding.initial_process.eprocess_va,
        );

        binding.nt_version = binding.get_nt_version();
        binding.nt_build = binding.get_nt_build();
        binding.offsets = Offsets::get_offsets(binding.nt_version, binding.nt_build);
        if binding.offsets.is_none() {
            return None;
        };

        Some(binding)
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

    fn get_nt_version(&self) -> u16 {
        let get_version = match self.find_kernel_export("RtlGetVersion") {
            Some(0) | None => return 0,
            Some(addr) => addr,
        };

        let buf: [u8; 0x100] = self.vread(self.initial_process.dirbase, get_version);
        let mut major: u8 = 0;
        let mut minor: u8 = 0;

        // Find writes to rcx +4 and +8 -- those are our major and minor versions
        for i in 0..240 {
            let firstlong = byteorder::LittleEndian::read_u32(&buf[i..]);
            if major == 0 && minor == 0 {
                if firstlong == 0x441c748 {
                    return byteorder::LittleEndian::read_u16(&buf[i + 4..]) * 100
                        + (buf[i + 5] & 0xfu8) as u16;
                }
            }
            if major == 0 && firstlong & 0xfffff == 0x441c7 {
                major = buf[i + 3];
            }
            if minor == 0 && firstlong & 0xfffff == 0x841c7 {
                minor = buf[i + 3];
            }
        }
        if minor >= 100 {
            minor = 0;
        }
        return major as u16 * 100 + minor as u16;
    }

    fn get_nt_build(&self) -> u32 {
        let get_version = match self.find_kernel_export("RtlGetVersion") {
            Some(0) | None => return 0,
            Some(addr) => addr,
        };
        let buf: [u8; 0x100] = self.vread(self.initial_process.dirbase, get_version);

        /* Find writes to rcx +12 -- that's where the version number is stored. These instructions are not on XP, but that is simply irrelevant. */
        for i in 0..240 {
            let firstlong = byteorder::LittleEndian::read_u32(&buf[i..]);
            let val = firstlong & 0xffffff;
            if val == 0x0c41c7 || val == 0x05c01b {
                return byteorder::LittleEndian::read_u32(&buf[i + 3..]);
            }
        }
        return 0;
    }

    // finding ntoskrnl.exe
    fn find_nt_kernel(&mut self, kernel_entry: u64) -> Option<(u64, HashMap<String, WinExport>)> {
        let mut mask = 0xfffffu64;
        while mask >= 0xfff {
            let mut i = (kernel_entry & !0x1fffff) + 0x20000000;
            while i > kernel_entry - 0x20000000 {
                for o in 0..0x20 {
                    let buf: [u8; 0x10000] =
                        self.vread(self.initial_process.dirbase, i + 0x10000 * o);
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
                        let mut pool_code: bool = false;
                        for u in 0..0x1000u64 {
                            let pu_offset = &buf[p as usize + u as usize..];
                            if pu_offset.len() < 8 {
                                continue;
                            }
                            kdbg = kdbg
                                || byteorder::LittleEndian::read_u64(pu_offset)
                                    == 0x4742444b54494e49;
                            pool_code = pool_code
                                || byteorder::LittleEndian::read_u64(pu_offset)
                                    == 0x45444f434c4f4f50;
                            if kdbg && pool_code {
                                let nt_kernel = i + 0x10000 * o + p;
                                match self
                                    .get_module_exports(self.initial_process.dirbase, nt_kernel)
                                {
                                    Err(e) => {
                                        println!(
                                            "Failed to get module exports for the kernel at 0x{:x}: {}",
                                            nt_kernel,
                                            e,
                                        );
                                        continue;
                                    }
                                    Ok(kexports) => {
                                        return Some((nt_kernel, kexports));
                                    }
                                }
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

    pub fn get_nt_header(&self, dirbase: u64, address: u64) -> Option<(NtHeaders, u64)> {
        let dos_header: IMAGE_DOS_HEADER = self.vread(dirbase, address);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }

        let nt_header_addr = address + dos_header.e_lfanew as u64;
        let nt_header: IMAGE_NT_HEADERS = self.vread(dirbase, nt_header_addr);
        if nt_header.Signature != IMAGE_NT_HEADERS_SIGNATURE {
            return None;
        }

        let magic = nt_header.OptionalHeader.Magic;
        if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            Some((NtHeaders::Bit64(nt_header), nt_header_addr))
        } else if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
            Some((
                NtHeaders::Bit32({
                    let nth: IMAGE_NT_HEADERS32 = self.vread(dirbase, nt_header_addr);
                    nth
                }),
                nt_header_addr,
            ))
        } else {
            None
        }
    }

    // CheckLowStub -- It contains PML4 (kernel DirectoryTableBase) and Kernel EP.
    fn find_initial_process(&self) -> Option<(u64, u64)> {
        for i in 0..10 {
            let buf: [u8; 0x10000] = self.read(i * 0x10000);
            let mut o: usize = 0;
            loop {
                if o >= 0x10000 {
                    break;
                }
                let ulonglong = byteorder::LittleEndian::read_u64(&buf[o..]);
                // START BYTES
                if 0x00000001000600E9 ^ (0xffffffffffff00ff & ulonglong) != 0 {
                    o += 0x1000;
                    continue;
                }
                // Kernel vaEntry
                let x70_ulonglong: u64 = byteorder::LittleEndian::read_u64(&buf[o + 0x70..]);
                if 0xfffff80000000000 ^ (0xfffff80000000000 & x70_ulonglong) != 0 {
                    o += 0x1000;
                    continue;
                }
                // PML4 (Kernel DTB)
                let xa0_ulonglong: u64 = byteorder::LittleEndian::read_u64(&buf[o + 0xa0..]);
                if 0xffffff0000000fff & xa0_ulonglong != 0 {
                    o += 0x1000;
                    continue;
                }
                // Page Map Level 4
                let pml4 = xa0_ulonglong;
                let kernel_entry = x70_ulonglong;
                return Some((pml4, kernel_entry));
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
            maps_start: largest_map.start() as u64,
            maps_size: largest_map.size() as u64,
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
        let res = match unsafe { vmread_bind(fd, &mut self.process) } {
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
}
