use byteorder::ByteOrder;
use itertools::Itertools;
use nix::fcntl::open;
use nix::unistd::close;
use pelite::image::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY,
    IMAGE_NT_HEADERS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use pelite::pe32::image::IMAGE_NT_HEADERS32;
use pelite::pe64::image::IMAGE_NT_HEADERS;
use proc_maps::{MapRange, Pid};
use regex::bytes::Regex;
use std::io::Read;
use std::process::Stdio;
use vmread_sys::{ProcessData, WinCtx, WinExportList, WinOffsets, WinProc};

pub struct VMBinding {
    kernelEntry: u64,
    ctx: WinCtx,
}

const PAGE_OFFSET_SIZE: u64 = 12;
const PMASK: u64 = (!0xfu64 << 8) & 0xfffffffffu64;

const VMREAD_IOCTL_MAGIC: u8 = 0x42;

ioctl_readwrite!(vmread_bind, VMREAD_IOCTL_MAGIC, 0, ProcessData);

pub enum NtHeaders {
    Bit64(pelite::pe64::image::IMAGE_NT_HEADERS),
    Bit32(pelite::pe32::image::IMAGE_NT_HEADERS),
}

fn empty_winctx_with_process_data(proc_data: ProcessData) -> WinCtx {
    WinCtx {
        process: proc_data,
        offsets: WinOffsets {
            apl: 0,
            session: 0,
            stackCount: 0,
            imageFileName: 0,
            dirBase: 0,
            peb: 0,
            peb32: 0,
            threadListHead: 0,
            threadListEntry: 0,
            teb: 0,
        },
        ntKernel: 0,
        ntVersion: 0,
        ntBuild: 0,
        ntExports: WinExportList {
            list: std::ptr::null_mut(),
            size: 0,
        },
        initialProcess: WinProc {
            process: 0,
            physProcess: 0,
            dirBase: 0,
            pid: 0,
            name: std::ptr::null_mut(),
        },
    }
}

impl VMBinding {
    pub fn new() -> Option<VMBinding> {
        let mut binding = VMBinding {
            kernelEntry: 0,
            ctx: empty_winctx_with_process_data(match Self::create_process_data() {
                None => return None,
                Some(s) => s,
            }),
        };
        if !binding.init_device() {
            return None;
        }
        match binding.find_initial_process() {
            Some((pml4, kernel_entry)) => {
                binding.ctx.initialProcess.dirBase = pml4;
                binding.kernelEntry = kernel_entry;
                binding.ctx.ntKernel = match binding.find_nt_kernel(kernel_entry) {
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

        let initProcAddr = unsafe {
            vmread_sys::FindProcAddress(
                binding.ctx.ntExports,
                std::ffi::CString::new("PsInitialSystemProcess")
                    .unwrap()
                    .as_ptr(),
            )
        };
        if initProcAddr == 0 {
            return None;
        }

        binding.ctx.initialProcess.process =
            binding.vread(binding.ctx.initialProcess.dirBase, initProcAddr);
        binding.ctx.initialProcess.physProcess = binding.native_translate(
            binding.ctx.initialProcess.dirBase,
            binding.ctx.initialProcess.process,
        );

        binding.ctx.ntVersion = binding.get_nt_version();
        binding.ctx.ntBuild = binding.get_nt_build();

        println!(
            "NT VERSION: {} NT BUILD: {}",
            binding.ctx.ntVersion, binding.ctx.ntBuild
        );
        // if (SetupOffsets(ctx))
        //   return 9;

        Some(binding)
    }

    fn get_nt_version(&self) -> u16 {
        let getVersion = unsafe {
            vmread_sys::FindProcAddress(
                self.ctx.ntExports,
                std::ffi::CString::new("RtlGetVersion").unwrap().as_ptr(),
            )
        };
        if getVersion == 0 {
            return 0;
        }

        let buf: [u8; 0x100] = self.vread(self.ctx.initialProcess.dirBase, getVersion);
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
        let getVersion = unsafe {
            vmread_sys::FindProcAddress(
                self.ctx.ntExports,
                std::ffi::CString::new("RtlGetVersion").unwrap().as_ptr(),
            )
        };
        if getVersion == 0 {
            return 0;
        }
        let buf: [u8; 0x100] = self.vread(self.ctx.initialProcess.dirBase, getVersion);

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

    pub fn vread<T>(&self, dirbase: u64, address: u64) -> T {
        self.read_physical(self.native_translate(dirbase, address))
    }

    pub fn free_export_list(&self) {
        unsafe { vmread_sys::FreeExportList(self.ctx.ntExports) };
    }

    pub fn genexports(&self, dirbase: u64, moduleBase: u64) -> Option<()> {
        let ntHeaders = match self.get_nt_header(dirbase, moduleBase) {
            Some(h) => h,
            _ => return None,
        };

        let dataDir = match ntHeaders {
            NtHeaders::Bit64(h64) => h64.OptionalHeader.DataDirectory,
            NtHeaders::Bit32(h32) => h32.OptionalHeader.DataDirectory,
        };

        let exportTable = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if exportTable.Size > 0x7fffffu32 {
            return None;
        }
        if exportTable.VirtualAddress as u64 == moduleBase {
            return None;
        }
        if exportTable.Size < std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>() as u32 {
            return None;
        }

        // TODO THIS THING

        return None;

        /*
               char* buf = (char*)malloc(exportTable->Size + 1);

               IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(void*)buf;
               if (VMemRead(&ctx->process, process->dirBase, (uint64_t)buf, moduleBase + exportTable->VirtualAddress, exportTable->Size) == -1) {
                   free(buf);
                   return 2;
               }
               buf[exportTable->Size] = 0;
               if (!exportDir->NumberOfNames || !exportDir->AddressOfNames) {
                   free(buf);
                   return 3;
               }

               uint32_t exportOffset = exportTable->VirtualAddress;

               uint32_t* names = (uint32_t*)(void*)(buf + exportDir->AddressOfNames - exportOffset);
               if (exportDir->AddressOfNames - exportOffset + exportDir->NumberOfNames * sizeof(uint32_t) > exportTable->Size) {
                   free(buf);
                   return 4;
               }
               uint16_t* ordinals = (uint16_t*)(void*)(buf + exportDir->AddressOfNameOrdinals - exportOffset);
               if (exportDir->AddressOfNameOrdinals - exportOffset + exportDir->NumberOfNames * sizeof(uint16_t) > exportTable->Size) {
                   free(buf);
                   return 5;
               }
               uint32_t* functions = (uint32_t*)(void*)(buf + exportDir->AddressOfFunctions - exportOffset);
               if (exportDir->AddressOfFunctions - exportOffset + exportDir->NumberOfFunctions * sizeof(uint32_t) > exportTable->Size) {
                   free(buf);
                   return 6;
               }

               outList->size = exportDir->NumberOfNames;
               outList->list = (WinExport*)malloc(sizeof(WinExport) * outList->size);

               size_t sz = 0;

               for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
                   if (names[i] > exportTable->Size + exportOffset || names[i] < exportOffset || ordinals[i] > exportDir->NumberOfNames)
                       continue;
                   outList->list[sz].name = strdup(buf + names[i] - exportOffset);
                   outList->list[sz].address = moduleBase + functions[ordinals[i]];
                   sz++;
               }

               outList->size = sz;
               free(buf);
               return 0;
           }



        */
    }

    pub fn get_nt_header(&self, dirbase: u64, address: u64) -> Option<NtHeaders> {
        let dosHeader: IMAGE_DOS_HEADER = self.vread(dirbase, address);
        if dosHeader.e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }

        let ntHeaderAddr = address + dosHeader.e_lfanew as u64;
        let ntHeader: IMAGE_NT_HEADERS = self.vread(dirbase, ntHeaderAddr);
        if ntHeader.Signature != IMAGE_NT_HEADERS_SIGNATURE {
            return None;
        }
        match ntHeader.OptionalHeader.Magic {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => Some(NtHeaders::Bit64(ntHeader)),
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => Some(NtHeaders::Bit32({
                let nth: IMAGE_NT_HEADERS32 = self.vread(dirbase, ntHeaderAddr);
                nth
            })),
            _ => None,
        }
    }

    fn find_nt_kernel(&mut self, kernelEntry: u64) -> Option<u64> {
        let mut mask = 0xfffffu64;
        while mask >= 0xfff {
            let mut i = (kernelEntry & !0x1fffff) + 0x20000000;
            while i > kernelEntry - 0x20000000 {
                for o in 0..0x20 {
                    let buf: [u8; 0x10000] =
                        self.vread(self.ctx.initialProcess.dirBase, i + 0x10000 * o);
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
                                let ntKernel = i + 0x10000 * o + p;
                                let export_list_result = unsafe {
                                    vmread_sys::GenerateExportList(
                                        &self.ctx as *const WinCtx,
                                        &self.ctx.initialProcess,
                                        ntKernel,
                                        &mut self.ctx.ntExports as *mut WinExportList,
                                    )
                                };
                                if export_list_result != 0 {
                                    // Maybe memleak here but normally doesn't get here
                                    break;
                                }
                                return Some(ntKernel);
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
                &self.ctx.process,
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
        let res = match unsafe { vmread_bind(fd, &mut self.ctx.process as *mut ProcessData) } {
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
