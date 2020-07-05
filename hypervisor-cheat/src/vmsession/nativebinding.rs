use crate::vmsession::win::heap_entry::HEAP;
use crate::vmsession::win::peb::FullPEB;
use crate::vmsession::win::Offsets;
use byteorder::ByteOrder;
use itertools::Itertools;
use memmem::Searcher;
use nix::fcntl::open;
use nix::unistd::close;
use pelite::image::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER,
    IMAGE_NT_HEADERS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use pelite::pe32::image::IMAGE_NT_HEADERS32;
use pelite::pe64::image::{IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER};
use proc_maps::{MapRange, Pid};
use regex::bytes::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::iter::FromIterator;
use std::mem::size_of;
use std::process::Stdio;
use vmread::WinExport;
use vmread_sys::{ProcessData, WinCtx, WinExportList, WinOffsets, WinProc, IMAGE_DATA_DIRECTORY};

pub struct VMBinding {
    kernelEntry: u64,
    cachedKernelExports: HashMap<String, WinExport>,
    ctx: WinCtx,
    offsets: Option<Offsets>,
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

fn str_chunks<'a>(s: &'a str, n: usize) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    Box::new(
        s.as_bytes()
            .chunks(n)
            .map(|c| std::str::from_utf8(c).unwrap()),
    )
}

impl VMBinding {
    pub fn list_kernel_procs(&self) {
        for (sname, rec) in self.cachedKernelExports.iter() {
            println!("KernelExport @ 0x{:x}\t{}", rec.address, sname);
        }
    }

    pub fn find_kernel_proc(&self, name: &str) -> Option<u64> {
        match self.cachedKernelExports.get(name) {
            None => None,
            Some(export) => Some(export.address),
        }
    }

    pub fn new() -> Option<VMBinding> {
        let mut binding = VMBinding {
            offsets: None,
            cachedKernelExports: HashMap::new(),
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
                match binding.find_nt_kernel(kernel_entry) {
                    Some((ntk, kexports)) => {
                        println!("NTKernel ModuleBase @ 0x{:x}", ntk);
                        println!("Found {} kernel exports", kexports.len());
                        // Less than ideal but we do it once. Better than having optionals or mutexes everywhere
                        for (k, v) in kexports.iter() {
                            binding.cachedKernelExports.insert(k.clone(), v.clone());
                        }
                    }
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

        let initProcAddr = match binding.find_kernel_proc("PsInitialSystemProcess") {
            Some(0) | None => return None,
            Some(addr) => addr,
        };
        binding.ctx.initialProcess.process =
            binding.vread(binding.ctx.initialProcess.dirBase, initProcAddr);
        binding.ctx.initialProcess.physProcess = binding.native_translate(
            binding.ctx.initialProcess.dirBase,
            binding.ctx.initialProcess.process,
        );

        binding.ctx.ntVersion = binding.get_nt_version();
        binding.ctx.ntBuild = binding.get_nt_build();
        binding.offsets = Offsets::GetOffsets(binding.ctx.ntVersion, binding.ctx.ntBuild);
        if binding.offsets.is_none() {
            return None;
        };

        Some(binding)
    }

    fn get_nt_version(&self) -> u16 {
        let getVersion = match self.find_kernel_proc("RtlGetVersion") {
            Some(0) | None => return 0,
            Some(addr) => addr,
        };

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
        let getVersion = match self.find_kernel_proc("RtlGetVersion") {
            Some(0) | None => return 0,
            Some(addr) => addr,
        };
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

    pub fn get_nt_header(&self, dirbase: u64, address: u64) -> Option<(NtHeaders, u64)> {
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
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => Some((NtHeaders::Bit64(ntHeader), ntHeaderAddr)),
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => Some((
                NtHeaders::Bit32({
                    let nth: IMAGE_NT_HEADERS32 = self.vread(dirbase, ntHeaderAddr);
                    nth
                }),
                ntHeaderAddr,
            )),
            _ => None,
        }
    }

    pub fn get_module_exports(
        &self,
        dirbase: u64,
        moduleBase: u64,
    ) -> Result<HashMap<String, WinExport>, String> {
        let mut hmap = HashMap::new();

        let ntHeadersAddr = match self.get_nt_header(dirbase, moduleBase) {
            Some((_, addr)) => addr,
            _ => return Err("couldn't get the NT header".to_string()),
        };

        let dataDirOffset =
            size_of::<IMAGE_FILE_HEADER>() + size_of::<u32>() + size_of::<IMAGE_OPTIONAL_HEADER>()
                - size_of::<[IMAGE_DATA_DIRECTORY; 0]>();
        let exportTable: IMAGE_DATA_DIRECTORY =
            self.vread(dirbase, ntHeadersAddr + dataDirOffset as u64);
        if exportTable.Size > 0x7fffffu32 {
            return Err(format!(
                "table size of 0x{:x} is greater than 0x7fffff",
                exportTable.Size
            ));
        }
        if exportTable.VirtualAddress as u64 == moduleBase {
            return Err(format!(
                "VirtualAddress of exportTable equals the moduleBase 0x{:x}",
                moduleBase
            ));
        }
        if exportTable.Size < size_of::<IMAGE_EXPORT_DIRECTORY>() as u32 {
            return Err(format!(
                "ExportTable size ({:x}) is smaller than size of IMAGE_EXPORT_DIRECTORY",
                exportTable.Size,
            ));
        }

        let bufBegin = moduleBase + exportTable.VirtualAddress as u64;
        let exportDir: IMAGE_EXPORT_DIRECTORY = self.vread(dirbase, bufBegin);
        if exportDir.NumberOfNames == 0 || exportDir.AddressOfNames == 0 {
            return Err(format!(
                "IMAGE_EXPORT_DIRECTORY->NumberOfNames or AddressOfNames is 0"
            ));
        }

        let namesPtr: u64 = moduleBase + exportDir.AddressOfNames as u64;
        // if exportDir.AddressOfNames as usize - exportOffset
        //     + exportDir.NumberOfNames as usize * size_of::<u32>()
        //     > exportTable.Size as usize
        // {
        //     return Err(format!("Offset issues for names"));
        // }

        let ordinalsPtr: u64 = moduleBase + exportDir.AddressOfNameOrdinals as u64;
        // if exportDir.AddressOfNameOrdinals as usize - exportOffset
        //     + exportDir.NumberOfNames as usize * size_of::<u16>()
        //     > exportTable.Size as usize
        // {
        //     return Err(format!("Offset issues for ordinals"));
        // }

        let fnPtr: u64 = moduleBase + exportDir.AddressOfFunctions as u64;
        // if exportDir.AddressOfFunctions as usize - exportOffset
        //     + exportDir.NumberOfFunctions as usize * size_of::<u32>()
        //     > exportTable.Size as usize
        // {
        //     return Err(format!("Offset issues for functions"));
        // }

        for i in 0..exportDir.NumberOfNames as u64 {
            let namePos = namesPtr + i * size_of::<u32>() as u64;
            let ordinalPos = ordinalsPtr + i * size_of::<u16>() as u64;

            let namePtr: u32 = self.vread(dirbase, namePos);
            let name = self.read_cstring_from_physical_mem(
                self.native_translate(dirbase, moduleBase + namePtr as u64),
                Some(128),
            );

            let ordinal: u16 = self.vread(dirbase, ordinalPos);
            let fnPos = fnPtr + ordinal as u64 * size_of::<u32>() as u64;
            let func: u32 = self.vread(dirbase, fnPos);

            hmap.insert(
                name.clone(),
                WinExport {
                    name: name.clone(),
                    address: func as u64 + moduleBase,
                },
            );
        }
        return Ok(hmap);
    }

    fn find_nt_kernel(&mut self, kernelEntry: u64) -> Option<(u64, HashMap<String, WinExport>)> {
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
                                match self
                                    .get_module_exports(self.ctx.initialProcess.dirBase, ntKernel)
                                {
                                    Err(e) => {
                                        println!(
                                            "Failed to get module exports for the kernel at 0x{:x}: {}",
                                            ntKernel,
                                            e,
                                        );
                                        continue;
                                    }
                                    Ok(kexports) => {
                                        return Some((ntKernel, kexports));
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

    pub fn read_physical<T>(&self, address: u64) -> T {
        let mut ret: T = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        unsafe {
            vmread_sys::MemRead(
                &self.ctx.process,
                &mut ret as *mut T as u64,
                address,
                size_of::<T>() as u64,
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

    fn _getvmem(&self, dirbase: Option<u64>, local_begin: u64, begin: u64, end: u64) -> i64 {
        let len = end - begin;
        if len <= 8 {
            let data = match dirbase {
                Some(d) => unsafe { vmread_sys::VMemReadU64(&self.ctx.process, d, begin) },
                None => unsafe { vmread_sys::MemReadU64(&self.ctx.process, begin) },
            };
            let bit64: [u8; 8] = data.to_le_bytes();
            let slice =
                unsafe { std::slice::from_raw_parts_mut(local_begin as *mut u8, len as usize) };
            for i in 0..len {
                slice[i as usize] = bit64[i as usize];
            }
            return len as i64;
        }
        if len <= 0 {
            return -2;
        }
        let mut res: i64 = match dirbase {
            Some(d) => unsafe {
                vmread_sys::VMemRead(&self.ctx.process, d, local_begin, begin, len)
            },
            None => unsafe { vmread_sys::MemRead(&self.ctx.process, local_begin, begin, len) },
        };
        if res < 0 {
            let chunksize = len / 2;
            res = self._getvmem(dirbase, local_begin, begin, begin + chunksize);
            if res < 0 {
                return res;
            }
            res = self._getvmem(dirbase, local_begin + chunksize, begin + chunksize, end);
        }
        return res;
    }

    pub fn getvmem(&self, dirbase: Option<u64>, begin: u64, end: u64) -> Option<Box<[u8]>> {
        let len = end - begin;
        let buffer: Box<[std::mem::MaybeUninit<u8>]> = Box::new_uninit_slice(len as usize);
        let buffer_begin = buffer.as_ptr() as u64;
        if self._getvmem(dirbase, buffer_begin, begin, end) > 0 {
            return Some(unsafe { buffer.assume_init() });
        }
        return None;
    }

    pub fn read_cstring_from_physical_mem(&self, addr: u64, maxlen: Option<u64>) -> String {
        let mut out: Vec<u8> = Vec::new();
        let mut len = 0;
        loop {
            let val: u8 = self.read_physical(addr + len);
            if val == 0 {
                break;
            }
            out.push(val);
            len += 1;
            if let Some(max) = maxlen {
                if len >= max {
                    break;
                }
            }
        }
        std::string::String::from_iter(out.iter().map(|b| *b as char))
    }

    pub fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        memmem::TwoWaySearcher::new(needle).search_in(haystack)
    }

    pub fn pmemmem(haystack: &[u8], needle_string: &str) -> Result<Vec<usize>, String> {
        let mut restr = String::from("(?-u:");
        for ch in str_chunks(&needle_string, 2) {
            let chunk: Vec<char> = ch.chars().collect();
            if chunk.len() != 2 {
                return Err("input needle_string without even length".to_string());
            }
            let (first, second) = (*chunk.get(0).unwrap(), *chunk.get(1).unwrap());
            let qmPresent = first == '?' || second == '?';
            let wildcard = first == '?' && second == '?';
            if qmPresent && !wildcard {
                return Err("needle_string has wildcards of uneven length".to_string());
            }
            if wildcard {
                restr += ".";
            } else {
                restr += "\\x";
                restr += ch;
            }
        }
        restr += ")";

        let re: Regex = match Regex::new(&restr) {
            Ok(r) => r,
            Err(e) => return Err(e.to_string()),
        };
        Ok(re.find_iter(haystack).map(|f| f.start()).collect())
    }

    pub fn memmemn(haystack: &[u8], needle: &[u8], max_opt: Option<usize>) -> Vec<usize> {
        match Self::memmem(haystack, needle) {
            None => vec![],
            Some(offset) => {
                let res = vec![offset];
                match max_opt {
                    Some(1) => res,
                    other => {
                        let updatedn = match other {
                            Some(x) => Some(x - 1),
                            None => None,
                        };
                        let needle_end = offset + needle.len();
                        let mut downstream_results =
                            Self::memmemn(&haystack[needle_end..], needle, updatedn);
                        for res in downstream_results.iter_mut() {
                            *res += needle_end;
                        }
                        let mut res = vec![offset];
                        res.append(&mut downstream_results);
                        res
                    }
                }
            }
        }
    }

    pub fn get_full_peb(&self, dirbase: u64, physProcess: u64) -> FullPEB {
        let peb_offset_from_eprocess = self.offsets.unwrap().peb as u64;
        let ptr: u64 = self.read_physical(physProcess + peb_offset_from_eprocess);
        self.vread(dirbase, ptr)
    }

    pub fn get_process_heap(&self, dirbase: u64, physProcess: u64) -> Vec<HEAP> {
        let peb = self.get_full_peb(dirbase, physProcess);
        // let primary_heap = peb.ProcessHeap;
        // println!("PEB->ProcessHeap = 0x{:x}", primary_heap);
        // println!("PEB->ProcessHeaps = 0x{:x}", peb.ProcessHeaps);
        let mut res: Vec<HEAP> = Vec::new();
        let heaps_array_begin: u64 = peb.ProcessHeaps;
        for heap_index in 0..peb.NumberOfHeaps {
            let offset = heap_index as usize * size_of::<u64>();
            let heapptr = heaps_array_begin + offset as u64;
            // println!("&PEB->ProcessHeaps[{}] = 0x{:x}", heap_index, heapptr);
            let heap: HEAP = self.vread(dirbase, heapptr);
            // println!("PEB->ProcessHeaps[{}] = ", heap_index, heapptr);
            res.push(heap);
        }
        return res;
    }
}
