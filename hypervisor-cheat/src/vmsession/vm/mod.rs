use crate::vmsession::win::Offsets;
use std::collections::HashMap;

pub mod binding_init;
pub mod binding_porcelain;
pub mod binding_read;
pub mod binding_search;
pub mod nativebinding;

const PAGE_OFFSET_SIZE: u64 = 12;
const PMASK: u64 = (!0xfu64 << 8) & 0xfffffffffu64;

const VMREAD_IOCTL_MAGIC: u8 = 0x42;

ioctl_readwrite!(vmread_bind, VMREAD_IOCTL_MAGIC, 0, ProcessData);

pub enum NtHeaders {
    Bit64(pelite::pe64::image::IMAGE_NT_HEADERS),
    Bit32(pelite::pe32::image::IMAGE_NT_HEADERS),
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ProcessData {
    pub mapsStart: u64,
    pub mapsSize: u64,
    pub pid: i32,
}

#[derive(Clone, Default)]
pub struct WinExport {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct WinModule {
    pub baseAddress: u64,
    pub entryPoint: u64,
    pub sizeOfModule: u64,
    pub name: String,
    pub loadCount: u16,
}

#[derive(Debug, Clone)]
pub struct WinProc {
    pub eprocessVA: u64,
    pub eprocessAddr: u64,
    pub dirBase: u64,
    pub pid: u64,
    pub name: String,
}

pub struct VMBinding {
    pub ntKernelEntry: u64,
    pub ntVersion: u16,
    pub ntBuild: u32,
    pub ntKernelModulebase: u64,
    pub initialProcess: WinProc,
    pub cachedNtExports: HashMap<String, WinExport>,
    pub process: ProcessData,
    pub offsets: Option<Offsets>,
}
