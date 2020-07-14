use crate::win::Offsets;
use std::cell::UnsafeCell;
use std::collections::HashMap;

pub mod binding_core;
pub mod binding_disasm;
pub mod binding_init;
pub mod binding_porcelain;
pub mod binding_rw;
pub mod binding_search;
pub mod nativebinding;

const PAGE_OFFSET_SIZE: u64 = 12;
const PMASK: u64 = (!0xfu64 << 8) & 0xfffffffffu64;
const KFIXC: u64 = 0x80000000;
const KFIXO: u64 = 0x80000000;

const VMREAD_IOCTL_MAGIC: u8 = 0x42;

ioctl_readwrite!(vmread_bind, VMREAD_IOCTL_MAGIC, 0, ProcessData);

pub enum NtHeaders {
    Bit64(pelite::pe64::image::IMAGE_NT_HEADERS),
    Bit32(pelite::pe32::image::IMAGE_NT_HEADERS),
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ProcessData {
    pub maps_start: u64,
    pub maps_size: u64,
    pub pid: i32,
}

#[derive(Clone, Default)]
pub struct WinExport {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct WinModule {
    pub base_address: u64,
    pub entry_point: u64,
    pub size_of_module: u64,
    pub name: String,
    pub load_count: u16,
}

#[derive(Debug, Clone)]
pub struct WinProc {
    pub eprocess_va: u64,
    pub eprocess_addr: u64,
    pub dirbase: u64,
    pub pid: u64,
    pub name: String,
}

pub struct VMBinding {
    pub nt_kernel_entry: u64,
    pub nt_version: u16,
    pub nt_build: u32,
    pub nt_kernel_modulebase: u64,
    pub initial_process: WinProc,
    pub cached_nt_exports: HashMap<String, WinExport>,
    pub process: UnsafeCell<ProcessData>,
    pub offsets: Option<Offsets>,
}
