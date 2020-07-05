use crate::vmsession::win::Offsets;
use std::collections::HashMap;
use vmread::WinExport;
use vmread_sys::{ProcessData, WinCtx};

pub mod binding_init;
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

pub struct VMBinding {
    kernelEntry: u64,
    cachedKernelExports: HashMap<String, WinExport>,
    ctx: WinCtx,
    offsets: Option<Offsets>,
}
