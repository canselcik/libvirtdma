use crate::vm::{VMBinding, PAGE_OFFSET_SIZE, PMASK};
use std::iter::FromIterator;
use std::mem::{size_of, MaybeUninit};
use std::vec::Vec;

macro_rules! min {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => {{
        let y = min!($($z),*);
        if $x < y {
            $x
        } else {
            y
        }
    }}
}

const STEP_SIZE: u64 = 2u64.pow(PAGE_OFFSET_SIZE as u32);

impl VMBinding {
    pub fn read<T>(&self, address: u64) -> T {
        let mut ret: MaybeUninit<T> = std::mem::MaybeUninit::uninit();
        self.memread(ret.as_mut_ptr() as u64, address, size_of::<T>() as u64);
        unsafe { ret.assume_init() }
    }

    pub fn readvec(&self, address: u64, len: u64) -> Box<[u8]> {
        let mut ret: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(len as usize);
        let ptr = ret.as_mut_ptr() as u64;
        self.memread(ptr, address, len);
        unsafe { ret.assume_init() }
    }

    fn _vread(&self, dirbase: u64, address: u64, localbuffer_begin: u64, len: u64) {
        if address >> PAGE_OFFSET_SIZE == (address + len) >> PAGE_OFFSET_SIZE {
            self.memread(
                localbuffer_begin,
                self.native_translate(dirbase, address),
                len,
            );
        } else {
            let mut cursor: u64 = 0;
            while cursor < len {
                let read = min!(STEP_SIZE, len - cursor);
                self.memread(
                    localbuffer_begin + cursor,
                    self.native_translate(dirbase, address + cursor),
                    read,
                );
                cursor += read;
            }
        }
    }

    pub fn vread<T>(&self, dirbase: u64, address: u64) -> T {
        let mut ret: MaybeUninit<T> = std::mem::MaybeUninit::uninit();
        self._vread(
            dirbase,
            address,
            ret.as_mut_ptr() as u64,
            size_of::<T>() as u64,
        );
        unsafe { ret.assume_init() }
    }

    pub fn vreadvec(&self, dirbase: u64, address: u64, len: u64) -> Box<[u8]> {
        let mut ret = Box::new_uninit_slice(len as usize);
        self._vread(dirbase, address, ret.as_mut_ptr() as u64, len);
        unsafe { ret.assume_init() }
    }

    pub fn native_translate(&self, dirbase: u64, address: u64) -> u64 {
        let dir_base = dirbase & !0xfu64;
        let page_offset = address & !(!0u64 << PAGE_OFFSET_SIZE);
        let pte = (address >> PAGE_OFFSET_SIZE) & 0x1ffu64;
        let pt = (address >> 21) & 0x1ffu64;
        let pd = (address >> 30) & 0x1ffu64;
        let pdp = (address >> 39) & 0x1ffu64;

        let pdpe: u64 = self.read(dir_base + 8 * pdp);
        if !pdpe & 1u64 != 0 {
            return 0;
        }

        let pde: u64 = self.read((pdpe & PMASK) + 8 * pd);
        if !pde & 1u64 != 0 {
            return 0;
        }

        // 1GB large page, use pde's 12-34 bits
        if pde & 0x80u64 != 0 {
            return (pde & (!0u64 << 42 >> PAGE_OFFSET_SIZE)) + (address & !(!0u64 << 30));
        }

        let pte_addr: u64 = self.read((pde & PMASK) + 8 * pt);
        if !pte_addr & 1u64 != 0 {
            return 0;
        }

        // 2MB large page
        if pte_addr & 0x80u64 != 0 {
            return (pte_addr & PMASK) + (address & !(!0u64 << 21));
        }

        let resolved_addr: u64 = self.read::<u64>((pte_addr & PMASK) + 8 * pte) & PMASK;
        if resolved_addr == 0 {
            return 0;
        }
        return resolved_addr + page_offset;
    }

    pub fn read_cstring_from_physical_mem(&self, addr: u64, maxlen: Option<u64>) -> String {
        let mut out: Vec<u8> = Vec::new();
        let mut len = 0;
        loop {
            let val: u8 = self.read(addr + len);
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

    pub fn vwrite(&self, dirbase: u64, address: u64, payload: &[u8]) {
        self._vwrite(
            dirbase,
            address,
            payload.as_ptr() as u64,
            payload.len() as u64,
        );
    }

    fn _vwrite(&self, dirbase: u64, address: u64, localbuffer_begin: u64, len: u64) {
        if address >> PAGE_OFFSET_SIZE == (address + len) >> PAGE_OFFSET_SIZE {
            self.memwrite(
                localbuffer_begin,
                self.native_translate(dirbase, address),
                len,
            );
        } else {
            let mut cursor: u64 = 0;
            while cursor < len {
                let write = min!(STEP_SIZE, len - cursor);
                self.memwrite(
                    localbuffer_begin + cursor,
                    self.native_translate(dirbase, address + cursor),
                    write,
                );
                cursor += write;
            }
        }
    }

    pub fn write(&self, address: u64, payload: &[u8]) -> bool {
        self.memwrite(payload.as_ptr() as u64, address, payload.len() as u64)
    }
}
