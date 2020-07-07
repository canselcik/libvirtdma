use crate::vm::{VMBinding, PAGE_OFFSET_SIZE, PMASK};
use std::iter::FromIterator;
use std::mem::size_of;

impl VMBinding {
    pub fn vread<T>(&self, dirbase: u64, address: u64) -> T {
        self.read(self.native_translate(dirbase, address))
    }

    pub fn vreadvec(&self, dirbase: u64, address: u64, len: u64) -> Option<Vec<u8>> {
        self.readvec(self.native_translate(dirbase, address), len)
    }

    pub fn read<T>(&self, address: u64) -> T {
        let mut ret: T = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        self.memread(&mut ret as *mut T as u64, address, size_of::<T>() as u64);
        ret
    }

    pub fn readvec(&self, address: u64, len: u64) -> Option<Vec<u8>> {
        let ret: Vec<u8> = Vec::with_capacity(len as usize);
        self.memread(ret.as_ptr() as u64, address, len);
        Some(ret)
    }

    pub fn native_translate(&self, dirbase: u64, address: u64) -> u64 {
        let dir_base = dirbase & !0xfu64;
        let page_offset = address & !(!0u64 << PAGE_OFFSET_SIZE);
        let pte = (address >> 12) & 0x1ffu64;
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
            return (pde & (!0u64 << 42 >> 12)) + (address & !(!0u64 << 30));
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
}
