use crate::vmsession::vm::{VMBinding, PAGE_OFFSET_SIZE, PMASK};
use std::iter::FromIterator;
use std::mem::size_of;

impl VMBinding {
    pub fn vread<T>(&self, dirbase: u64, address: u64) -> T {
        self.read_physical(self.native_translate(dirbase, address))
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
}
