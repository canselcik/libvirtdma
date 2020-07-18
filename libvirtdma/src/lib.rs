#![feature(const_int_pow)]
#![feature(new_uninit)]

#[macro_use]
extern crate c2rust_bitfields;

#[macro_use]
extern crate nix;

pub mod proc_kernelinfo;

pub mod vm;
use crate::vm::VMBinding;
pub use vm::binding_disasm::print_disasm as disasm;

pub mod win;

pub struct TypedRemotePtr<T> {
    ptr: RemotePtr,
    typ: std::marker::PhantomData<*const T>,
}

impl<T> TypedRemotePtr<T> {
    pub fn virt(addr: u64, dtb: u64) -> Self {
        Self {
            ptr: RemotePtr::virt(addr, dtb),
            typ: Default::default(),
        }
    }

    pub fn phys(addr: u64) -> Self {
        Self {
            ptr: RemotePtr::phys(addr),
            typ: Default::default(),
        }
    }

    pub fn read(&self, vm: &VMBinding, offset: i64) -> T {
        self.ptr.read(vm, offset)
    }

    pub fn vread(&self, vm: &VMBinding, dtb: u64, offset: i64) -> T {
        self.ptr.vread(vm, dtb, offset)
    }

    pub fn readvec(&self, vm: &VMBinding, offset: i64, len: Option<u64>) -> Box<[u8]> {
        let len_to_read = match len {
            Some(l) => l,
            None => std::mem::size_of::<T>().wrapping_sub(offset as usize) as u64,
        };
        let offseted = self.ptr.addr.wrapping_add(offset as u64);
        vm.readvec(offseted, len_to_read)
    }

    pub fn vreadvec(&self, vm: &VMBinding, dtb: u64, offset: i64, len: Option<u64>) -> Box<[u8]> {
        let len_to_read = match len {
            Some(l) => l,
            None => std::mem::size_of::<T>().wrapping_sub(offset as usize) as u64,
        };
        let offseted = self.ptr.addr.wrapping_add(offset as u64);
        vm.vreadvec(dtb, offseted, len_to_read)
    }
}

impl<T> std::fmt::Debug for TypedRemotePtr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ptr.print(f)
    }
}
impl<T> std::fmt::Display for TypedRemotePtr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ptr.print(f)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RemotePtr {
    addr: u64,
    dtb: Option<u64>,
}

impl RemotePtr {
    fn new(addr: u64, dtb: Option<u64>) -> Self {
        Self { addr, dtb }
    }

    pub fn virt(addr: u64, dtb: u64) -> Self {
        Self::new(addr, Some(dtb))
    }

    pub fn phys(addr: u64) -> Self {
        Self::new(addr, None)
    }

    pub fn read<T>(&self, vm: &VMBinding, offset: i64) -> T {
        let offseted = self.addr.wrapping_add(offset as u64);
        vm.read(offseted)
    }

    pub fn vread<T>(&self, vm: &VMBinding, dtb: u64, offset: i64) -> T {
        let offseted = self.addr.wrapping_add(offset as u64);
        vm.vread(dtb, offseted)
    }

    pub fn readvec(&self, vm: &VMBinding, offset: i64, len: u64) -> Box<[u8]> {
        let offseted = self.addr.wrapping_add(offset as u64);
        vm.readvec(offseted, len)
    }

    pub fn vreadvec(&self, vm: &VMBinding, dtb: u64, offset: i64, len: u64) -> Box<[u8]> {
        let offseted = self.addr.wrapping_add(offset as u64);
        vm.vreadvec(dtb, offseted, len)
    }

    fn print(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:0>16x}", self.addr)
    }

    #[inline(always)]
    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn with_offset(&self, offset: i64) -> Self {
        Self {
            dtb: self.dtb.clone(),
            addr: self.addr.wrapping_add(offset as u64),
        }
    }
}

impl std::fmt::Debug for RemotePtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.print(f)
    }
}
impl std::fmt::Display for RemotePtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.print(f)
    }
}
