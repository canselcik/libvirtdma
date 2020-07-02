use crate::vmsession::VMSession;
use std::marker::PhantomData;
use vmread::WinProcess;

pub struct PtrForeign<T> {
    ptr: u64,
    vm: std::sync::Arc<VMSession>,
    proc: Option<WinProcess>,
    typ: PhantomData<*const T>,
}

impl<T> PtrForeign<T> {
    pub fn new(ptr: u64, vm: std::sync::Arc<VMSession>, proc: Option<WinProcess>) -> PtrForeign<T> {
        return PtrForeign {
            ptr,
            vm,
            proc,
            typ: PhantomData,
        };
    }

    pub fn read(&self) -> T {
        match &self.proc {
            Some(proc) => proc.read(&self.vm.native_ctx, self.ptr),
            None => self.vm.ctx.read(self.ptr),
        }
    }
}
