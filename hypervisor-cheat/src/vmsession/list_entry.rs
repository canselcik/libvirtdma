use crate::vmsession::VMSession;
use vmread::{WinContext, WinProcess};
use vmread_sys::WinCtx;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListEntry {
    Flink: u64, // ptr to next
    Blink: u64, // ptr to prev
}

impl std::fmt::Debug for ListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ListEntry(fLink=0x{:x}, bLink=0x{:x})",
            self.Flink, self.Blink
        )
    }
}

impl ListEntry {
    pub fn getNextFromProcess<T>(&self, native_ctx: &WinCtx, proc: &WinProcess) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        Some(proc.read(native_ctx, self.Flink))
    }

    pub fn getPreviousFromProcess<T>(&self, native_ctx: &WinCtx, proc: &WinProcess) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        Some(proc.read(native_ctx, self.Blink))
    }

    pub fn getNextFromKernelInitialProcess<T>(&self, vm: &VMSession) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        Some(vm.read_physical(vm.native_ctx.initialProcess.dirBase + self.Flink))
    }

    pub fn getPreviousFromKernelInitialProcess<T>(&self, vm: &VMSession) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        Some(vm.read_physical(vm.native_ctx.initialProcess.dirBase + self.Blink))
    }

    pub fn getNextFromPhysicalMemory<T>(&self, ctx: &WinContext) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        ctx.read(self.Flink)
    }

    pub fn getPreviousFromPhysicalMemory<T>(&self, ctx: &WinContext) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        ctx.read(self.Blink)
    }
}
