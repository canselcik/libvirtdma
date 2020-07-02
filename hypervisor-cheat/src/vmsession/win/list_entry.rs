use crate::vmsession::VMSession;
use vmread::WinProcess;
use vmread_sys::{ProcessData, WinCtx};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SingleListEntry {
    Next: u64, // ptr to next
}

impl std::fmt::Debug for SingleListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SingleListEntry(next=0x{:x})", self.Next)
    }
}

impl SingleListEntry {
    pub fn getNextFromProcess<T>(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Next == 0 {
            return None;
        }
        Some(proc.read(native_ctx, self.Next - listEntryOffsetInTargetStruct))
    }

    pub fn getNextFromKernelInitialProcess<T>(
        &self,
        vm: &VMSession,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Next == 0 {
            return None;
        }
        Some(vm.read_physical(
            vm.native_ctx.initialProcess.dirBase + self.Next - listEntryOffsetInTargetStruct,
        ))
    }

    pub fn getNextWithDirbase<T>(
        &self,
        vm: &VMSession,
        dirbase: Option<u64>,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Next == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => unsafe {
                vmread_sys::VTranslate(
                    &vm.native_ctx.process as *const ProcessData,
                    d,
                    self.Next - listEntryOffsetInTargetStruct,
                )
            },
            None => self.Next - listEntryOffsetInTargetStruct,
        };
        Some(vm.read_physical(addr))
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListEntry {
    pub Flink: u64, // ptr to next
    pub Blink: u64, // ptr to prev
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
    pub fn getNextFromProcess<T>(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        Some(proc.read(native_ctx, self.Flink - listEntryOffsetInTargetStruct))
    }

    pub fn getNextFromKernelInitialProcess<T>(
        &self,
        vm: &VMSession,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        Some(vm.read_physical(
            vm.native_ctx.initialProcess.dirBase + self.Flink - listEntryOffsetInTargetStruct,
        ))
    }

    pub fn getNextWithDirbase<T>(
        &self,
        vm: &VMSession,
        dirbase: Option<u64>,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => unsafe {
                vmread_sys::VTranslate(
                    &vm.native_ctx.process as *const ProcessData,
                    d,
                    self.Flink - listEntryOffsetInTargetStruct,
                )
            },
            None => self.Flink - listEntryOffsetInTargetStruct,
        };
        Some(vm.read_physical(addr))
    }

    pub fn getPreviousFromProcess<T>(
        &self,
        native_ctx: &WinCtx,
        proc: &WinProcess,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        Some(proc.read(native_ctx, self.Blink - listEntryOffsetInTargetStruct))
    }

    pub fn getPreviousFromKernelInitialProcess<T>(
        &self,
        vm: &VMSession,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        Some(vm.read_physical(
            vm.native_ctx.initialProcess.dirBase + self.Blink - listEntryOffsetInTargetStruct,
        ))
    }

    pub fn getPreviousWithDirbase<T>(
        &self,
        vm: &VMSession,
        dirbase: Option<u64>,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => unsafe {
                vmread_sys::VTranslate(
                    &vm.native_ctx.process as *const ProcessData,
                    d,
                    self.Blink - listEntryOffsetInTargetStruct,
                )
            },
            None => self.Blink - listEntryOffsetInTargetStruct,
        };
        Some(vm.read_physical(addr))
    }
}
