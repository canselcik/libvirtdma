#![allow(dead_code)]
use crate::vmsession::vm::VMBinding;

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
    pub fn getNextFromKernelInitialProcess<T>(
        &self,
        vm: &VMBinding,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        self.getNextWithDirbase(
            vm,
            Some(vm.initialProcess.dirBase),
            listEntryOffsetInTargetStruct,
        )
    }

    pub fn getNextWithDirbase<T>(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Next == 0 {
            return None;
        }
        Some(match dirbase {
            Some(db) => vm.vread(db, self.Next - listEntryOffsetInTargetStruct),
            None => vm.read(self.Next - listEntryOffsetInTargetStruct),
        })
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
    pub fn getNextFromKernelInitialProcess<T>(
        &self,
        vm: &VMBinding,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        self.getNextWithDirbase(
            vm,
            Some(vm.initialProcess.dirBase),
            listEntryOffsetInTargetStruct,
        )
    }

    pub fn getNextWithDirbase<T>(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Flink == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => vm.native_translate(d, self.Flink - listEntryOffsetInTargetStruct),
            None => self.Flink - listEntryOffsetInTargetStruct,
        };
        Some(vm.read(addr))
    }

    pub fn getPreviousFromKernelInitialProcess<T>(
        &self,
        vm: &VMBinding,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        self.getPreviousWithDirbase(
            vm,
            Some(vm.initialProcess.dirBase),
            listEntryOffsetInTargetStruct,
        )
    }

    pub fn getPreviousWithDirbase<T>(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        listEntryOffsetInTargetStruct: u64,
    ) -> Option<T> {
        if self.Blink == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => vm.native_translate(d, self.Blink - listEntryOffsetInTargetStruct),
            None => self.Flink - listEntryOffsetInTargetStruct,
        };
        Some(vm.read(addr))
    }
}
