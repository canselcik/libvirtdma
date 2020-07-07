#![allow(dead_code)]
use crate::vm::VMBinding;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SingleListEntry {
    next: u64, // ptr to next
}

impl std::fmt::Debug for SingleListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SingleListEntry(next=0x{:x})", self.next)
    }
}

impl SingleListEntry {
    pub fn get_next_from_kernel_initial_process<T>(
        &self,
        vm: &VMBinding,
        list_entry_offset_in_target_struct: u64,
    ) -> Option<T> {
        self.get_next_with_dirbase(
            vm,
            Some(vm.initial_process.dirbase),
            list_entry_offset_in_target_struct,
        )
    }

    pub fn get_next_with_dirbase<T>(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        list_entry_offset_in_target_struct: u64,
    ) -> Option<T> {
        if self.next == 0 {
            return None;
        }
        Some(match dirbase {
            Some(db) => vm.vread(db, self.next - list_entry_offset_in_target_struct),
            None => vm.read(self.next - list_entry_offset_in_target_struct),
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListEntry {
    pub flink: u64, // ptr to next
    pub blink: u64, // ptr to prev
}

impl std::fmt::Debug for ListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ListEntry(fLink=0x{:x}, bLink=0x{:x})",
            self.flink, self.blink
        )
    }
}

impl ListEntry {
    pub fn get_next_from_kernel_initial_process<T>(
        &self,
        vm: &VMBinding,
        list_entry_offset_in_target_struct: u64,
    ) -> Option<T> {
        self.get_next_with_dirbase(
            vm,
            Some(vm.initial_process.dirbase),
            list_entry_offset_in_target_struct,
        )
    }

    pub fn get_next_with_dirbase<T>(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        list_entry_offset_in_target_struct: u64,
    ) -> Option<T> {
        if self.flink == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => vm.native_translate(d, self.flink - list_entry_offset_in_target_struct),
            None => self.flink - list_entry_offset_in_target_struct,
        };
        Some(vm.read(addr))
    }

    pub fn get_previous_from_kernel_initial_process<T>(
        &self,
        vm: &VMBinding,
        list_entry_offset_in_target_struct: u64,
    ) -> Option<T> {
        self.get_previous_with_dirbase(
            vm,
            Some(vm.initial_process.dirbase),
            list_entry_offset_in_target_struct,
        )
    }

    pub fn get_previous_with_dirbase<T>(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        list_entry_offset_in_target_struct: u64,
    ) -> Option<T> {
        if self.blink == 0 {
            return None;
        }
        let addr = match dirbase {
            Some(d) => vm.native_translate(d, self.blink - list_entry_offset_in_target_struct),
            None => self.flink - list_entry_offset_in_target_struct,
        };
        Some(vm.read(addr))
    }
}
