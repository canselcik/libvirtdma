use crate::vmsession::vm::{VMBinding, WinModule, WinProc};
use crate::vmsession::win::heap_entry::HEAP;

impl VMBinding {
    pub fn find_kmod(&self, name: &str) -> Option<WinModule> {
        return None;
    }

    pub fn find_process(&self, name: &str) -> Option<WinProc> {
        return None;
    }

    pub fn list_kmods(&self) {}

    pub fn list_processes(&self) {}

    pub fn dump_kmod_vmem(&self, module: &WinModule) -> Result<Vec<u8>, i64> {
        return Err(0);
    }

    pub fn get_heaps_with_dirbase(&self, dirbase: u64, physProcess: u64) -> Vec<HEAP> {
        return Vec::new();
    }

    pub fn pinspect(&self, proc: &mut WinProc) {}

    pub fn list_process_modules(&self, proc: &mut WinProc) {}
}
