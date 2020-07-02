use crate::vmsession::win::eprocess::EPROCESS;

#[derive(Debug, Clone)]
pub struct ProcKernelInfo {
    pub name: String,
    pub eprocess: EPROCESS,
    pub eprocessVirtAddr: u64,
    pub eprocessPhysAddr: u64,
}

impl ProcKernelInfo {
    pub fn new(name: &str, eprocess: EPROCESS, virtAddr: u64, physAddr: u64) -> ProcKernelInfo {
        ProcKernelInfo {
            name: name.to_string(),
            eprocess,
            eprocessPhysAddr: physAddr,
            eprocessVirtAddr: virtAddr,
        }
    }
}
