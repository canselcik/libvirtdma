use crate::vm::{VMBinding, KFIXC, KFIXO};

#[inline(always)]
fn kfix2(x: u64) -> u64 {
    if x < KFIXC {
        x
    } else {
        x - KFIXO
    }
}

impl VMBinding {
    pub(crate) fn memread(&self, local_addr: u64, remote_addr: u64, len: u64) -> bool {
        let remote: u64 = kfix2(remote_addr);
        unsafe {
            if remote >= self.process.maps_size - len {
                return false;
            }
            libc::memcpy(
                local_addr as *mut libc::c_void,
                (remote + self.process.maps_start) as *mut libc::c_void,
                len as libc::size_t,
            );
        }
        return true;
    }

    pub(crate) fn memwrite(&self, local_addr: u64, remote_addr: u64, len: u64) -> bool {
        let remote: u64 = kfix2(remote_addr);
        unsafe {
            if remote >= self.process.maps_size - len {
                return false;
            }
            libc::memcpy(
                (remote + self.process.maps_start) as *mut libc::c_void,
                local_addr as *mut libc::c_void,
                len as libc::size_t,
            );
        }
        return true;
    }
}
