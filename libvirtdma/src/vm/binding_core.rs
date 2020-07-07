use crate::vm::{VMBinding, KFIXC, KFIXO};

#[inline(always)]
fn kfix2(x: u64) -> u64 {
    if x < KFIXC {
        x
    } else {
        x - KFIXO
    }
}

const STEP_SIZE: u64 = 0x1000;

impl VMBinding {
    pub(crate) fn memread(&self, local: u64, remote_addr: u64, len: u64) -> bool {
        let reader = |l, r, length| -> bool {
            let remote = kfix2(r);
            if remote >= self.process.maps_size - length {
                return false;
            }
            unsafe {
                libc::memcpy(
                    l as *mut libc::c_void,
                    (self.process.maps_start + remote) as *mut libc::c_void,
                    length as libc::size_t,
                );
            }
            return true;
        };
        return if remote_addr >> 12u64 != remote_addr + len >> 12u64 {
            let mut cur = 0u64;
            while cur < len {
                let mut readlen = len - cur;
                if readlen > STEP_SIZE {
                    readlen = STEP_SIZE;
                }
                if !reader(local + cur, remote_addr + cur, readlen) {
                    return false;
                }
                cur += readlen;
            }
            true
        } else {
            reader(local, remote_addr, len)
        };
    }

    #[allow(dead_code)]
    pub(crate) fn memwrite(&self, local: u64, remote_addr: u64, len: u64) -> bool {
        let writer = |l, r, length| -> bool {
            let remote = kfix2(r);
            if remote >= self.process.maps_size - length {
                return false;
            }
            unsafe {
                libc::memcpy(
                    (self.process.maps_start + remote) as *mut libc::c_void,
                    l as *mut libc::c_void,
                    length as libc::size_t,
                );
            }
            return true;
        };
        return if remote_addr >> 12u64 != remote_addr + len >> 12u64 {
            let mut cur = 0u64;
            while cur < len {
                let mut writelen = len - cur;
                if writelen > STEP_SIZE {
                    writelen = STEP_SIZE;
                }
                if !writer(local + cur, remote_addr + cur, writelen) {
                    return false;
                }
                cur += writelen;
            }
            true
        } else {
            writer(local, remote_addr, len)
        };
    }
}
