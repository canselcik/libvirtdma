use crate::vmsession::vm::{VMBinding, KFIXC, KFIXO};

#[inline(always)]
fn KFIX2(x: u64) -> u64 {
    if x < KFIXC {
        x
    } else {
        x - KFIXO
    }
}

const STEP_SIZE: u64 = 0x1000;

impl VMBinding {
    pub(crate) fn memread(&self, local: u64, remoteAddr: u64, len: u64) -> bool {
        let reader = |l, r, length| -> bool {
            let remote = KFIX2(r);
            if remote >= self.process.mapsSize - length {
                return false;
            }
            unsafe {
                libc::memcpy(
                    l as *mut libc::c_void,
                    (self.process.mapsStart + remote) as *mut libc::c_void,
                    length as libc::size_t,
                );
            }
            return true;
        };
        return if remoteAddr >> 12u64 != remoteAddr + len >> 12u64 {
            let mut cur = 0u64;
            while cur < len {
                let mut readlen = len - cur;
                if readlen > STEP_SIZE {
                    readlen = STEP_SIZE;
                }
                if !reader(local + cur, remoteAddr + cur, readlen) {
                    return false;
                }
                cur += readlen;
            }
            true
        } else {
            reader(local, remoteAddr, len)
        };
    }

    pub(crate) fn memwrite(&self, local: u64, remoteAddr: u64, len: u64) -> bool {
        let writer = |l, r, length| -> bool {
            let remote = KFIX2(r);
            if remote >= self.process.mapsSize - length {
                return false;
            }
            unsafe {
                libc::memcpy(
                    (self.process.mapsStart + remote) as *mut libc::c_void,
                    l as *mut libc::c_void,
                    length as libc::size_t,
                );
            }
            return true;
        };
        return if remoteAddr >> 12u64 != remoteAddr + len >> 12u64 {
            let mut cur = 0u64;
            while cur < len {
                let mut writelen = len - cur;
                if writelen > STEP_SIZE {
                    writelen = STEP_SIZE;
                }
                if !writer(local + cur, remoteAddr + cur, writelen) {
                    return false;
                }
                cur += writelen;
            }
            true
        } else {
            writer(local, remoteAddr, len)
        };
    }
}
