use crate::vm::VMBinding;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnicodeString {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) buffer: u64, // ptr to null-terminated 16bit unicode chars
}

impl std::fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnicodeString(len={}, maxLen={}, buffer=0x{:x})",
            self.length, self.maximum_length, self.buffer,
        )
    }
}

impl UnicodeString {
    pub fn looks_invalid(&self) -> bool {
        self.length == 0xFFFF && self.buffer == 0xFFFFFFFFFFFFFFFF
    }

    pub fn resolve(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        max_len: Option<u16>,
    ) -> Option<String> {
        if self.looks_invalid() {
            return Some("<UNABLE_TO_READ_LOOKS_INVALID>".to_string());
        }
        let readlen = match max_len {
            Some(l) => {
                if l < self.length {
                    l
                } else {
                    self.length
                }
            }
            None => self.length,
        } as u64;
        let data = match dirbase {
            Some(dbase) => vm.vreadvec(dbase, self.buffer, readlen),
            None => vm.readvec(self.buffer, readlen),
        };
        let s = unsafe {
            widestring::U16String::from_ptr(data.as_ptr() as *const u16, readlen as usize / 2)
        };
        Some(s.to_string_lossy())
    }
}
