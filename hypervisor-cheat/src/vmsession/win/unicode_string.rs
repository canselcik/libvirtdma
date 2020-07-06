use crate::vmsession::vm::VMBinding;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnicodeString {
    pub(crate) Length: u16,
    pub(crate) MaximumLength: u16,
    pub(crate) Buffer: u64, // ptr to null-terminated 16bit unicode chars
}

impl std::fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnicodeString(len={}, maxLen={}, buffer=0x{:x})",
            self.Length, self.MaximumLength, self.Buffer,
        )
    }
}

impl UnicodeString {
    pub fn resolve(
        &self,
        vm: &VMBinding,
        dirbase: Option<u64>,
        maxLen: Option<u16>,
    ) -> Option<String> {
        let readlen = match maxLen {
            Some(l) => {
                if l < self.Length {
                    l
                } else {
                    self.Length
                }
            }
            None => self.Length,
        };
        let mut input: Vec<u16> = Vec::new();
        for offset in 0..readlen {
            let addr = self.Buffer + offset as u64 * std::mem::size_of::<u16>() as u64;
            let current: u16 = match dirbase {
                Some(dbase) => vm.vread(dbase, addr),
                None => vm.read_physical(addr),
            };
            input.push(current);
        }
        let charlen = readlen / 2;
        let s = unsafe { widestring::U16String::from_ptr(input.as_ptr(), charlen as usize) };
        Some(s.to_string_lossy())
    }
}
