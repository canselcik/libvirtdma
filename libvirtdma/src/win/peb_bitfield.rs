#![allow(non_snake_case)]

#[derive(Debug, Copy, Clone)]
pub struct PEBBitfieldReading {
    ImageUsesLargePages: bool,
    IsProtectedProcess: bool,
    IsLegacyProcess: bool,
    IsImageDynamicallyRelocated: bool,
    SkipPatchingUser32Forwarders: bool,
    SpareBit0: bool,
    SpareBit1: bool,
    SpareBit2: bool,
}

#[derive(Copy, Clone)]
pub struct PEBBitfield(u8);

impl PEBBitfield {
    fn interpret(&self) -> Option<PEBBitfieldReading> {
        let s = self.as_bitstr();
        if s.len() != 8 {
            return None;
        }
        let serialized = s.as_bytes();
        Some(PEBBitfieldReading {
            ImageUsesLargePages: serialized[0] == '1' as u8,
            IsProtectedProcess: serialized[1] == '1' as u8,
            IsLegacyProcess: serialized[2] == '1' as u8,
            IsImageDynamicallyRelocated: serialized[3] == '1' as u8,
            SkipPatchingUser32Forwarders: serialized[4] == '1' as u8,
            SpareBit0: serialized[5] == '1' as u8,
            SpareBit1: serialized[6] == '1' as u8,
            SpareBit2: serialized[7] == '1' as u8,
        })
    }

    fn as_bitstr(&self) -> String {
        let s = format!("{:b}", self.0);
        format!("{}{}", "0".repeat(8 - s.len()), s)
            .chars()
            .rev()
            .collect::<String>()
    }
}

impl std::fmt::Debug for PEBBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PEBBitfield(dec={}, beBinary={:b}, intermediate={}, detailed={:#?})",
            self.0,
            self.0,
            self.as_bitstr(),
            self.interpret().unwrap(),
        )
    }
}
