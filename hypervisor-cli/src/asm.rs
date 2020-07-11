
use dynasmrt::{dynasm, DynasmApi}; /* DynasmLabelApi for labels */
pub fn asmdisasm() -> Vec<u8> {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x64
        ; xor edx, edx
        ; call rax
        ; add rsp, BYTE 0x28
        ; ret
    );
    let buf = ops.finalize().unwrap();
    let v = buf.to_vec();
    v
}