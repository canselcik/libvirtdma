use dynasmrt::{dynasm, DynasmApi}; /* DynasmLabelApi for labels */

/*
 x86_64 Windows Calling Convention:
   // a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack
   func1(int a, int b, int c, int d, int e, int f);

   MessageBoxA
       HWND    hWnd,
       LPCTSTR lpText,
       LPCTSTR lpCaption,
       UINT    uType
*/
pub fn MessageBoxA(msgbox_vaddr: u64, title_vaddr: u64, body_vaddr: u64) -> Vec<u8> {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x64
        ; xor rcx, rcx
        ; mov rdx, QWORD body_vaddr as i64
        ; mov r8,  QWORD title_vaddr as i64
        ; xor r9, r9
        ; mov rbx, QWORD msgbox_vaddr as i64
        ; call rbx
    );
    let buf = ops.finalize().unwrap();
    let v = buf.to_vec();
    v
}
