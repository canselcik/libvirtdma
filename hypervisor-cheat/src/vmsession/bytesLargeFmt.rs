#[derive(Copy, Clone)]
pub struct Bytes1024([u8; 1024]);
impl std::fmt::Debug for Bytes1024 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes1024(...)")
    }
}
