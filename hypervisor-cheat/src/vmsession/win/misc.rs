#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GroupAffinity {
    pub Mask: u64,          //0x0
    pub Group: u16,         //0x8
    pub Reserved: [u16; 3], //0xa
}

macro_rules! makeByteRange {
    ($name:ident, $length:expr) => {
        #[derive(Copy, Clone)]
        pub struct $name([u8; $length]);
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(...)", stringify!($name))
            }
        }
    };
}

makeByteRange!(Bytes1024, 1024);
makeByteRange!(Bytes1520, 0x5f0);
makeByteRange!(Bytes168, 0xA8);
makeByteRange!(Bytes24, 24);
makeByteRange!(Bytes272, 0x110);
makeByteRange!(Bytes280, 280);
makeByteRange!(Bytes32, 0x20);
makeByteRange!(Bytes40, 40);
makeByteRange!(Bytes48, 0x30);
makeByteRange!(Bytes192, 192);
makeByteRange!(Bytes64, 0x40);
makeByteRange!(Bytes660, 0x294);
makeByteRange!(Bytes71, 71);
makeByteRange!(Bytes744, 744);
makeByteRange!(Bytes80, 80);
makeByteRange!(Bytes88, 0x58);
makeByteRange!(Bytes96, 0x60);
