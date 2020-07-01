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

makeByteRange!(Bytes24, 24);
makeByteRange!(Bytes32, 0x20);
makeByteRange!(Bytes40, 40);
makeByteRange!(Bytes48, 0x30);
makeByteRange!(Bytes71, 71);
makeByteRange!(Bytes80, 80);
makeByteRange!(Bytes96, 0x60);
makeByteRange!(Bytes168, 0xA8);
makeByteRange!(Bytes272, 0x110);
makeByteRange!(Bytes660, 0x294);
makeByteRange!(Bytes744, 744);
makeByteRange!(Bytes760, 760);
makeByteRange!(Bytes1024, 1024);
makeByteRange!(Bytes1520, 0x5f0);
