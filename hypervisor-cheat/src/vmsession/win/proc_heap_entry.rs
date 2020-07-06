#![allow(dead_code)]
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HeapBlock {
    pub hMem: u32, // HANDLE
    pub dwReserved: [u32; 3],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HeapRegion {
    pub dwCommittedSize: u32,   // DWORD
    pub dwUnCommittedSize: u32, // DWORD
    pub lpFirstBlock: u64,      // void*
    pub lpLastBlock: u64,       // void*
}

impl std::fmt::Debug for HeapBlockOrRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HeapBlockOrRegion(as_block={:#?}, as_region={:#?})",
            unsafe { self.Block },
            unsafe { self.Region },
        )
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union HeapBlockOrRegion {
    pub Block: HeapBlock,
    pub Region: HeapRegion,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ProcessHeapEntry {
    pub lpData: u64,      // void*
    pub cbData: u32,      // DWORD
    pub cbOverhead: u8,   // BYTE
    pub iRegionIndex: i8, // BYTE
    pub wFlags: u16,      // WORD
    pub BlockOrRegion: HeapBlockOrRegion,
}

#[repr(u16)]
pub enum HeapProperty {
    ProcessHeapEntryBusy = 0x0004,
    ProcessHeapEntryDdeshare = 0x0020,
    ProcessHeapEntryMoveable = 0x0010,
    ProcessHeapRegion = 0x0001,
    ProcessHeapUncommittedRange = 0x0002,
}

impl ProcessHeapEntry {
    pub fn as_table(&self, title: Option<String>) -> String {
        let mut table = Table::new();
        table.max_column_width = 45;
        table.style = TableStyle::thin();
        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            match title {
                Some(t) => t,
                None => "ProcessHeapEntry".to_string(),
            },
            2,
            Alignment::Center,
        )]));
        let mut field_adder = |k, v| {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(k, 1, Alignment::Left),
                TableCell::new_with_alignment(v, 1, Alignment::Right),
            ]));
        };
        if self.wFlags & HeapProperty::ProcessHeapEntryBusy as u16 != 0 {
            field_adder("Type", "Allocated Block".to_string());
            field_adder(
                "Movable",
                if self.wFlags & HeapProperty::ProcessHeapEntryMoveable as u16 != 0 {
                    format!("with HANDLE 0x{:x}", unsafe {
                        self.BlockOrRegion.Block.hMem
                    })
                } else {
                    "false".to_string()
                },
            );
            field_adder(
                "DDESHARE",
                if self.wFlags & HeapProperty::ProcessHeapEntryDdeshare as u16 != 0 {
                    "true".to_string()
                } else {
                    "false".to_string()
                },
            );
        } else if self.wFlags & HeapProperty::ProcessHeapRegion as u16 != 0 {
            field_adder("Type", "Region".to_string());
            field_adder(
                "Committed Size",
                format!("0x{:x}", unsafe {
                    self.BlockOrRegion.Region.dwCommittedSize
                }),
            );
            field_adder(
                "Uncommitted Size",
                format!("0x{:x}", unsafe {
                    self.BlockOrRegion.Region.dwUnCommittedSize
                }),
            );
            field_adder(
                "First Block",
                format!("0x{:x}", unsafe { self.BlockOrRegion.Region.lpFirstBlock }),
            );
            field_adder(
                "Last Block",
                format!("0x{:x}", unsafe { self.BlockOrRegion.Region.lpLastBlock }),
            );
        } else if self.wFlags & HeapProperty::ProcessHeapUncommittedRange as u16 != 0 {
            field_adder("Type", "Uncommitted range".to_string());
        } else {
            field_adder("Type", "Block".to_string());
        }

        field_adder("Data Portion Begins at", format!("0x{:x}", self.lpData));
        field_adder("Data Portion Size", format!("0x{:x}", self.cbData));
        field_adder("Overhead", format!("0x{:x}", self.cbOverhead));
        field_adder("Region Index", format!("0x{:x}", self.iRegionIndex));
        table.render()
    }
}
