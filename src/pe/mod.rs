mod carve;
mod exports;
mod image;
mod imports;
mod packers;
mod parse;
mod rebuild;

use std::fmt::{Display, Formatter};

pub(crate) use carve::{CarveResult, CarveSource, carve_embedded};
pub(crate) use exports::{ExportIndex, ExportStats, embedded_module_name};
pub(crate) use packers::PackerReport;
pub(crate) use parse::memory_image_size;
pub(crate) use rebuild::{DiskImage, RebuiltImage, append_overlay, overlay_offset, rebuild};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegionEvidence {
    pub(crate) offset: usize,
    pub(crate) size: usize,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryPointRva(u32);

impl EntryPointRva {
    pub(crate) fn new(value: u32) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    fn get(self) -> u32 {
        self.0
    }
}

pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub(crate) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub(crate) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub(crate) const EXPORT_DIRECTORY: usize = 0;
pub(crate) const IMPORT_DIRECTORY: usize = 1;
pub(crate) const RESOURCE_DIRECTORY: usize = 2;
pub(crate) const EXCEPTION_DIRECTORY: usize = 3;
pub(crate) const SECURITY_DIRECTORY: usize = 4;
pub(crate) const BASERELOC_DIRECTORY: usize = 5;
pub(crate) const DEBUG_DIRECTORY: usize = 6;
pub(crate) const TLS_DIRECTORY: usize = 9;
pub(crate) const LOAD_CONFIG_DIRECTORY: usize = 10;
pub(crate) const BOUND_IMPORT_DIRECTORY: usize = 11;
pub(crate) const IAT_DIRECTORY: usize = 12;
pub(crate) const DELAY_IMPORT_DIRECTORY: usize = 13;
pub(crate) const SECTION_HEADER_SIZE: usize = 40;
pub(crate) const RUNTIME_FUNCTION_SIZE: usize = 12;
pub(crate) const RELOCATION_HIGHLOW: u16 = 3;
pub(crate) const RELOCATION_DIR64: u16 = 10;
pub(crate) const DYNAMIC_BASE: u16 = 0x0040;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeKind {
    Pe32,
    Pe32Plus,
}

impl PeKind {
    pub(crate) fn pointer_width(self) -> usize {
        match self {
            Self::Pe32 => 4,
            Self::Pe32Plus => 8,
        }
    }
}

impl Display for PeKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pe32 => formatter.write_str("PE32"),
            Self::Pe32Plus => formatter.write_str("PE32+"),
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Rva(u32);

impl Rva {
    fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy)]
struct DataDirectory {
    rva: Rva,
    size: u32,
}

struct PeImage<'a> {
    bytes: &'a [u8],
    model: PeModel,
}

struct SectionModel {
    header_offset: usize,
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: Rva,
    raw_pointer: u32,
    raw_size: u32,
    characteristics: u32,
}

struct PeModel {
    kind: PeKind,
    is_dll: bool,
    subsystem: u16,
    nt_offset: usize,
    size_of_code_offset: usize,
    size_of_initialized_data_offset: usize,
    size_of_uninitialized_data_offset: usize,
    entry_point_offset: usize,
    base_of_code_offset: usize,
    image_base_offset: usize,
    size_of_image_offset: usize,
    size_of_headers_offset: usize,
    dll_characteristics_offset: usize,
    number_of_directories_offset: usize,
    data_directory_offset: usize,
    directory_count: usize,
    file_alignment: u32,
    section_alignment: u32,
    image_size: u32,
    sections: Vec<SectionModel>,
    salvaged: bool,
}
