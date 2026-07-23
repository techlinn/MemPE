mod exports;
mod image;
mod imports;
mod parse;
mod rebuild;

use std::fmt::{Display, Formatter};

pub(crate) use exports::{ExportIndex, ExportStats, embedded_module_name};
pub(crate) use parse::memory_image_size;
pub(crate) use rebuild::{RebuiltImage, rebuild};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeKind {
    Pe32,
    Pe32Plus,
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
    raw_size: u32,
    characteristics: u32,
}

struct PeModel {
    kind: PeKind,
    is_dll: bool,
    nt_offset: usize,
    size_of_code_offset: usize,
    size_of_initialized_data_offset: usize,
    size_of_uninitialized_data_offset: usize,
    entry_point_offset: usize,
    base_of_code_offset: usize,
    image_base_offset: usize,
    size_of_image_offset: usize,
    size_of_headers_offset: usize,
    number_of_directories_offset: usize,
    data_directory_offset: usize,
    directory_count: usize,
    file_alignment: u32,
    section_alignment: u32,
    image_size: u32,
    sections: Vec<SectionModel>,
    salvaged: bool,
}
