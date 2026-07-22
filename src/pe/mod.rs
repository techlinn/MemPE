mod exports;
mod imports;
mod parse;
mod rebuild;

use std::fmt::{Display, Formatter};

pub(crate) use exports::{ExportIndex, ExportStats, embedded_module_name};
pub(crate) use parse::memory_image_size;
pub(crate) use rebuild::{RebuiltImage, rebuild};

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
