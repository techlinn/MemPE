use std::fmt::{Display, Formatter};
use std::ops::Range;

use super::bytes::{read_u16, read_u32, write_u32};
use super::parse::MIN_STANDARD_SECTION_ALIGNMENT;
use super::{CHECKSUM_OFFSET, DIRECTORY_ENTRY_SIZE, DYNAMIC_BASE, ENTRY_POINT_OFFSET};
use super::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use super::{IMPORT_DESCRIPTOR_SIZE, IMPORT_DIRECTORY, IMPORT_IAT_OFFSET, IMPORT_LOOKUP_OFFSET};
use super::{IMPORT_NAME_OFFSET, MAX_IMPORT_DESCRIPTORS};
use super::{RELOCATION_DIR64, RELOCATION_HIGHLOW};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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

    pub(crate) fn bits(self) -> u32 {
        match self {
            Self::Pe32 => 32,
            Self::Pe32Plus => 64,
        }
    }

    pub(crate) fn ordinal_flag(self) -> u64 {
        1 << (self.bits() - 1)
    }

    pub(crate) fn relocation_type(self) -> u16 {
        match self {
            Self::Pe32 => RELOCATION_HIGHLOW,
            Self::Pe32Plus => RELOCATION_DIR64,
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
pub(crate) struct Rva(pub(crate) u32);

impl Rva {
    pub(crate) fn get(self) -> u32 {
        self.0
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DataDirectory {
    pub(super) rva: Rva,
    pub(super) size: u32,
}

pub(crate) struct PeImage<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) model: PeModel,
}

pub(crate) struct SectionModel {
    pub(crate) header_offset: usize,
    pub(super) name: [u8; 8],
    pub(crate) virtual_size: u32,
    pub(super) virtual_address: Rva,
    pub(crate) raw_pointer: u32,
    pub(crate) raw_size: u32,
    pub(super) characteristics: u32,
    pub(super) span: u32, // mapped size, section aligned
}

pub(crate) struct PeModel {
    pub(crate) kind: PeKind,
    pub(crate) is_dll: bool,
    pub(crate) subsystem: u16,
    pub(crate) nt_offset: usize,
    pub(crate) size_of_code_offset: usize,
    pub(crate) size_of_initialized_data_offset: usize,
    pub(crate) size_of_uninitialized_data_offset: usize,
    pub(crate) entry_point_offset: usize,
    pub(crate) base_of_code_offset: usize,
    pub(crate) image_base_offset: usize,
    pub(crate) size_of_image_offset: usize,
    pub(crate) size_of_headers_offset: usize,
    pub(crate) dll_characteristics_offset: usize,
    pub(crate) number_of_directories_offset: usize,
    pub(crate) data_directory_offset: usize,
    pub(crate) directory_count: usize,
    pub(crate) file_alignment: u32,
    pub(crate) section_alignment: u32,
    pub(crate) image_size: u32,
    pub(crate) sections: Vec<SectionModel>,
    pub(crate) salvaged: bool,
}

impl DataDirectory {
    pub(crate) fn rva(self) -> Rva {
        self.rva
    }

    pub(crate) fn size(self) -> u32 {
        self.size
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ImportDescriptor {
    pub(crate) at: usize,
    pub(crate) lookup: u32,
    pub(crate) name: u32,
    pub(crate) iat: u32,
}

impl ImportDescriptor {
    pub(crate) fn read(bytes: &[u8], at: usize) -> Option<Self> {
        let field = |offset: usize| read_u32(bytes, at.checked_add(offset)?).ok();

        Some(Self {
            at,
            lookup: field(IMPORT_LOOKUP_OFFSET)?,
            name: field(IMPORT_NAME_OFFSET)?,
            iat: field(IMPORT_IAT_OFFSET)?,
        })
    }

    pub(crate) fn raw<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        bytes.get(self.at..self.at.checked_add(IMPORT_DESCRIPTOR_SIZE)?)
    }

    pub(crate) fn ends_table(&self) -> bool {
        self.name == 0 || self.iat == 0 // where the loader stops
    }
}

impl<'a> PeImage<'a> {
    pub(crate) fn new(bytes: &'a [u8], model: PeModel) -> Self {
        Self { bytes, model }
    }

    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) fn into_model(self) -> PeModel {
        self.model
    }

    pub(crate) fn model(&self) -> &PeModel {
        &self.model
    }

    pub(crate) fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.model.directory(self.bytes, index)
    }

    pub(crate) fn import_descriptors(&self) -> impl Iterator<Item = ImportDescriptor> + 'a {
        let bytes = self.bytes;
        let first = self
            .directory(IMPORT_DIRECTORY)
            .map(|directory| directory.rva().as_usize());

        (0..MAX_IMPORT_DESCRIPTORS)
            .map_while(move |index| {
                let at = first?.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
                ImportDescriptor::read(bytes, at)
            })
            .take_while(|descriptor| !descriptor.ends_table())
    }
}

impl SectionModel {
    pub(crate) fn span(&self) -> u32 {
        self.span
    }

    pub(crate) fn range(&self) -> Range<usize> {
        let start = self.virtual_address.as_usize();
        start..start.saturating_add(self.span as usize)
    }

    pub(crate) fn mapped_size(&self) -> u32 {
        match self.virtual_size {
            0 => self.raw_size,
            size => size, // raw past VirtualSize dropped
        }
    }

    pub(crate) fn range_in(&self, bytes: &[u8]) -> Range<usize> {
        let start = self.virtual_address.as_usize();
        start..start.saturating_add(self.span() as usize).min(bytes.len())
    }

    pub(crate) fn held_size(&self) -> u32 {
        self.mapped_size().max(self.raw_size.min(self.span))
    }

    pub(crate) fn contains_rva(&self, rva: Rva) -> bool {
        let start = self.virtual_address.get();
        let end = start.saturating_add(self.span());
        rva.get() >= start && rva.get() < end
    }

    pub(crate) fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub(crate) fn is_data(&self) -> bool {
        !self.is_executable()
            && self.characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) != 0
    }

    pub(crate) fn name(&self) -> &[u8; 8] {
        &self.name
    }

    pub(crate) fn virtual_address(&self) -> Rva {
        self.virtual_address
    }

    pub(crate) fn characteristics(&self) -> u32 {
        self.characteristics
    }
}

impl PeModel {
    pub(crate) fn optional_header_offset(&self) -> usize {
        self.entry_point_offset.saturating_sub(ENTRY_POINT_OFFSET)
    }

    pub(crate) fn checksum_offset(&self) -> usize {
        self.optional_header_offset()
            .saturating_add(CHECKSUM_OFFSET)
    }

    pub(crate) fn is_low_alignment(&self) -> bool {
        self.section_alignment < MIN_STANDARD_SECTION_ALIGNMENT
    }

    pub(crate) fn dynamic_base(&self, bytes: &[u8]) -> bool {
        read_u16(bytes, self.dll_characteristics_offset)
            .is_ok_and(|flags| flags & DYNAMIC_BASE != 0)
    }

    pub(crate) fn relocatable(&self, bytes: &[u8]) -> bool {
        self.is_dll || self.dynamic_base(bytes)
    }

    pub(crate) fn directory(&self, bytes: &[u8], index: usize) -> Option<DataDirectory> {
        let offset = self.directory_offset(index)?;

        let rva = read_u32(bytes, offset).ok()?;
        let size = read_u32(bytes, offset.checked_add(4)?).ok()?;

        (rva != 0 && size != 0).then_some(DataDirectory {
            rva: Rva(rva),
            size,
        })
    }

    pub(crate) fn header_bytes_in_use(
        &self,
        bytes: &[u8],
        slot: &Range<usize>,
        stale: Option<usize>,
    ) -> bool {
        let covered = (0..self.directory_count)
            .filter(|index| Some(*index) != stale)
            .filter_map(|index| self.directory(bytes, index))
            .any(|directory| {
                let start = directory.rva().as_usize();
                start < slot.end && slot.start < start.saturating_add(directory.size() as usize)
            });
        let entry = read_u32(bytes, self.entry_point_offset).map_or(0, |entry| entry as usize);

        covered || slot.contains(&entry)
    }

    pub(crate) fn directory_offset(&self, index: usize) -> Option<usize> {
        let relative = (index < self.directory_count).then(|| index * DIRECTORY_ENTRY_SIZE)?;
        self.data_directory_offset.checked_add(relative)
    }

    pub(crate) fn set_directory(
        &self,
        bytes: &mut [u8],
        index: usize,
        rva: usize,
        size: usize,
    ) -> Option<()> {
        let offset = self.directory_offset(index)?;
        write_u32(bytes, offset, u32::try_from(rva).ok()?).ok()?;
        write_u32(bytes, offset.checked_add(4)?, u32::try_from(size).ok()?).ok()
    }

    // true when the entry held anything, even one field
    pub(crate) fn clear_directory(&self, bytes: &mut [u8], index: usize) -> bool {
        let entry = self
            .directory_offset(index)
            .and_then(|offset| bytes.get_mut(offset..offset.checked_add(DIRECTORY_ENTRY_SIZE)?));
        let Some(entry) = entry else {
            return false;
        };

        let held = entry.iter().any(|byte| *byte != 0);
        entry.fill(0);
        held
    }

    pub(crate) fn executable_rva(&self, rva: Rva) -> bool {
        self.sections
            .iter()
            .any(|section| section.is_executable() && section.contains_rva(rva))
    }
}

pub(crate) fn first_section_rva(sections: &[SectionModel]) -> Option<usize> {
    sections
        .iter()
        .filter(|section| section.mapped_size() != 0)
        .map(|section| section.virtual_address.as_usize())
        .min()
}
