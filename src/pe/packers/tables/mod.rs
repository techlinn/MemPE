mod debug;
mod directories;
mod exports;
mod fresh;
mod icons;
mod imports;
mod pogo;
mod relocations;
mod resources;
mod sections;
mod tls;

use crate::pe::PeModel;
use crate::pe::image::write_u32;

pub(super) use debug::{
    DEBUG_ADDRESS_OFFSET, DEBUG_ENTRY_SIZE, DEBUG_SIZE_OFFSET, DEBUG_TYPE_CODEVIEW,
    DEBUG_TYPE_OFFSET, codeview_entry, debug_timestamp, find_codeview_record,
};
pub(super) use directories::{recover_directories, security_cookie};
pub(super) use exports::{
    export_functions, exports_intact, linker_export_layout, linker_export_start,
    moved_export_directory,
};
pub(super) use fresh::{fresh_image, map_disk_image};
pub(super) use icons::repair_icon_groups;
pub(super) use imports::{
    HINT_SIZE, IMPORT_DESCRIPTOR_SIZE, IMPORT_IAT_OFFSET, IMPORT_NAME_OFFSET,
    MAX_IMPORT_DESCRIPTORS, MAX_THUNKS, ORDINAL_FLAG, OriginalImage, THUNK_SIZE,
    apply_listed_imports, iat_filled, iat_span, imports_from_original, listed_imports,
};
pub(super) use pogo::{pogo_parts, pogo_sections, pogo_tls_directory};
pub(super) use relocations::{
    MAX_RELOCATION_BLOCK, RELOCATION_BLOCK_HEADER, RELOCATION_BLOCK_SIZE_OFFSET, relocate,
    relocated_fields, relocation_blocks, relocations_intact,
};
pub(super) use resources::{
    LinkerTree, RESOURCE_DATA_SIZE_OFFSET, RESOURCE_SIZE_ALIGNMENT, ResourceLayout,
    lay_out_resources, linker_resource_layout, lowest_moved_leaf, resource_layout,
    resources_intact, restore_moved_resources, return_moved_leaves, walk_resources,
};
pub(super) use sections::{
    LinkerBounds, SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, SECTION_RVA_OFFSET,
    SectionHints, SectionPiece, first_section_range, linker_bounds, name_sections,
    replace_first_section, split_merged_section,
};
pub(super) use tls::restore_tls;

const MAX_NAME_LENGTH: usize = 4_096;
pub(super) const FIRST_SECTION_RVA: usize = 0x1000;
pub(super) const SCAN_STEP: usize = 4;

pub(super) enum Restoration {
    Restored,
    Absent,
    Failed,
    Lost,
}

pub(super) fn is_free(restored: &[u8], destination: usize, content: &[u8]) -> bool {
    restored
        .get(destination..destination.saturating_add(content.len()))
        .is_some_and(|current| {
            current
                .iter()
                .zip(content)
                .all(|(byte, wanted)| *byte == 0 || byte == wanted)
        })
}

pub(super) fn place(restored: &mut [u8], destination: usize, content: &[u8]) -> Option<()> {
    if !is_free(restored, destination, content) {
        return None;
    }

    restored
        .get_mut(destination..destination.checked_add(content.len())?)?
        .copy_from_slice(content);
    Some(())
}

pub(super) fn set_directory(
    restored: &mut [u8],
    model: &PeModel,
    index: usize,
    rva: usize,
    size: usize,
) -> Option<()> {
    let offset = model.directory_offset(index).ok()??;
    write_u32(restored, offset, u32::try_from(rva).ok()?).ok()?;
    write_u32(restored, offset.checked_add(4)?, u32::try_from(size).ok()?).ok()
}

pub(super) fn clear_directory(restored: &mut [u8], model: &PeModel, index: usize) {
    let _ = set_directory(restored, model, index, 0, 0);
}

pub(super) fn unique<T>(mut found: impl Iterator<Item = T>) -> Option<T> {
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

pub(super) fn read_c_string(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let tail = bytes.get(at..)?;
    let length = tail
        .iter()
        .take(MAX_NAME_LENGTH)
        .position(|byte| *byte == 0)?;
    let text = std::str::from_utf8(tail.get(..length)?).ok()?;
    (!text.is_empty()).then(|| (text.to_owned(), at.saturating_add(length).saturating_add(1)))
}
