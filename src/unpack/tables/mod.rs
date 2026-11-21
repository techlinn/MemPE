mod debug_directory;
mod exception_directory;
mod exports;
mod icons;
mod imports;
mod lost_directories;
mod move_tables;
mod pogo_sections;
mod relocations;
mod resources;
mod sections;
mod tls;

pub(crate) use debug_directory::{
    DEBUG_TYPE_CODEVIEW, codeview_entry, debug_entries, debug_timestamp, find_codeview_record,
};
pub(crate) use exception_directory::{keep_unwind_within, restore_exception_directory};
pub(crate) use exports::{
    export_forwarders, exports_intact, linker_export_layout, linker_export_start,
    moved_export_directory,
};
pub(crate) use icons::repair_icon_groups;
pub(crate) use imports::{
    ORDINAL_FLAG, OriginalBytes, THUNK_SIZE, apply_listed_imports, iat_filled, iat_span, iat_start,
    imports_from_original, listed_imports,
};
pub(crate) use lost_directories::{
    is_module_name, load_config_length, recover_directories, restore_load_config, safe_handlers,
    safeseh_field, security_cookie,
};
pub(crate) use move_tables::{evacuate, place_table, table_references};
pub(crate) use pogo_sections::{CoffGroup, pogo_parts, pogo_sections, pogo_tls_directory};
pub(crate) use relocations::{
    Fixups, MAX_RELOCATION_BLOCK, RELOCATION_BLOCK_SIZE_OFFSET, drop_relocation_blocks,
    find_relocation_table, relocate, relocated_fields, relocation_blocks, relocations_intact,
    restore_relocation_directory,
};
pub(crate) use resources::{
    LinkerTree, RESOURCE_SIZE_ALIGNMENT, ResourceLayout, lay_out_resources, linker_resource_layout,
    lowest_leaf_below, resource_layout, resource_leaf, resources_intact, restore_moved_resources,
    return_moved_leaves, walk_resources,
};
pub(crate) use sections::{
    LinkerBounds, PlannedSection, SectionHints, SectionKind, append, clear_header_slack,
    code_stores_into, cut_tail, first_section_range, flags_from_names, header_code_range,
    linker_bounds, name_sections, next_section_rva, replace_first_section, shed,
    split_merged_section,
};
pub(crate) use tls::{restore_tls, tls_callbacks};

use crate::pe::bytes::{read_ascii, read_u32};
use crate::pe::{MAX_NAME_LENGTH, PeModel};

pub(crate) const SCAN_STEP: usize = 4;

pub(crate) enum Restoration {
    Restored,
    Inferred(&'static str), // by search or a layout assumption
    Absent,
    Failed,
    Lost,
}

pub(crate) enum Search<T> {
    None,
    One(T),
    Several,
}

impl<T> Search<T> {
    pub(crate) fn one(self) -> Option<T> {
        match self {
            Self::One(found) => Some(found),
            Self::None | Self::Several => None,
        }
    }

    pub(crate) fn and_then<U>(self, next: impl FnOnce(T) -> Search<U>) -> Search<U> {
        match self {
            Self::One(found) => next(found),
            Self::None => Search::None,
            Self::Several => Search::Several,
        }
    }

    pub(crate) fn filter_map<U>(self, change: impl FnOnce(T) -> Option<U>) -> Search<U> {
        self.and_then(|found| change(found).map_or(Search::None, Search::One))
    }
}

pub(crate) fn sole<T>(found: impl IntoIterator<Item = T>) -> Search<T> {
    let mut found = found.into_iter();
    let Some(first) = found.next() else {
        return Search::None;
    };

    match found.next() {
        Some(_) => Search::Several,
        None => Search::One(first),
    }
}

pub(crate) fn unique<T>(found: impl IntoIterator<Item = T>) -> Option<T> {
    sole(found).one()
}

pub(crate) fn is_free(restored: &[u8], destination: usize, content: &[u8]) -> bool {
    restored
        .get(destination..destination.saturating_add(content.len()))
        .is_some_and(|current| {
            current
                .iter()
                .zip(content)
                .all(|(byte, wanted)| *byte == 0 || byte == wanted)
        })
}

pub(crate) fn place(restored: &mut [u8], destination: usize, content: &[u8]) -> Option<()> {
    if !is_free(restored, destination, content) {
        return None;
    }

    restored
        .get_mut(destination..destination.checked_add(content.len())?)?
        .copy_from_slice(content);
    Some(())
}

// a table that could not be rebuilt leaves no directory naming it
pub(crate) fn restored_or_cleared(
    restored: &mut [u8],
    model: &PeModel,
    index: usize,
    rebuilt: Option<Restoration>,
) -> Restoration {
    rebuilt.unwrap_or_else(|| {
        model.clear_directory(restored, index);
        Restoration::Failed
    })
}

pub(super) fn rewrite_table(
    restored: &mut [u8],
    model: &PeModel,
    index: usize,
    keep: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Option<()> {
    let entry = model.directory_offset(index)?;
    let rva = read_u32(restored, entry).ok()? as usize;
    let size = read_u32(restored, entry.checked_add(4)?).ok()? as usize;
    let kept = keep(restored.get(rva..rva.checked_add(size)?)?);

    let area = restored.get_mut(rva..rva + size)?;
    area.fill(0);
    area.get_mut(..kept.len())?.copy_from_slice(&kept);

    match kept.is_empty() {
        true => _ = model.clear_directory(restored, index),
        false => model.set_directory(restored, index, rva, kept.len())?,
    }
    Some(())
}

pub(crate) fn read_c_string(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let text = read_ascii(bytes, at, MAX_NAME_LENGTH)?;
    let next = at.saturating_add(text.len()).saturating_add(1);
    Some((text.to_owned(), next))
}
