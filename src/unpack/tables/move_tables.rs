use std::ops::Range;

use super::exception_directory::runtime_functions;
use super::exports::EXPORT_RVA_OFFSETS;
use super::lost_directories::MAX_LOAD_CONFIG_SIZE;
use super::resources::walk_resources;
use super::tls::tls_callbacks;
use super::{SCAN_STEP, SectionKind, append, load_config_length};
use crate::pe::bytes::{read_pointer, read_u32, write_u32};
use crate::pe::{
    BASERELOC_DIRECTORY, DEBUG_ADDRESS_OFFSET, DEBUG_DIRECTORY, DEBUG_ENTRY_SIZE,
    DELAY_ATTRIBUTES_RVA_BASED, DELAY_BOUND_IAT_OFFSET, DELAY_DESCRIPTOR_SIZE, DELAY_HANDLE_OFFSET,
    DELAY_IAT_OFFSET, DELAY_IMPORT_DIRECTORY, DELAY_INT_OFFSET, DELAY_NAME_OFFSET,
    DELAY_UNLOAD_OFFSET, EXCEPTION_DIRECTORY, EXPORT_DIRECTORY, EXPORT_ENTRY_SIZE,
    EXPORT_NAME_COUNT_OFFSET, EXPORT_NAMES_OFFSET, IAT_DIRECTORY, IMPORT_DIRECTORY,
    LOAD_CONFIG_DIRECTORY, PeKind, PeModel, RESOURCE_DIRECTORY, SECTION_VIRTUAL_SIZE_OFFSET,
    SECURITY_DIRECTORY, SectionModel, TLS_DIRECTORY, TLS_POINTER_FIELDS,
};

const TABLE_ALIGNMENT: usize = 16;
const DELAY_RVA_FIELDS: [usize; 6] = [
    DELAY_NAME_OFFSET,
    DELAY_HANDLE_OFFSET,
    DELAY_IAT_OFFSET,
    DELAY_INT_OFFSET,
    DELAY_BOUND_IAT_OFFSET,
    DELAY_UNLOAD_OFFSET,
];
const MAX_TABLE_ENTRIES: usize = 4096;
const FOLLOWED_DIRECTORIES: [usize; 8] = [
    EXPORT_DIRECTORY,
    RESOURCE_DIRECTORY,
    EXCEPTION_DIRECTORY,
    BASERELOC_DIRECTORY, // holds no pointers
    DEBUG_DIRECTORY,
    TLS_DIRECTORY,
    LOAD_CONFIG_DIRECTORY,
    DELAY_IMPORT_DIRECTORY,
];

fn reclaim(
    restored: &mut [u8],
    model: &PeModel,
    original: &Range<usize>,
    size: usize,
) -> Option<usize> {
    let align = model.section_alignment as usize;
    let mut rooms: Vec<&SectionModel> = model
        .sections
        .iter()
        .filter(|section| original.contains(&section.virtual_address().as_usize()))
        .collect();
    rooms.sort_by_key(|section| section.is_executable());

    for section in rooms {
        let start = section.virtual_address().as_usize();
        let header = section.header_offset + SECTION_VIRTUAL_SIZE_OFFSET;
        let grown_before = read_u32(restored, header).unwrap_or(0);
        let Some(at) = start
            .checked_add(section.held_size().max(grown_before) as usize)
            .and_then(|data_end| data_end.checked_next_multiple_of(TABLE_ALIGNMENT))
        else {
            continue;
        };
        let Some(end) = at.checked_add(size) else {
            continue;
        };
        let next = model
            .sections
            .iter()
            .map(|other| other.virtual_address().as_usize())
            .filter(|other| *other > start)
            .min()
            .unwrap_or(usize::MAX);
        let ceiling = next.min(at.next_multiple_of(align)).min(restored.len());

        let padding = restored
            .get(at..end)
            .filter(|_| end <= ceiling)
            .is_some_and(|room| room.iter().all(|byte| *byte == 0));
        if !padding {
            continue;
        }

        let Ok(grown) = u32::try_from(end - start) else {
            continue;
        };
        if write_u32(restored, header, grown).is_ok() {
            return Some(at);
        }
    }

    None
}

pub(crate) fn place_table(
    restored: &mut Vec<u8>,
    model: &PeModel,
    original: &Range<usize>,
    body: &[u8],
    name: &[u8; 8],
    kind: SectionKind,
) -> Option<usize> {
    match reclaim(restored, model, original, body.len()) {
        Some(at) => {
            restored
                .get_mut(at..at.checked_add(body.len())?)?
                .copy_from_slice(body);
            Some(at)
        }
        None => append(restored, model, name, kind, body),
    }
}

pub(crate) fn evacuate(
    restored: &mut Vec<u8>,
    model: &PeModel,
    original: &Range<usize>,
    block: &Range<usize>,
    name: &[u8; 8],
) -> bool {
    let resources_walk = model
        .directory(restored, RESOURCE_DIRECTORY)
        .is_none_or(|tree| walk_resources(restored, tree.rva().as_usize()).is_some());

    resources_walk // an unread tree may keep leaves in the block
        && (0..model.directory_count)
            .filter(|directory| !matches!(*directory, IMPORT_DIRECTORY | SECURITY_DIRECTORY))
            .all(|directory| move_out(restored, model, directory, original, block, name).is_some())
}

fn move_out(
    restored: &mut Vec<u8>,
    model: &PeModel,
    directory: usize,
    original: &Range<usize>,
    block: &Range<usize>,
    name: &[u8; 8],
) -> Option<()> {
    let Some(data) = model.directory(restored, directory) else {
        return Some(());
    };
    let rva = data.rva().as_usize();
    let size = data.size() as usize;
    if !block.contains(&rva) {
        return Some(());
    }

    if directory == IAT_DIRECTORY {
        model.clear_directory(restored, directory);
        return Some(());
    }

    let followed = FOLLOWED_DIRECTORIES.contains(&directory)
        && (directory != EXCEPTION_DIRECTORY || model.kind == PeKind::Pe32Plus); // runtime_functions reads x64 entries only
    followed.then_some(())?; // table_references could not vouch for what it points at

    let length = match directory {
        LOAD_CONFIG_DIRECTORY => load_config_length(restored, rva, size),
        _ => size,
    };
    let body = restored.get(rva..rva.checked_add(length)?)?.to_vec();
    let moved = place_table(restored, model, original, &body, name, SectionKind::Data)?;
    model.set_directory(restored, directory, moved, size)
}

pub(crate) fn table_references(restored: &[u8], model: &PeModel, base: usize) -> Vec<usize> {
    let tables = Tables {
        restored,
        model,
        base,
    };

    [
        tables.export_references(),
        tables.resource_references(),
        tables.unwind_references(),
        tables.tls_references(),
        tables.load_config_references(),
        tables.debug_references(),
        tables.delay_references(),
    ]
    .concat()
}

struct Tables<'a> {
    restored: &'a [u8],
    model: &'a PeModel,
    base: usize,
}

impl Tables<'_> {
    fn directory(&self, index: usize) -> Option<(usize, usize)> {
        self.model
            .directory(self.restored, index)
            .map(|data| (data.rva().as_usize(), data.size() as usize))
    }

    fn rva_at(&self, at: usize) -> Option<usize> {
        read_u32(self.restored, at).ok().map(|rva| rva as usize)
    }

    fn pointer_at(&self, at: usize) -> Option<usize> {
        read_pointer(self.restored, at, self.model.kind).ok()
    }

    fn export_references(&self) -> Vec<usize> {
        let Some((at, _)) = self.directory(EXPORT_DIRECTORY) else {
            return Vec::new();
        };

        let fields = EXPORT_RVA_OFFSETS
            .iter()
            .filter_map(|field| self.rva_at(at.saturating_add(*field)));
        let names = self
            .rva_at(at.saturating_add(EXPORT_NAMES_OFFSET))
            .unwrap_or(0);
        let count = self
            .rva_at(at.saturating_add(EXPORT_NAME_COUNT_OFFSET))
            .unwrap_or(0);
        let named = (0..count.min(MAX_TABLE_ENTRIES))
            .filter_map(|index| self.rva_at(names.saturating_add(index * EXPORT_ENTRY_SIZE)));

        fields.chain(named).collect()
    }

    fn tls_references(&self) -> Vec<usize> {
        let Some((at, _)) = self.directory(TLS_DIRECTORY) else {
            return Vec::new();
        };

        let width = self.model.kind.pointer_width();
        (0..TLS_POINTER_FIELDS)
            .filter_map(|field| self.pointer_at(at.saturating_add(field * width)))
            .filter_map(|address| address.checked_sub(self.base))
            .chain(tls_callbacks(self.restored, self.model, self.base))
            .collect()
    }

    fn resource_references(&self) -> Vec<usize> {
        let Some((root, _)) = self.directory(RESOURCE_DIRECTORY) else {
            return Vec::new();
        };
        let Some(tree) = walk_resources(self.restored, root) else {
            return Vec::new();
        };

        tree.data_entries
            .iter()
            .filter_map(|entry| self.rva_at(root.saturating_add(*entry)))
            .collect()
    }

    fn unwind_references(&self) -> Vec<usize> {
        runtime_functions(self.restored, self.model)
            .into_iter()
            .map(|function| function.unwind_info)
            .collect()
    }

    fn load_config_references(&self) -> Vec<usize> {
        let Some((at, declared)) = self.directory(LOAD_CONFIG_DIRECTORY) else {
            return Vec::new();
        };

        let length =
            load_config_length(self.restored, at, declared).min(MAX_LOAD_CONFIG_SIZE as usize);
        (0..length)
            .step_by(SCAN_STEP)
            .filter_map(|offset| self.pointer_at(at.saturating_add(offset)))
            .filter_map(|address| address.checked_sub(self.base)) // any field that reads as an address counts
            .collect()
    }

    fn debug_references(&self) -> Vec<usize> {
        let Some((at, size)) = self.directory(DEBUG_DIRECTORY) else {
            return Vec::new();
        };

        (0..(size / DEBUG_ENTRY_SIZE).min(MAX_TABLE_ENTRIES))
            .filter_map(|index| {
                self.rva_at(at.saturating_add(index * DEBUG_ENTRY_SIZE + DEBUG_ADDRESS_OFFSET))
            })
            .collect()
    }

    fn delay_references(&self) -> Vec<usize> {
        let Some((at, size)) = self.directory(DELAY_IMPORT_DIRECTORY) else {
            return Vec::new();
        };

        (0..(size / DELAY_DESCRIPTOR_SIZE).min(MAX_TABLE_ENTRIES))
            .map(|index| at.saturating_add(index * DELAY_DESCRIPTOR_SIZE))
            .take_while(|descriptor| {
                self.rva_at(descriptor.saturating_add(DELAY_NAME_OFFSET))
                    .is_some_and(|name| name != 0) // terminator descriptor
            })
            .flat_map(|descriptor| self.delay_descriptor_references(descriptor))
            .collect()
    }

    fn delay_descriptor_references(&self, descriptor: usize) -> Vec<usize> {
        let width = self.model.kind.pointer_width();
        let relative = self
            .rva_at(descriptor)
            .is_some_and(|attributes| attributes & DELAY_ATTRIBUTES_RVA_BASED as usize != 0);
        let to_rva = |value: usize| match relative {
            true => Some(value),
            false => value.checked_sub(self.base), // old linkers (delphi) write addresses
        };

        let fields = DELAY_RVA_FIELDS
            .iter()
            .filter_map(|field| self.rva_at(descriptor.saturating_add(*field)))
            .filter(|value| *value != 0)
            .filter_map(to_rva);
        let Some(lookups) = self
            .rva_at(descriptor.saturating_add(DELAY_INT_OFFSET))
            .filter(|lookups| *lookups != 0)
            .and_then(to_rva)
        else {
            return fields.collect(); // offset 0 would read the dos header
        };
        let names = (0..MAX_TABLE_ENTRIES)
            .map_while(|slot| {
                self.pointer_at(lookups.saturating_add(slot * width))
                    .filter(|entry| *entry != 0)
            })
            .filter(|entry| entry >> (width * 8 - 1) == 0)
            .filter_map(to_rva);

        fields.chain(names).collect()
    }
}
