use std::ops::Range;

use super::{
    DATA_SECTION, DEBUG_ENTRY_SIZE, SECTION_VIRTUAL_SIZE_OFFSET, append, clear_directory,
    load_config_length, set_directory,
};
use crate::pe::image::{read_pointer, read_u32, write_u32};
use crate::pe::{
    DEBUG_DIRECTORY, DELAY_IMPORT_DIRECTORY, EXPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY,
    LOAD_CONFIG_DIRECTORY, PeModel, SECURITY_DIRECTORY, SectionModel, TLS_DIRECTORY,
};

const TABLE_ALIGNMENT: usize = 16; // the loader refuses an unaligned load config, and the other tables want alignment too
const EXPORT_TABLE_FIELDS: [usize; 4] = [12, 28, 32, 36]; // Name, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
const EXPORT_NAME_COUNT: usize = 24;
const EXPORT_NAMES_RVA: usize = 32;
const DELAY_NAME_RVA: usize = 4;
const DELAY_RVA_FORM: usize = 1; // attributes bit 0: the fields are rvas, not addresses
const DELAY_LOOKUP_RVA: usize = 16;
const TLS_POINTER_FIELDS: usize = 4; // raw data start and end, index, callbacks
const DEBUG_RAW_DATA_RVA: usize = 20;
const DELAY_DESCRIPTOR_SIZE: usize = 32;
const DELAY_RVA_FIELDS: [usize; 5] = [4, 8, 12, 16, 20]; // name, module handle, iat, int, bound iat
const MAX_TABLE_ENTRIES: usize = 4096;

fn reclaim(
    restored: &mut [u8],
    model: &PeModel,
    original: &Range<usize>,
    size: usize,
) -> Option<usize> {
    let align = (model.section_alignment as usize).max(1); // a header may claim no alignment at all
    let mut rooms: Vec<&SectionModel> = model
        .sections()
        .iter()
        .filter(|section| original.contains(&section.virtual_address().as_usize()))
        .collect();
    rooms.sort_by_key(|section| section.is_executable());

    for section in rooms {
        let start = section.virtual_address().as_usize();
        let Some(at) = start
            .checked_add(section.held_size() as usize)
            .and_then(|data_end| data_end.checked_next_multiple_of(TABLE_ALIGNMENT))
        else {
            continue;
        };
        let Some(end) = at.checked_add(size) else {
            continue;
        };
        let next = model
            .sections()
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
        let header = section.header_offset + SECTION_VIRTUAL_SIZE_OFFSET;
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
    characteristics: u32,
) -> Option<usize> {
    match reclaim(restored, model, original, body.len()) {
        Some(at) => {
            restored
                .get_mut(at..at.checked_add(body.len())?)?
                .copy_from_slice(body);
            Some(at)
        }
        None => append(restored, model, name, characteristics, body),
    }
}

pub(crate) fn evacuate(
    restored: &mut Vec<u8>,
    model: &PeModel,
    original: &Range<usize>,
    block: &Range<usize>,
    name: &[u8; 8],
) -> bool {
    (0..model.directory_count)
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
    let Ok(Some(data)) = model.directory(restored, directory) else {
        return Some(());
    };
    let rva = data.rva().as_usize();
    let size = data.size() as usize;
    if !block.contains(&rva) {
        return Some(());
    }

    if directory == IAT_DIRECTORY {
        clear_directory(restored, model, directory); // the slots it listed stay where the program's code reaches them
        return Some(());
    }

    let length = match directory {
        LOAD_CONFIG_DIRECTORY => load_config_length(restored, rva, size),
        _ => size,
    };
    let body = restored.get(rva..rva.checked_add(length)?)?.to_vec();
    let moved = place_table(restored, model, original, &body, name, DATA_SECTION)?;
    set_directory(restored, model, directory, moved, size)
}

pub(crate) fn table_references(restored: &[u8], model: &PeModel, base: usize) -> Vec<usize> {
    let tables = Tables {
        restored,
        model,
        base,
    };

    [
        tables.export_references(),
        tables.tls_references(),
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
            .ok()
            .flatten()
            .map(|data| (data.rva().as_usize(), data.size() as usize))
    }

    fn rva_at(&self, at: usize) -> Option<usize> {
        read_u32(self.restored, at).ok().map(|rva| rva as usize)
    }

    fn pointer_at(&self, at: usize) -> Option<usize> {
        read_pointer(self.restored, at, self.model.kind()).ok()
    }

    fn export_references(&self) -> Vec<usize> {
        let Some((at, _)) = self.directory(EXPORT_DIRECTORY) else {
            return Vec::new();
        };

        let fields = EXPORT_TABLE_FIELDS
            .iter()
            .filter_map(|field| self.rva_at(at.saturating_add(*field)));
        let names = self
            .rva_at(at.saturating_add(EXPORT_NAMES_RVA))
            .unwrap_or(0);
        let count = self
            .rva_at(at.saturating_add(EXPORT_NAME_COUNT))
            .unwrap_or(0);
        let named = (0..count.min(MAX_TABLE_ENTRIES))
            .filter_map(|index| self.rva_at(names.saturating_add(index * 4)));

        fields.chain(named).collect()
    }

    fn tls_references(&self) -> Vec<usize> {
        let Some((at, _)) = self.directory(TLS_DIRECTORY) else {
            return Vec::new();
        };

        let width = self.model.kind().pointer_width();
        (0..TLS_POINTER_FIELDS)
            .filter_map(|field| self.pointer_at(at.saturating_add(field * width)))
            .filter_map(|address| address.checked_sub(self.base))
            .collect()
    }

    fn debug_references(&self) -> Vec<usize> {
        let Some((at, size)) = self.directory(DEBUG_DIRECTORY) else {
            return Vec::new();
        };

        (0..(size / DEBUG_ENTRY_SIZE).min(MAX_TABLE_ENTRIES))
            .filter_map(|index| {
                self.rva_at(at.saturating_add(index * DEBUG_ENTRY_SIZE + DEBUG_RAW_DATA_RVA))
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
                self.rva_at(descriptor.saturating_add(DELAY_NAME_RVA))
                    .is_some_and(|name| name != 0) // the zero descriptor that ends the table, whose rvas would read the headers
            })
            .flat_map(|descriptor| self.delay_descriptor_references(descriptor))
            .collect()
    }

    fn delay_descriptor_references(&self, descriptor: usize) -> Vec<usize> {
        let width = self.model.kind().pointer_width();
        let relative = self
            .rva_at(descriptor)
            .is_some_and(|attributes| attributes & DELAY_RVA_FORM != 0);
        let to_rva = |value: usize| match relative {
            true => Some(value),
            false => value.checked_sub(self.base), // older linkers such as delphi's write addresses
        };

        let fields = DELAY_RVA_FIELDS
            .iter()
            .filter_map(|field| self.rva_at(descriptor.saturating_add(*field)))
            .filter(|value| *value != 0)
            .filter_map(to_rva);
        let lookups = self
            .rva_at(descriptor.saturating_add(DELAY_LOOKUP_RVA))
            .and_then(to_rva)
            .unwrap_or(0);
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
