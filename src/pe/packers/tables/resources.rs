use std::collections::{HashMap, HashSet};
use std::ops::Range;

use super::{Restoration, is_free, set_directory};
use crate::pe::image::{read_u16, read_u32, write_u32};
use crate::pe::{PeModel, RESOURCE_DIRECTORY};

pub(crate) const RESOURCE_DATA_SIZE_OFFSET: usize = 4;
const RESOURCE_TABLE_SIZE: usize = 16;
const RESOURCE_NAMED_COUNT_OFFSET: usize = 12;
const RESOURCE_ID_COUNT_OFFSET: usize = 14;
const RESOURCE_ENTRY_SIZE: usize = 8;
const RESOURCE_ENTRY_TARGET_OFFSET: usize = 4;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const RESOURCE_SUBDIRECTORY: u32 = 0x8000_0000;
const MAX_RESOURCE_DEPTH: usize = 4;
pub(super) const MAX_RESOURCE_ENTRIES: usize = 65_536;
const LINKER_LEAF_ALIGNMENT: usize = 8;
const RESOURCE_LEAF_ALIGNMENTS: [usize; 2] = [LINKER_LEAF_ALIGNMENT, 4]; // windows only needs 4
pub(crate) const RESOURCE_SIZE_ALIGNMENT: usize = 8; // msvc pads the resource section to 8 bytes
const BORLAND_LEAF_ALIGNMENT: usize = 4;
const VISUAL_BASIC_FIRST_LEAF_ALIGNMENT: usize = 16;
const LINKER_VERSION_OFFSET: usize = 0x1A;
const BORLAND_LINKER: [u8; 2] = [2, 25];
const VISUAL_BASIC_RUNTIMES: [&str; 2] = ["msvbvm60.dll", "msvbvm50.dll"];
const BORLAND_RESOURCE: &[u8] = b"D\0V\0C\0L\0A\0L\0"; // every delphi and c++builder program carries this rcdata

pub(crate) struct ResourceTree {
    pub(crate) structure_length: usize,
    pub(crate) data_entries: Vec<usize>,
    pub(crate) kinds: Vec<[u32; 2]>, // type and name ids
}

pub(crate) fn walk_resources(bytes: &[u8], start: usize) -> Option<ResourceTree> {
    let mut tree = ResourceTree {
        structure_length: 0,
        data_entries: Vec::new(),
        kinds: Vec::new(),
    };

    let mut budget = MAX_RESOURCE_ENTRIES;
    walk_resource_table(bytes, start, 0, (0, [0; 2]), &mut tree, &mut budget)?;
    Some(tree)
}

fn walk_resource_table(
    bytes: &[u8],
    start: usize,
    table: usize,
    (depth, path): (usize, [u32; 2]),
    tree: &mut ResourceTree,
    budget: &mut usize,
) -> Option<()> {
    if depth >= MAX_RESOURCE_DEPTH || tree.data_entries.len() >= MAX_RESOURCE_ENTRIES {
        return None;
    }

    let header = start.checked_add(table)?;
    let named =
        usize::from(read_u16(bytes, header.checked_add(RESOURCE_NAMED_COUNT_OFFSET)?).ok()?);
    let numbered =
        usize::from(read_u16(bytes, header.checked_add(RESOURCE_ID_COUNT_OFFSET)?).ok()?);
    let count = named.checked_add(numbered)?;
    let entries_end = table
        .checked_add(RESOURCE_TABLE_SIZE)?
        .checked_add(count.checked_mul(RESOURCE_ENTRY_SIZE)?)?;
    tree.structure_length = tree.structure_length.max(entries_end);

    for index in 0..count {
        *budget = budget.checked_sub(1)?;
        let entry = header
            .checked_add(RESOURCE_TABLE_SIZE)?
            .checked_add(index.checked_mul(RESOURCE_ENTRY_SIZE)?)?;
        let name = read_u32(bytes, entry).ok()?;
        let target = read_u32(bytes, entry.checked_add(RESOURCE_ENTRY_TARGET_OFFSET)?).ok()?;

        if name & RESOURCE_SUBDIRECTORY != 0 {
            let string = (name & !RESOURCE_SUBDIRECTORY) as usize;
            let length = usize::from(read_u16(bytes, start.checked_add(string)?).ok()?);
            let string_end = string.checked_add(2)?.checked_add(length.checked_mul(2)?)?;
            tree.structure_length = tree.structure_length.max(string_end);
        }

        let offset = (target & !RESOURCE_SUBDIRECTORY) as usize;

        if target & RESOURCE_SUBDIRECTORY != 0 {
            let mut below = path;
            if let Some(level) = below.get_mut(depth) {
                *level = name;
            }
            walk_resource_table(
                bytes,
                start,
                offset,
                (depth.checked_add(1)?, below),
                tree,
                budget,
            )?;
        } else {
            let entry_end = offset.checked_add(RESOURCE_DATA_ENTRY_SIZE)?;
            tree.structure_length = tree.structure_length.max(entry_end);
            tree.data_entries.push(offset);
            tree.kinds.push(path);
        }
    }

    Some(())
}

pub(crate) fn return_moved_leaves(
    restored: &mut [u8],
    tree_start: usize,
    region: Range<usize>,
    original_end: usize,
) -> Restoration {
    let Some(tree) = walk_resources(restored, tree_start) else {
        return Restoration::Failed;
    };

    let leaves = tree
        .data_entries
        .iter()
        .filter_map(|entry| {
            let at = tree_start.checked_add(*entry)?;
            let rva = read_u32(restored, at).ok()? as usize;
            let size =
                read_u32(restored, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()? as usize;
            Some((at, rva, size))
        })
        .collect::<Vec<_>>();
    let moved = leaves
        .iter()
        .filter(|(_, rva, _)| *rva >= original_end)
        .copied()
        .collect::<Vec<_>>();
    if moved.is_empty() {
        return Restoration::Absent;
    }

    let mut used = leaves
        .iter()
        .filter(|(_, rva, _)| *rva < original_end)
        .map(|(_, rva, size)| (*rva, rva.saturating_add(*size)))
        .collect::<Vec<_>>();
    used.push((tree_start, tree_start.saturating_add(tree.structure_length)));

    for (entry, rva, size) in moved {
        let Some(data) = restored
            .get(rva..rva.saturating_add(size))
            .map(<[u8]>::to_vec)
        else {
            return Restoration::Failed;
        };

        let overlaps = |at: usize| {
            used.iter()
                .any(|(start, end)| at < *end && *start < at.saturating_add(size))
        };

        let Some(destination) = RESOURCE_LEAF_ALIGNMENTS.iter().find_map(|alignment| {
            (region.start..region.end.saturating_sub(size))
                .step_by(*alignment)
                .find(|at| !overlaps(*at) && is_free(restored, *at, &data))
        }) else {
            return Restoration::Failed;
        };

        let written = restored
            .get_mut(destination..destination.saturating_add(size))
            .map(|slot| slot.copy_from_slice(&data))
            .and_then(|()| write_u32(restored, entry, u32::try_from(destination).ok()?).ok());
        if written.is_none() {
            return Restoration::Failed;
        }

        used.push((destination, destination.saturating_add(size)));
    }

    Restoration::Restored
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ResourceLayout {
    Microsoft,
    Borland,
    VisualBasic,
}

pub(crate) fn resource_layout<'a>(
    bytes: &[u8],
    model: &PeModel,
    mut modules: impl Iterator<Item = &'a str>,
) -> ResourceLayout {
    if modules.any(|module| {
        VISUAL_BASIC_RUNTIMES
            .iter()
            .any(|runtime| module.eq_ignore_ascii_case(runtime))
    }) {
        return ResourceLayout::VisualBasic;
    }

    let at = model.nt_offset.saturating_add(LINKER_VERSION_OFFSET);
    let linker = bytes.get(at..at.saturating_add(BORLAND_LINKER.len()));
    let named = || {
        let root = model
            .directory(bytes, RESOURCE_DIRECTORY)
            .ok()??
            .rva()
            .as_usize();
        let tree = linker_resource_layout(bytes, root)?;
        Some(
            tree.bytes
                .windows(BORLAND_RESOURCE.len())
                .any(|name| name == BORLAND_RESOURCE),
        )
    };

    match linker == Some(&BORLAND_LINKER[..]) || named().unwrap_or(false) {
        true => ResourceLayout::Borland,
        false => ResourceLayout::Microsoft,
    }
}

pub(crate) fn lay_out_resources(
    restored: &mut [u8],
    model: &PeModel,
    packed_root: usize,
    section: Range<usize>,
    layout: ResourceLayout,
    pristine: Option<&[u8]>,
) -> Option<()> {
    let kept_size = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()
        .flatten()
        .map(|directory| directory.size() as usize);

    let mut tree = linker_resource_layout(restored, packed_root)?;
    let leaves = tree
        .data_entries
        .iter()
        .map(|entry| {
            let rva = read_u32(&tree.bytes, *entry).ok()? as usize;
            let size = read_u32(&tree.bytes, entry.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()?;
            pristine
                .unwrap_or(restored)
                .get(rva..rva.checked_add(size as usize)?)
                .map(<[u8]>::to_vec)
        })
        .collect::<Option<Vec<_>>>()?;

    let (first_alignment, alignment) = match layout {
        ResourceLayout::Microsoft => (LINKER_LEAF_ALIGNMENT, LINKER_LEAF_ALIGNMENT),
        ResourceLayout::Borland => (BORLAND_LEAF_ALIGNMENT, BORLAND_LEAF_ALIGNMENT),
        ResourceLayout::VisualBasic => (VISUAL_BASIC_FIRST_LEAF_ALIGNMENT, BORLAND_LEAF_ALIGNMENT),
    };
    let order: Vec<usize> = match layout {
        ResourceLayout::VisualBasic => (0..leaves.len()).rev().collect(), // vb6 writes them last entry first
        _ => (0..leaves.len()).collect(),
    };

    let mut cursor = section
        .start
        .checked_add(tree.bytes.len())?
        .checked_next_multiple_of(first_alignment)?;
    let mut placed = vec![0; leaves.len()];
    for index in order {
        cursor = cursor.checked_next_multiple_of(alignment)?;
        let entry = *tree.data_entries.get(index)?;
        write_u32(&mut tree.bytes, entry, u32::try_from(cursor).ok()?).ok()?;
        placed[index] = cursor - section.start;
        cursor = cursor.checked_add(leaves.get(index)?.len())?;
    }

    (cursor <= section.end).then_some(())?;

    let region = restored.get_mut(section.clone())?;
    region.fill(0);
    region
        .get_mut(..tree.bytes.len())?
        .copy_from_slice(&tree.bytes);
    for (offset, data) in placed.into_iter().zip(&leaves) {
        region
            .get_mut(offset..offset + data.len())?
            .copy_from_slice(data);
    }

    let used = cursor - section.start;
    let size = match kept_size {
        Some(kept) if kept >= used && section.start.checked_add(kept)? <= section.end => kept, // fsg keeps the original size
        _ => used.checked_next_multiple_of(RESOURCE_SIZE_ALIGNMENT)?,
    };
    set_directory(restored, model, RESOURCE_DIRECTORY, section.start, size)
}

pub(crate) struct LinkerTree {
    pub(crate) bytes: Vec<u8>,
    pub(crate) data_entries: Vec<usize>,
}

pub(crate) fn linker_resource_layout(bytes: &[u8], start: usize) -> Option<LinkerTree> {
    let entries_of = |table: usize| -> Option<Vec<(u32, u32)>> {
        let header = start.checked_add(table)?;
        let named = read_u16(bytes, header.checked_add(RESOURCE_NAMED_COUNT_OFFSET)?).ok()?;
        let numbered = read_u16(bytes, header.checked_add(RESOURCE_ID_COUNT_OFFSET)?).ok()?;

        (0..usize::from(named) + usize::from(numbered))
            .map(|index| {
                let entry =
                    header.checked_add(RESOURCE_TABLE_SIZE + index * RESOURCE_ENTRY_SIZE)?;
                let target = entry.checked_add(RESOURCE_ENTRY_TARGET_OFFSET)?;
                Some((read_u32(bytes, entry).ok()?, read_u32(bytes, target).ok()?))
            })
            .collect()
    };

    let mut tables = vec![(0usize, entries_of(0)?)]; // breadth first, the order msvc writes them in
    let mut seen = HashSet::from([0usize]);
    let mut total = tables[0].1.len();
    let mut next = 0;

    while let Some((_, entries)) = tables.get(next) {
        let children = entries
            .iter()
            .filter(|(_, target)| target & RESOURCE_SUBDIRECTORY != 0)
            .map(|(_, target)| (target & !RESOURCE_SUBDIRECTORY) as usize)
            .collect::<Vec<_>>();

        for child in children {
            seen.insert(child).then_some(())?; // a linker never shares or loops a table
            let entries = entries_of(child)?;
            total = total.checked_add(entries.len())?;
            (total <= MAX_RESOURCE_ENTRIES).then_some(())?;
            tables.push((child, entries));
        }
        next += 1;
    }

    let mut table_offsets = HashMap::new();
    let mut length = 0usize;
    for (table, entries) in &tables {
        table_offsets.insert(*table, length);
        length = length.checked_add(RESOURCE_TABLE_SIZE + entries.len() * RESOURCE_ENTRY_SIZE)?;
    }

    let mut leaves = Vec::new();
    let by_offset = tables
        .iter()
        .map(|(offset, entries)| (*offset, entries.as_slice()))
        .collect::<HashMap<_, _>>();
    collect_leaves(&by_offset, 0, 0, &mut leaves)?; // depth first, unlike the tables

    let mut leaf_offsets = HashMap::new();
    for leaf in &leaves {
        leaf_offsets.insert(*leaf, length);
        length = length.checked_add(RESOURCE_DATA_ENTRY_SIZE)?;
    }

    let mut string_offsets = HashMap::new();
    let mut strings = Vec::new();
    for (name, _) in tables.iter().flat_map(|(_, entries)| entries) {
        if name & RESOURCE_SUBDIRECTORY == 0 {
            continue;
        }

        let at = start.checked_add((name & !RESOURCE_SUBDIRECTORY) as usize)?;
        let units = usize::from(read_u16(bytes, at).ok()?);
        let string = bytes.get(at..at.checked_add(2 + units * 2)?)?;

        if !string_offsets.contains_key(string) {
            string_offsets.insert(string, length);
            strings.push(string);
            length = length.checked_add(string.len())?;
        }
    }

    let mut layout = vec![0u8; length];
    let named_string = |name: u32| -> Option<u32> {
        let at = start.checked_add((name & !RESOURCE_SUBDIRECTORY) as usize)?;
        let units = usize::from(read_u16(bytes, at).ok()?);
        let offset = string_offsets.get(bytes.get(at..at.checked_add(2 + units * 2)?)?)?;
        Some(u32::try_from(*offset).ok()? | RESOURCE_SUBDIRECTORY)
    };

    for (table, entries) in &tables {
        let to = *table_offsets.get(table)?;
        let from = start.checked_add(*table)?;
        layout
            .get_mut(to..to + RESOURCE_TABLE_SIZE)?
            .copy_from_slice(bytes.get(from..from.checked_add(RESOURCE_TABLE_SIZE)?)?);

        for (index, (name, target)) in entries.iter().enumerate() {
            let name = match name & RESOURCE_SUBDIRECTORY {
                0 => *name,
                _ => named_string(*name)?,
            };
            let offset = (target & !RESOURCE_SUBDIRECTORY) as usize;
            let target = match target & RESOURCE_SUBDIRECTORY {
                0 => u32::try_from(*leaf_offsets.get(&offset)?).ok()?,
                _ => u32::try_from(*table_offsets.get(&offset)?).ok()? | RESOURCE_SUBDIRECTORY,
            };

            let entry = to + RESOURCE_TABLE_SIZE + index * RESOURCE_ENTRY_SIZE;
            write_u32(&mut layout, entry, name).ok()?;
            write_u32(&mut layout, entry + RESOURCE_ENTRY_TARGET_OFFSET, target).ok()?;
        }
    }

    for leaf in &leaves {
        let to = *leaf_offsets.get(leaf)?;
        let from = start.checked_add(*leaf)?;
        layout
            .get_mut(to..to + RESOURCE_DATA_ENTRY_SIZE)?
            .copy_from_slice(bytes.get(from..from.checked_add(RESOURCE_DATA_ENTRY_SIZE)?)?);
    }

    for string in strings {
        let to = *string_offsets.get(string)?;
        layout
            .get_mut(to..to + string.len())?
            .copy_from_slice(string);
    }

    let data_entries = leaves
        .iter()
        .map(|leaf| leaf_offsets.get(leaf).copied())
        .collect::<Option<Vec<_>>>()?;

    Some(LinkerTree {
        bytes: layout,
        data_entries,
    })
}

fn collect_leaves(
    tables: &HashMap<usize, &[(u32, u32)]>,
    table: usize,
    depth: usize,
    leaves: &mut Vec<usize>,
) -> Option<()> {
    (depth < MAX_RESOURCE_DEPTH).then_some(())?;
    let entries = tables.get(&table)?;

    for (_, target) in entries.iter() {
        let offset = (target & !RESOURCE_SUBDIRECTORY) as usize;
        match target & RESOURCE_SUBDIRECTORY {
            0 => leaves.push(offset),
            _ => collect_leaves(tables, offset, depth + 1, leaves)?,
        }
    }

    Some(())
}

pub(crate) fn lowest_moved_leaf(restored: &[u8], model: &PeModel, end: usize) -> Option<usize> {
    let root = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()??
        .rva()
        .as_usize();
    let tree = walk_resources(restored, root)?;

    tree.data_entries
        .iter()
        .filter_map(|entry| Some(read_u32(restored, root.checked_add(*entry)?).ok()? as usize))
        .filter(|rva| *rva < end)
        .min()
}

pub(crate) fn restore_moved_resources(
    restored: &mut [u8],
    model: &PeModel,
    sections: &[Range<usize>],
    end: usize,
    layout: ResourceLayout,
    pristine: Option<&[u8]>,
) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let root = directory.rva().as_usize();
    if root < end {
        return Restoration::Absent;
    }

    let Some(leaf) = lowest_moved_leaf(restored, model, end) else {
        return Restoration::Absent; // every resource stayed in the packer's section
    };

    let laid_out = sections
        .iter()
        .find(|section| section.contains(&leaf))
        .and_then(|section| {
            lay_out_resources(restored, model, root, section.clone(), layout, pristine)
        });
    match laid_out {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

pub(crate) fn resources_intact(bytes: &[u8], start: usize) -> bool {
    walk_resources(bytes, start).is_some_and(|tree| {
        !tree.data_entries.is_empty()
            && tree.data_entries.iter().all(|entry| {
                read_u32(bytes, start.saturating_add(*entry))
                    .is_ok_and(|rva| rva != 0 && (rva as usize) < bytes.len())
            })
    })
}
