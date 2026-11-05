use std::collections::{HashMap, HashSet};

use super::Restoration;
use super::resources::{MAX_RESOURCE_ENTRIES, RESOURCE_DATA_SIZE_OFFSET, walk_resources};
use crate::pe::image::{read_u16, read_u32, write_u16, write_u32};
use crate::pe::{PeModel, RESOURCE_DIRECTORY};

const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;
const ICON_GROUP_HEADER: usize = 6;
const ICON_GROUP_COUNT_OFFSET: usize = 4;
const ICON_GROUP_ENTRY_SIZE: usize = 14;
const ICON_ENTRY_PLANES_OFFSET: usize = 4;
const ICON_ENTRY_BITS_OFFSET: usize = 6;
const ICON_ENTRY_SIZE_OFFSET: usize = 8;
const ICON_ENTRY_ID_OFFSET: usize = 12;
const PNG_SIGNATURE: &[u8] = b"\x89PNG";
const PNG_WIDTH_OFFSET: usize = 16;
const PNG_HEIGHT_OFFSET: usize = 20;
const PNG_DEPTH_OFFSET: usize = 24;
const PNG_COLOR_TYPE_OFFSET: usize = 25;
const BITMAP_WIDTH_OFFSET: usize = 4;
const BITMAP_HEIGHT_OFFSET: usize = 8; // an icon bitmap counts its mask too, so twice the height
const BITMAP_PLANES_OFFSET: usize = 12;
const BITMAP_BITS_OFFSET: usize = 14;
const FULL_ICON_SIZE: u32 = 256; // stored as 0 in a one byte field

pub(crate) fn repair_icon_groups(restored: &mut [u8], model: &PeModel) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let root = directory.rva().as_usize();
    let icons = typed_leaves(restored, root, RT_ICON);
    let groups = typed_leaves(restored, root, RT_GROUP_ICON);

    let by_id = icons
        .iter()
        .map(|(id, rva, size)| (*id, (*rva, *size)))
        .collect::<HashMap<_, _>>();
    let icon_at = |id: u32| by_id.get(&id).copied();

    let entry_at = |group: usize, index: usize| {
        group
            .checked_add(ICON_GROUP_HEADER)?
            .checked_add(index.checked_mul(ICON_GROUP_ENTRY_SIZE)?)
    };
    let fits = |bytes: &[u8], entry: usize| {
        let id = read_u16(bytes, entry + ICON_ENTRY_ID_OFFSET).ok()?;
        let size = read_u32(bytes, entry + ICON_ENTRY_SIZE_OFFSET).ok()?;
        icon_at(u32::from(id))
            .filter(|(_, icon_size)| *icon_size == size as usize)
            .map(|_| id)
    };

    let mut broken = Vec::new();
    let mut referenced = HashSet::new();
    let mut budget = MAX_RESOURCE_ENTRIES;
    for (_, group, size) in &groups {
        let count = usize::from(read_u16(restored, group + ICON_GROUP_COUNT_OFFSET).unwrap_or(0));
        budget = match budget.checked_sub(count) {
            Some(left) => left,
            None => return Restoration::Failed,
        };

        for index in 0..count {
            let Some(entry) = entry_at(*group, index)
                .filter(|entry| entry + ICON_GROUP_ENTRY_SIZE <= group + size)
            else {
                return Restoration::Failed;
            };
            match fits(restored, entry) {
                Some(id) => {
                    referenced.insert(u32::from(id));
                }
                None => broken.push(entry),
            }
        }
    }

    if broken.is_empty() {
        return Restoration::Absent;
    }

    let mut spare = icons
        .iter()
        .filter(|(id, ..)| !referenced.contains(id))
        .map(|(id, rva, size)| (*id, *rva, *size))
        .collect::<Vec<_>>(); // the linker numbers icons in the order the groups list them
    spare.sort_unstable();
    if spare.len() < broken.len() {
        return Restoration::Failed;
    }

    for (entry, (id, rva, size)) in broken.into_iter().zip(spare) {
        let rebuilt = restored
            .get(rva..rva.saturating_add(size))
            .and_then(|icon| icon_group_entry(icon, id, size));
        let written = rebuilt.and_then(|rebuilt| {
            restored
                .get_mut(entry..entry.checked_add(ICON_GROUP_ENTRY_SIZE)?)?
                .copy_from_slice(&rebuilt);
            Some(())
        });
        if written.is_none() {
            return Restoration::Failed;
        }
    }

    Restoration::Restored
}

fn typed_leaves(bytes: &[u8], root: usize, kind: u32) -> Vec<(u32, usize, usize)> {
    let Some(tree) = walk_resources(bytes, root) else {
        return Vec::new();
    };

    tree.data_entries
        .iter()
        .zip(&tree.kinds)
        .filter(|(_, [type_id, _])| *type_id == kind)
        .filter_map(|(entry, [_, id])| {
            let at = root.checked_add(*entry)?;
            let rva = read_u32(bytes, at).ok()? as usize;
            let size = read_u32(bytes, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()? as usize;
            Some((*id, rva, size))
        })
        .collect()
}

fn icon_group_entry(icon: &[u8], id: u32, size: usize) -> Option<[u8; ICON_GROUP_ENTRY_SIZE]> {
    let byte_size = |value: u32| match value {
        FULL_ICON_SIZE => Some(0),
        _ => u8::try_from(value).ok(),
    };
    let big_endian = |at: usize| Some(u32::from_be_bytes(icon.get(at..at + 4)?.try_into().ok()?));

    let (width, height, colors, planes, bits) = if icon.starts_with(PNG_SIGNATURE) {
        let channels = match icon.get(PNG_COLOR_TYPE_OFFSET)? {
            0 | 3 => 1,
            2 => 3,
            4 => 2,
            6 => 4,
            _ => return None,
        };
        let bits = u16::from(*icon.get(PNG_DEPTH_OFFSET)?) * channels;
        (
            big_endian(PNG_WIDTH_OFFSET)?,
            big_endian(PNG_HEIGHT_OFFSET)?,
            0,
            1,
            bits,
        )
    } else {
        let bits = read_u16(icon, BITMAP_BITS_OFFSET).ok()?;
        let colors = if bits < 8 { 1u8 << bits } else { 0 };
        (
            read_u32(icon, BITMAP_WIDTH_OFFSET).ok()?,
            read_u32(icon, BITMAP_HEIGHT_OFFSET).ok()? / 2,
            colors,
            read_u16(icon, BITMAP_PLANES_OFFSET).ok()?,
            bits,
        )
    };

    let mut entry = [0u8; ICON_GROUP_ENTRY_SIZE];
    entry[0] = byte_size(width)?;
    entry[1] = byte_size(height)?;
    entry[2] = colors;
    write_u16(&mut entry, ICON_ENTRY_PLANES_OFFSET, planes).ok()?;
    write_u16(&mut entry, ICON_ENTRY_BITS_OFFSET, bits).ok()?;
    write_u32(
        &mut entry,
        ICON_ENTRY_SIZE_OFFSET,
        u32::try_from(size).ok()?,
    )
    .ok()?;
    write_u16(&mut entry, ICON_ENTRY_ID_OFFSET, u16::try_from(id).ok()?).ok()?;

    Some(entry)
}
