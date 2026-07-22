use crate::pe::exports::{ExportIndex, ResolvedExport};
use crate::pe::{PeKind, PeModel};

const IMPORT_DIRECTORY: usize = 1;
const IAT_DIRECTORY: usize = 12;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const MAX_IMPORTS: usize = 65_536;
const MAX_IMPORT_GROUPS: usize = 4_096;
const MAX_IMPORT_NAME: usize = 4_096;
const MAX_THUNK_DEPTH: usize = 4;

pub(super) struct ImportEntry {
    pub(super) name: Option<String>,
    pub(super) ordinal: u32,
}

pub(super) struct ImportGroup {
    pub(super) module: String,
    pub(super) first_thunk: u32,
    pub(super) entries: Vec<ImportEntry>,
}

#[derive(Default)]
pub(super) struct ImportPlan {
    pub(super) groups: Vec<ImportGroup>,
    pub(super) recovered: usize,
    pub(super) ambiguous: usize,
    pub(super) existing_valid: bool,
}

pub(super) fn analyze(
    memory: &[u8],
    observed_base: usize,
    model: &PeModel,
    exports: &ExportIndex,
) -> ImportPlan {
    if existing_imports_are_valid(memory, model) {
        return ImportPlan {
            existing_valid: true,
            ..ImportPlan::default()
        };
    }
    let mut plan = ImportPlan::default();
    let declared_iat = directory(memory, model, IAT_DIRECTORY)
        .and_then(|(rva, size)| rva.checked_add(size).map(|end| (rva, end)));
    for section in &model.sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            || section.characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) == 0
        {
            continue;
        }
        let section_start = section.virtual_address.get();
        let section_end = section_start.saturating_add(section.virtual_size.max(section.raw_size));
        let trusted_range = declared_iat
            .and_then(|(start, end)| {
                let overlap_start = start.max(section_start);
                let overlap_end = end.min(section_end);
                (overlap_start < overlap_end).then_some((overlap_start, overlap_end))
            })
            .or_else(|| is_import_section(&section.name).then_some((section_start, section_end)));
        let Some((trusted_start, trusted_end)) = trusted_range else {
            continue;
        };
        let start = trusted_start as usize;
        let length = section.virtual_size.max(section.raw_size) as usize;
        let end = (trusted_end as usize)
            .min((section_start as usize).saturating_add(length))
            .min(memory.len());
        scan_section(
            memory,
            observed_base,
            model.kind,
            exports,
            start,
            end,
            &mut plan,
        );
        if plan.recovered >= MAX_IMPORTS || plan.groups.len() >= MAX_IMPORT_GROUPS {
            break;
        }
    }
    plan
}

fn scan_section(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    start: usize,
    end: usize,
    plan: &mut ImportPlan,
) {
    let width = if kind == PeKind::Pe32 { 4 } else { 8 };
    let aligned_start = start.saturating_add((width - start % width) % width);
    let mut offset = aligned_start;
    while offset.saturating_add(width) <= end && plan.recovered < MAX_IMPORTS {
        let run_start = offset;
        let mut entries = Vec::<(u32, ResolvedExport)>::new();
        while offset.saturating_add(width) <= end && entries.len() < MAX_IMPORTS {
            let Some(value) = read_pointer(memory, offset, width) else {
                break;
            };
            let Some((symbol, ambiguous)) =
                resolve_value(memory, observed_base, kind, value, exports)
            else {
                break;
            };
            if ambiguous {
                plan.ambiguous = plan.ambiguous.saturating_add(1);
                break;
            }
            let Ok(slot_rva) = u32::try_from(offset) else {
                break;
            };
            entries.push((slot_rva, symbol));
            offset = offset.saturating_add(width);
        }
        let starts_cleanly = run_start == aligned_start
            || run_start
                .checked_sub(width)
                .and_then(|before| read_pointer(memory, before, width))
                == Some(0);
        let ends_cleanly = read_pointer(memory, offset, width) == Some(0) || offset == end;
        if entries.len() >= 2 && starts_cleanly && ends_cleanly {
            append_groups(entries, width, plan);
        }
        if offset == run_start {
            offset = offset.saturating_add(width);
        }
    }
}

fn append_groups(entries: Vec<(u32, ResolvedExport)>, width: usize, plan: &mut ImportPlan) {
    let mut current: Option<ImportGroup> = None;
    for (slot, symbol) in entries {
        let same_module = current.as_ref().is_some_and(|group| {
            group.module.eq_ignore_ascii_case(&symbol.module)
                && group
                    .entries
                    .len()
                    .checked_mul(width)
                    .and_then(|offset| u32::try_from(offset).ok())
                    .and_then(|offset| group.first_thunk.checked_add(offset))
                    == Some(slot)
        });
        if !same_module {
            if let Some(group) = current.take() {
                push_group(group, plan);
            }
            current = Some(ImportGroup {
                module: symbol.module.clone(),
                first_thunk: slot,
                entries: Vec::new(),
            });
        }
        if let Some(group) = &mut current {
            group.entries.push(ImportEntry {
                name: symbol.name,
                ordinal: symbol.ordinal,
            });
        }
    }
    if let Some(group) = current {
        push_group(group, plan);
    }
}

fn push_group(group: ImportGroup, plan: &mut ImportPlan) {
    if group.entries.len() < 2 || plan.groups.len() >= MAX_IMPORT_GROUPS {
        return;
    }
    plan.recovered = plan.recovered.saturating_add(group.entries.len());
    plan.groups.push(group);
}

fn is_import_section(name: &[u8; 8]) -> bool {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let value = &name[..end];
    value.eq_ignore_ascii_case(b".idata") || value.eq_ignore_ascii_case(b".didat")
}

fn resolve_value(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    value: usize,
    exports: &ExportIndex,
) -> Option<(ResolvedExport, bool)> {
    let mut value = value;
    for _hop in 0..=MAX_THUNK_DEPTH {
        if let Some((symbol, ambiguous)) = exports.resolve(value) {
            return Some((symbol.clone(), ambiguous));
        }
        let rva = value.checked_sub(observed_base)?;
        let next = match kind {
            PeKind::Pe32Plus => decode_x64_thunk(memory, observed_base, rva),
            PeKind::Pe32 => decode_x86_thunk(memory, observed_base, rva),
        }?;
        if next == value {
            return None;
        }
        value = next;
    }
    None
}

fn decode_x64_thunk(memory: &[u8], base: usize, rva: usize) -> Option<usize> {
    let code = memory.get(rva..rva.checked_add(12)?)?;
    if code.starts_with(&[0xFF, 0x25]) {
        let displacement = i32::from_le_bytes([code[2], code[3], code[4], code[5]]) as i64;
        let slot_va = i64::try_from(base.checked_add(rva)?.checked_add(6)?).ok()?;
        let signed_base = i64::try_from(base).ok()?;
        let slot_rva = usize::try_from(
            slot_va
                .checked_add(displacement)?
                .checked_sub(signed_base)?,
        )
        .ok()?;
        return read_pointer(memory, slot_rva, 8);
    }
    if code[0..2] == [0x48, 0xB8] && code[10..12] == [0xFF, 0xE0] {
        return read_pointer(code, 2, 8);
    }
    None
}

fn decode_x86_thunk(memory: &[u8], base: usize, rva: usize) -> Option<usize> {
    let code = memory.get(rva..rva.checked_add(7)?)?;
    if code.starts_with(&[0xFF, 0x25]) {
        let slot_va = read_pointer(code, 2, 4)?;
        let slot_rva = slot_va.checked_sub(base)?;
        return read_pointer(memory, slot_rva, 4);
    }
    if code[0] == 0xB8 && code[5..7] == [0xFF, 0xE0] {
        return read_pointer(code, 1, 4);
    }
    None
}

fn existing_imports_are_valid(memory: &[u8], model: &PeModel) -> bool {
    let Some((directory_rva, directory_size)) = directory(memory, model, IMPORT_DIRECTORY) else {
        return false;
    };
    if directory_size < IMPORT_DESCRIPTOR_SIZE as u32 {
        return false;
    }
    let max_descriptors = (directory_size as usize / IMPORT_DESCRIPTOR_SIZE).min(MAX_IMPORT_GROUPS);
    let mut found = false;
    for index in 0..max_descriptors {
        let Some(offset) =
            (directory_rva as usize).checked_add(index.saturating_mul(IMPORT_DESCRIPTOR_SIZE))
        else {
            return false;
        };
        let Some(descriptor) = memory.get(offset..offset.saturating_add(IMPORT_DESCRIPTOR_SIZE))
        else {
            return false;
        };
        if descriptor.iter().all(|byte| *byte == 0) {
            return found;
        }
        let Some(original_thunk) = read_u32(memory, offset) else {
            return false;
        };
        let Some(name_rva) = read_u32(memory, offset + 12) else {
            return false;
        };
        let Some(first_thunk) = read_u32(memory, offset + 16) else {
            return false;
        };
        if read_ascii(memory, name_rva as usize).is_none()
            || !thunk_table_is_valid(memory, model.kind, original_thunk, first_thunk)
        {
            return false;
        }
        found = true;
    }
    false
}

fn thunk_table_is_valid(memory: &[u8], kind: PeKind, original: u32, first: u32) -> bool {
    let table = if original != 0 { original } else { first } as usize;
    let width = if kind == PeKind::Pe32 { 4 } else { 8 };
    let ordinal_flag = if kind == PeKind::Pe32 {
        0x8000_0000usize
    } else {
        0x8000_0000_0000_0000usize
    };
    for index in 0..MAX_IMPORTS {
        let Some(offset) = table.checked_add(index.saturating_mul(width)) else {
            return false;
        };
        let Some(value) = read_pointer(memory, offset, width) else {
            return false;
        };
        if value == 0 {
            return index > 0;
        }
        if value & ordinal_flag == 0 {
            let Some(name_offset) = value.checked_add(2) else {
                return false;
            };
            if read_ascii(memory, name_offset).is_none() {
                return false;
            }
        }
    }
    false
}

fn directory(bytes: &[u8], model: &PeModel, index: usize) -> Option<(u32, u32)> {
    if index >= model.directory_count {
        return None;
    }
    let offset = model
        .data_directory_offset
        .checked_add(index.checked_mul(8)?)?;
    let rva = read_u32(bytes, offset)?;
    let size = read_u32(bytes, offset.checked_add(4)?)?;
    (rva != 0 && size != 0).then_some((rva, size))
}

fn read_ascii(bytes: &[u8], offset: usize) -> Option<()> {
    let tail = bytes.get(offset..)?;
    let length = tail
        .iter()
        .take(MAX_IMPORT_NAME)
        .position(|byte| *byte == 0)?;
    (length > 0 && tail.get(..length)?.is_ascii()).then_some(())
}

fn read_pointer(bytes: &[u8], offset: usize, width: usize) -> Option<usize> {
    match width {
        4 => read_u32(bytes, offset).map(|value| value as usize),
        8 => {
            let value = bytes.get(offset..offset.checked_add(8)?)?;
            usize::try_from(u64::from_le_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ]))
            .ok()
        }
        _ => None,
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use pelite::PeFile;

    use super::analyze;
    use crate::pe::parse::parse_memory_image;
    use crate::pe::{ExportIndex, rebuild};

    #[test]
    fn finds_two_adjacent_resolved_imports() -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u64(&mut target, 0x2000, export_base as u64 + 0x1000);
        put_u64(&mut target, 0x2008, export_base as u64 + 0x1010);
        let model = parse_memory_image(&target)?;

        let plan = analyze(&target, 0x0000_7FF6_0000_0000, &model, &index);

        assert_eq!(plan.recovered, 2);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].module, "fixture.dll");

        let rebuilt = rebuild(&target, 0x0000_7FF6_0000_0000, None, &index)?;
        assert_eq!(rebuilt.imports_rebuilt, 2);
        assert_eq!(rebuilt.section_count, 3);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        Ok(())
    }

    fn fixture_pe64(with_exports: bool) -> Vec<u8> {
        let mut image = vec![0u8; 0x3000];
        put_u16(&mut image, 0, 0x5A4D);
        put_u32(&mut image, 0x3c, 0x80);
        put_u32(&mut image, 0x80, 0x0000_4550);
        put_u16(&mut image, 0x84, 0x8664);
        put_u16(&mut image, 0x86, 2);
        put_u16(&mut image, 0x94, 0xF0);
        put_u16(&mut image, 0x96, 0x22);
        let optional = 0x98;
        put_u16(&mut image, optional, 0x20B);
        put_u32(&mut image, optional + 16, 0x1000);
        put_u64(&mut image, optional + 24, 0x0000_7FF6_0000_0000);
        put_u32(&mut image, optional + 32, 0x1000);
        put_u32(&mut image, optional + 36, 0x200);
        put_u32(&mut image, optional + 56, 0x3000);
        put_u32(&mut image, optional + 60, 0x400);
        put_u32(&mut image, optional + 108, 16);
        let text = optional + 0xF0;
        image[text..text + 5].copy_from_slice(b".text");
        put_u32(&mut image, text + 8, 0x1000);
        put_u32(&mut image, text + 12, 0x1000);
        put_u32(&mut image, text + 16, 0x200);
        put_u32(&mut image, text + 36, 0x6000_0020);
        let data = text + 40;
        image[data..data + 6].copy_from_slice(b".idata");
        put_u32(&mut image, data + 8, 0x1000);
        put_u32(&mut image, data + 12, 0x2000);
        put_u32(&mut image, data + 16, 0x200);
        put_u32(&mut image, data + 36, 0x4000_0040);
        if with_exports {
            add_exports(&mut image, optional);
        }
        image
    }

    fn add_exports(image: &mut [u8], optional: usize) {
        put_u32(image, optional + 112, 0x2000);
        put_u32(image, optional + 116, 0x100);
        put_u32(image, 0x2000 + 12, 0x2080);
        put_u32(image, 0x2000 + 16, 1);
        put_u32(image, 0x2000 + 20, 2);
        put_u32(image, 0x2000 + 24, 2);
        put_u32(image, 0x2000 + 28, 0x2040);
        put_u32(image, 0x2000 + 32, 0x2048);
        put_u32(image, 0x2000 + 36, 0x2050);
        put_u32(image, 0x2040, 0x1000);
        put_u32(image, 0x2044, 0x1010);
        put_u32(image, 0x2048, 0x2090);
        put_u32(image, 0x204c, 0x2096);
        put_u16(image, 0x2050, 0);
        put_u16(image, 0x2052, 1);
        image[0x2080..0x208c].copy_from_slice(b"fixture.dll\0");
        image[0x2090..0x2096].copy_from_slice(b"First\0");
        image[0x2096..0x209d].copy_from_slice(b"Second\0");
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
