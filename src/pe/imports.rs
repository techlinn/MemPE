use std::collections::{BTreeMap, BTreeSet};

use crate::pe::exports::{ExportIndex, ResolvedExport, embedded_module_name};
use crate::pe::image;
use crate::pe::{
    IAT_DIRECTORY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    IMPORT_DIRECTORY, PeImage, PeKind, Rva,
};

const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const MAX_IMPORTS: usize = 65_536;
const MAX_IMPORT_GROUPS: usize = 4_096;
const MAX_IMPORT_NAME: usize = 4_096;
const MAX_THUNK_DEPTH: usize = 4;
const MAX_CODE_REFERENCE_BYTES: usize = 256 * 1024 * 1024;
const DELAY_IMPORT_DIRECTORY: usize = 13;
const DELAY_DESCRIPTOR_SIZE: usize = 32;
const DELAY_ATTRIBUTES_RVA_BASED: u32 = 0x1;
const DELAY_NAME_OFFSET: usize = 4;
const DELAY_IAT_OFFSET: usize = 12;
const DELAY_INT_OFFSET: usize = 16;
const DESCRIPTOR_ORIGINAL_THUNK_OFFSET: usize = 0;
const DESCRIPTOR_NAME_OFFSET: usize = 12;
const DESCRIPTOR_FIRST_THUNK_OFFSET: usize = 16;
const DESCRIPTOR_SCAN_STEP: usize = 4;
const MAX_DESCRIPTOR_SCAN_STEPS: usize = 1_000_000;
const MIN_AVERAGE_THUNKS: usize = 2;
const ATTESTED_MINIMUM_ENTRIES: usize = 1;
const SCANNED_MINIMUM_ENTRIES: usize = 2;
const CALL_JUMP_LENGTH: usize = 6;
const CALL_JUMP_PREFIX: u8 = 0xFF;
const CALL_MODRM: u8 = 0x15;
const JUMP_MODRM: u8 = 0x25;
const MOV_LOAD_LENGTH: usize = 7;
const MOV_REX_W: u8 = 0x48;
const MOV_REX_WR: u8 = 0x4C;
const MOV_LOAD_OPCODE: u8 = 0x8B;
const MODRM_RIP_MASK: u8 = 0xC7;
const MODRM_RIP_VALUE: u8 = 0x05;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reference {
    Called,
    Loaded,
}

pub(super) struct ImportEntry {
    pub(super) name: Option<String>,
    pub(super) ordinal: u32,
}

pub(super) struct ImportGroup {
    pub(super) module: String,
    pub(super) first_thunk: u32,
    pub(super) entries: Vec<ImportEntry>,
    source: ImportSource,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ImportSource {
    Attested,
    Scanned,
    Delayed,
    Inferred,
}

#[derive(Default)]
pub(super) struct ImportPlan {
    pub(super) groups: Vec<ImportGroup>,
    pub(super) recovered: usize,
    pub(super) ambiguous: usize,
    pub(super) aliased_names: usize,
    pub(super) unresolved_delay: usize,
    pub(super) unresolved_outside_image: usize,
    pub(super) unresolved_unknown_stub: usize,
    pub(super) unresolved_chain_exhausted: usize,
    pub(super) slots_outside_data_sections: usize,
    pub(super) recovered_attested: usize,
    pub(super) recovered_scanned: usize,
    pub(super) recovered_delayed: usize,
    pub(super) recovered_inferred: usize,
    pub(super) mixed_module_runs: usize,
    pub(super) slots_with_call_sites: usize,
    pub(super) existing: Vec<u8>,
    own: Option<String>,
}

pub(super) fn build_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
) -> ImportPlan {
    let mut plan = ImportPlan {
        own: embedded_module_name(image.bytes()),
        ..ImportPlan::default()
    };
    let referenced = find_referenced_slots(image, observed_base);
    match existing_descriptors(image).or_else(|| scan_for_orphaned_descriptors(image)) {
        Some(existing) => plan.existing = existing,
        None => scan_trusted_ranges(image, observed_base, exports, &referenced, &mut plan),
    }
    scan_delay_imports(image, observed_base, exports, &referenced, &mut plan);
    recover_referenced_imports(image, observed_base, exports, &referenced, &mut plan);
    plan
}

fn scan_trusted_ranges(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let memory = image.bytes();
    let model = image.model();
    let declared_iat = directory(image, IAT_DIRECTORY)
        .and_then(|(rva, size)| rva.checked_add(size).map(|end| (rva, end)));
    for section in model.sections() {
        if section.characteristics() & IMAGE_SCN_MEM_EXECUTE != 0
            || section.characteristics() & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) == 0
        {
            continue;
        }
        let section_start = section.virtual_address().get();
        let section_end = section_start.saturating_add(section.span());
        let trusted_range = declared_iat
            .and_then(|(start, end)| {
                let overlap_start = start.max(section_start);
                let overlap_end = end.min(section_end);
                (overlap_start < overlap_end).then_some(TrustedRange {
                    start: overlap_start,
                    end: overlap_end,
                    minimum: ATTESTED_MINIMUM_ENTRIES,
                    source: ImportSource::Attested,
                })
            })
            .or_else(|| {
                is_import_section(section.name()).then_some(TrustedRange {
                    start: section_start,
                    end: section_end,
                    minimum: SCANNED_MINIMUM_ENTRIES,
                    source: ImportSource::Scanned,
                })
            });
        let Some(trusted) = trusted_range else {
            continue;
        };
        let start = trusted.start as usize;
        let length = section.span() as usize;
        let end = (trusted.end as usize)
            .min((section_start as usize).saturating_add(length))
            .min(memory.len());
        scan_import_range(
            memory,
            observed_base,
            model.kind(),
            exports,
            ImportScan {
                start,
                end,
                minimum: trusted.minimum,
                source: trusted.source,
            },
            referenced,
            plan,
        );
        if plan.recovered >= MAX_IMPORTS || plan.groups.len() >= MAX_IMPORT_GROUPS {
            break;
        }
    }
}

fn scan_delay_imports(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let Some((directory_rva, directory_size)) = directory(image, DELAY_IMPORT_DIRECTORY) else {
        return;
    };
    if (directory_size as usize) < DELAY_DESCRIPTOR_SIZE {
        return;
    }
    let memory = image.bytes();
    let kind = image.model().kind();
    let width = kind.pointer_width();
    let already_recovered = collect_recovered_slots(plan, width);
    let max_descriptors = (directory_size as usize / DELAY_DESCRIPTOR_SIZE).min(MAX_IMPORT_GROUPS);
    let mut budget = MAX_IMPORTS;
    let mut unbound = 0usize;
    for index in 0..max_descriptors {
        if plan.recovered >= MAX_IMPORTS || plan.groups.len() >= MAX_IMPORT_GROUPS {
            break;
        }
        let Some(offset) =
            (directory_rva as usize).checked_add(index.saturating_mul(DELAY_DESCRIPTOR_SIZE))
        else {
            break;
        };
        let Some(descriptor) = memory.get(offset..offset.saturating_add(DELAY_DESCRIPTOR_SIZE))
        else {
            break;
        };
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let Some((start, end)) = delay_table_range(memory, descriptor, width, &mut budget) else {
            continue;
        };
        if u32::try_from(start).is_ok_and(|slot| already_recovered.contains(&slot)) {
            continue;
        }
        let scan = ImportScan {
            start,
            end,
            minimum: ATTESTED_MINIMUM_ENTRIES,
            source: ImportSource::Delayed,
        };
        unbound = unbound.saturating_add(unbound_delay_slots(
            memory,
            observed_base,
            kind,
            exports,
            &scan,
        ));
        scan_import_range(memory, observed_base, kind, exports, scan, referenced, plan);
    }
    plan.unresolved_delay = plan.unresolved_delay.saturating_add(unbound);
}

fn unbound_delay_slots(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    scan: &ImportScan,
) -> usize {
    let width = kind.pointer_width();
    let mut unbound = 0usize;
    let mut offset = scan.start;
    while offset.saturating_add(width) <= scan.end {
        let Some(value) = read_pointer(memory, offset, width) else {
            break;
        };
        if resolve_value(memory, observed_base, kind, value, exports).is_err() {
            unbound = unbound.saturating_add(1);
        }
        offset = offset.saturating_add(width);
    }
    unbound
}

fn delay_table_range(
    memory: &[u8],
    descriptor: &[u8],
    width: usize,
    budget: &mut usize,
) -> Option<(usize, usize)> {
    if read_u32(descriptor, 0)? & DELAY_ATTRIBUTES_RVA_BASED == 0 {
        return None;
    }
    read_ascii(memory, read_u32(descriptor, DELAY_NAME_OFFSET)? as usize)?;
    let iat_rva = read_u32(descriptor, DELAY_IAT_OFFSET)? as usize;
    let int_rva = read_u32(descriptor, DELAY_INT_OFFSET)? as usize;
    if iat_rva == 0
        || int_rva == 0
        || !iat_rva.is_multiple_of(width)
        || !int_rva.is_multiple_of(width)
    {
        return None;
    }
    let entries = delay_table_length(memory, iat_rva, width, budget)?;
    if entries == 0 || entries != delay_table_length(memory, int_rva, width, budget)? {
        return None;
    }
    let end = iat_rva.checked_add(entries.checked_mul(width)?)?;
    Some((iat_rva, end))
}

fn delay_table_length(
    memory: &[u8],
    start: usize,
    width: usize,
    budget: &mut usize,
) -> Option<usize> {
    for index in 0..*budget {
        *budget = budget.saturating_sub(1);
        let offset = start.checked_add(index.checked_mul(width)?)?;
        if read_pointer(memory, offset, width)? == 0 {
            return Some(index);
        }
    }
    None
}

struct ImportScan {
    start: usize,
    end: usize,
    minimum: usize,
    source: ImportSource,
}

struct TrustedRange {
    start: u32,
    end: u32,
    minimum: usize,
    source: ImportSource,
}

fn scan_import_range(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    scan: ImportScan,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let ImportScan {
        start,
        end,
        minimum,
        source,
    } = scan;
    let width = kind.pointer_width();
    let aligned_start = start.saturating_add((width - start % width) % width);
    let mut offset = aligned_start;
    while offset.saturating_add(width) <= end && plan.recovered < MAX_IMPORTS {
        let run_start = offset;
        let mut entries = Vec::<(u32, ResolvedExport)>::new();
        while offset.saturating_add(width) <= end && entries.len() < MAX_IMPORTS {
            let Some(value) = read_pointer(memory, offset, width) else {
                break;
            };
            let Ok((symbol, ambiguous, aliased)) =
                resolve_value(memory, observed_base, kind, value, exports)
            else {
                break;
            };
            if ambiguous {
                plan.ambiguous = plan.ambiguous.saturating_add(1);
                break;
            }
            if aliased {
                plan.aliased_names = plan.aliased_names.saturating_add(1);
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
        if entries.len() >= minimum && starts_cleanly && ends_cleanly {
            record_mixed_module_run(plan, &entries);
            append_groups(entries, width, minimum, source, referenced, plan);
        }
        if offset == run_start {
            offset = offset.saturating_add(width);
        }
    }
}

fn recover_referenced_imports(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    if plan.recovered >= MAX_IMPORTS || plan.groups.len() >= MAX_IMPORT_GROUPS {
        return;
    }
    let model = image.model();
    let memory = image.bytes();
    let kind = model.kind();
    let width = kind.pointer_width();
    let mut recovered = collect_recovered_slots(plan, width);
    recovered.append(&mut existing_thunk_slots(memory, &plan.existing, width));
    let remaining = MAX_IMPORTS.saturating_sub(plan.recovered);
    let mut entries = Vec::with_capacity(referenced.len().min(remaining));

    for (&slot, &reference) in referenced {
        if recovered.contains(&slot) || entries.len() >= remaining {
            continue;
        }
        if !slot_is_in_data_section(image, slot, width) {
            record_nondata_slot(plan, reference);
            continue;
        }
        let Some(value) = read_pointer(memory, slot as usize, width) else {
            continue;
        };
        let (symbol, ambiguous, aliased) =
            match resolve_value(memory, observed_base, kind, value, exports) {
                Ok(found) => found,
                Err(reason) => {
                    record_unresolved_call(plan, reference, reason);
                    continue;
                }
            };
        if ambiguous {
            plan.ambiguous = plan.ambiguous.saturating_add(1);
            continue;
        }
        if reference == Reference::Loaded
            && !neighbor_shares_module(memory, observed_base, kind, exports, slot, &symbol.module)
        {
            continue;
        }
        if aliased {
            plan.aliased_names = plan.aliased_names.saturating_add(1);
        }
        entries.push((slot, symbol));
    }

    append_groups(
        entries,
        width,
        1,
        ImportSource::Inferred,
        referenced,
        plan,
    );
}

fn image_offset(observed_base: usize, memory_length: usize, value: usize) -> Option<usize> {
    let offset = value.checked_sub(observed_base)?;
    (offset < memory_length).then_some(offset)
}

fn record_nondata_slot(plan: &mut ImportPlan, reference: Reference) {
    if reference != Reference::Called {
        return;
    }
    plan.slots_outside_data_sections = plan.slots_outside_data_sections.saturating_add(1);
}

fn record_unresolved_call(plan: &mut ImportPlan, reference: Reference, reason: Unresolved) {
    if reference != Reference::Called {
        return;
    }
    let counter = match reason {
        Unresolved::OwnImage => return,
        Unresolved::OutsideImage => &mut plan.unresolved_outside_image,
        Unresolved::UnknownStub => &mut plan.unresolved_unknown_stub,
        Unresolved::ChainExhausted => &mut plan.unresolved_chain_exhausted,
    };
    *counter = counter.saturating_add(1);
}

fn neighbor_shares_module(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    slot: u32,
    module: &str,
) -> bool {
    let width = kind.pointer_width();
    let step = width as u32;
    [slot.checked_sub(step), slot.checked_add(step)]
        .into_iter()
        .flatten()
        .filter_map(|neighbor| read_pointer(memory, neighbor as usize, width))
        .filter_map(|value| resolve_value(memory, observed_base, kind, value, exports).ok())
        .any(|(symbol, _, _)| symbol.module.eq_ignore_ascii_case(module))
}

fn find_referenced_slots(image: &PeImage<'_>, observed_base: usize) -> BTreeMap<u32, Reference> {
    let memory = image.bytes();
    let model = image.model();
    let mut slots = BTreeMap::new();
    let mut scanned = 0usize;
    for section in model.sections() {
        if !section.is_executable() || scanned >= MAX_CODE_REFERENCE_BYTES {
            continue;
        }
        let start = section.virtual_address().as_usize();
        let end = start
            .saturating_add(section.span() as usize)
            .min(memory.len());
        let Some(code) = memory.get(start..end) else {
            continue;
        };
        let remaining = MAX_CODE_REFERENCE_BYTES.saturating_sub(scanned);
        let scan_length = code.len().min(remaining);
        for index in 0..scan_length.saturating_sub(5) {
            let instruction = start.saturating_add(index);
            if let Some((slot, reference)) =
                decode_slot_reference(memory, observed_base, model.kind(), instruction)
            {
                let seen = slots.entry(slot).or_insert(reference);
                if reference == Reference::Called {
                    *seen = Reference::Called;
                }
                if slots.len() >= MAX_IMPORTS {
                    return slots;
                }
            }
        }
        scanned = scanned.saturating_add(scan_length);
    }
    slots
}

fn decode_slot_reference(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    instruction: usize,
) -> Option<(u32, Reference)> {
    if let Some(code) = memory.get(instruction..instruction.checked_add(CALL_JUMP_LENGTH)?)
        && code[0] == CALL_JUMP_PREFIX
        && matches!(code[1], CALL_MODRM | JUMP_MODRM)
    {
        let operand = u32::from_le_bytes([code[2], code[3], code[4], code[5]]);
        let slot = match kind {
            PeKind::Pe32 => {
                u32::try_from(usize::try_from(operand).ok()?.checked_sub(observed_base)?).ok()
            }
            PeKind::Pe32Plus => {
                rip_relative_slot(observed_base, instruction, CALL_JUMP_LENGTH, operand as i32)
            }
        };
        return Some((slot?, Reference::Called));
    }
    if kind != PeKind::Pe32Plus {
        return None;
    }
    let code = memory.get(instruction..instruction.checked_add(MOV_LOAD_LENGTH)?)?;
    if !matches!(code[0], MOV_REX_W | MOV_REX_WR)
        || code[1] != MOV_LOAD_OPCODE
        || code[2] & MODRM_RIP_MASK != MODRM_RIP_VALUE
    {
        return None;
    }
    let displacement = i32::from_le_bytes([code[3], code[4], code[5], code[6]]);
    let slot = rip_relative_slot(observed_base, instruction, MOV_LOAD_LENGTH, displacement)?;
    Some((slot, Reference::Loaded))
}

fn rip_relative_slot(
    observed_base: usize,
    instruction: usize,
    length: usize,
    displacement: i32,
) -> Option<u32> {
    let next = observed_base
        .checked_add(instruction)?
        .checked_add(length)?;
    let address = if displacement >= 0 {
        next.checked_add(displacement as usize)?
    } else {
        next.checked_sub(displacement.unsigned_abs() as usize)?
    };
    u32::try_from(address.checked_sub(observed_base)?).ok()
}

fn slot_is_in_data_section(image: &PeImage<'_>, slot: u32, width: usize) -> bool {
    if !(slot as usize).is_multiple_of(width) {
        return false;
    }
    let Some(end) = slot.checked_add(width as u32) else {
        return false;
    };
    if end as usize > image.bytes().len() {
        return false;
    }
    image.model().sections().iter().any(|section| {
        let start = section.virtual_address().get();
        let section_end = start.saturating_add(section.span());
        section.characteristics() & IMAGE_SCN_MEM_EXECUTE == 0
            && section.characteristics() & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) != 0
            && slot >= start
            && end <= section_end
    })
}

fn existing_thunk_slots(memory: &[u8], descriptors: &[u8], width: usize) -> BTreeSet<u32> {
    let mut slots = BTreeSet::new();
    for descriptor in descriptors.chunks_exact(IMPORT_DESCRIPTOR_SIZE) {
        let Some(first_thunk) = read_u32(descriptor, 16) else {
            continue;
        };
        for index in 0..MAX_IMPORTS {
            let Some(slot) = index
                .checked_mul(width)
                .and_then(|offset| u32::try_from(offset).ok())
                .and_then(|offset| first_thunk.checked_add(offset))
            else {
                break;
            };
            let Some(thunk) = read_pointer(memory, slot as usize, width) else {
                break;
            };
            if thunk == 0 {
                break;
            }
            slots.insert(slot);
        }
    }
    slots
}

fn collect_recovered_slots(plan: &ImportPlan, width: usize) -> BTreeSet<u32> {
    let mut slots = BTreeSet::new();
    for group in &plan.groups {
        for index in 0..group.entries.len() {
            let Some(offset) = index
                .checked_mul(width)
                .and_then(|value| u32::try_from(value).ok())
            else {
                continue;
            };
            if let Some(slot) = group.first_thunk.checked_add(offset) {
                slots.insert(slot);
            }
        }
    }
    slots
}

fn append_groups(
    entries: Vec<(u32, ResolvedExport)>,
    width: usize,
    minimum_entries: usize,
    source: ImportSource,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let mut current: Option<ImportGroup> = None;
    for (slot, symbol) in entries {
        if plan
            .own
            .as_deref()
            .is_some_and(|own| own.eq_ignore_ascii_case(&symbol.module))
        {
            continue;
        }
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
                commit_group(group, minimum_entries, width, referenced, plan);
            }
            current = Some(ImportGroup {
                module: symbol.module.clone(),
                first_thunk: slot,
                entries: Vec::new(),
                source,
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
        commit_group(group, minimum_entries, width, referenced, plan);
    }
}

fn commit_group(
    group: ImportGroup,
    minimum_entries: usize,
    width: usize,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let agreeing = count_referenced_slots(&group, width, referenced);
    let source = group.source;
    if !push_group(group, minimum_entries, plan) {
        return;
    }
    if !carries_call_site_evidence(source) {
        return;
    }
    plan.slots_with_call_sites = plan.slots_with_call_sites.saturating_add(agreeing);
}

fn carries_call_site_evidence(source: ImportSource) -> bool {
    matches!(source, ImportSource::Attested | ImportSource::Scanned)
}

fn count_referenced_slots(
    group: &ImportGroup,
    width: usize,
    referenced: &BTreeMap<u32, Reference>,
) -> usize {
    (0..group.entries.len())
        .filter_map(|index| {
            let offset = u32::try_from(index.checked_mul(width)?).ok()?;
            group.first_thunk.checked_add(offset)
        })
        .filter(|slot| referenced.contains_key(slot))
        .count()
}

fn record_mixed_module_run(plan: &mut ImportPlan, entries: &[(u32, ResolvedExport)]) {
    let modules = entries
        .iter()
        .map(|(_, symbol)| symbol.module.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if modules.len() > 1 {
        plan.mixed_module_runs = plan.mixed_module_runs.saturating_add(1);
    }
}

fn push_group(group: ImportGroup, minimum_entries: usize, plan: &mut ImportPlan) -> bool {
    let Some(recovered) = plan.recovered.checked_add(group.entries.len()) else {
        return false;
    };
    if group.entries.len() < minimum_entries
        || recovered > MAX_IMPORTS
        || plan.groups.len() >= MAX_IMPORT_GROUPS
    {
        return false;
    }
    record_recovered_tier(plan, group.source, group.entries.len());
    plan.recovered = recovered;
    plan.groups.push(group);
    true
}

fn record_recovered_tier(plan: &mut ImportPlan, source: ImportSource, entries: usize) {
    let counter = match source {
        ImportSource::Attested => &mut plan.recovered_attested,
        ImportSource::Scanned => &mut plan.recovered_scanned,
        ImportSource::Delayed => &mut plan.recovered_delayed,
        ImportSource::Inferred => &mut plan.recovered_inferred,
    };
    *counter = counter.saturating_add(entries);
}

fn is_import_section(name: &[u8; 8]) -> bool {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let value = &name[..end];
    value.eq_ignore_ascii_case(b".idata") || value.eq_ignore_ascii_case(b".didat")
}

enum Unresolved {
    OwnImage,
    OutsideImage,
    UnknownStub,
    ChainExhausted,
}

fn resolve_value(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    value: usize,
    exports: &ExportIndex,
) -> Result<(ResolvedExport, bool, bool), Unresolved> {
    let mut value = value;
    for _hop in 0..=MAX_THUNK_DEPTH {
        if let Some(found) = exports.resolve(value) {
            if image_offset(observed_base, memory.len(), value).is_some() {
                return Err(Unresolved::OwnImage);
            }
            return Ok((found.symbol.clone(), found.ambiguous, found.aliased));
        }
        let rva =
            image_offset(observed_base, memory.len(), value).ok_or(Unresolved::OutsideImage)?;
        let next = match kind {
            PeKind::Pe32Plus => decode_x64_thunk(memory, observed_base, rva),
            PeKind::Pe32 => decode_x86_thunk(memory, observed_base, rva),
        }
        .ok_or(Unresolved::UnknownStub)?;
        if next == value {
            return Err(Unresolved::ChainExhausted);
        }
        value = next;
    }
    Err(Unresolved::ChainExhausted)
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

fn existing_descriptors(image: &PeImage<'_>) -> Option<Vec<u8>> {
    let memory = image.bytes();
    let model = image.model();
    let (directory_rva, directory_size) = directory(image, IMPORT_DIRECTORY)?;
    if directory_size < IMPORT_DESCRIPTOR_SIZE as u32 {
        return None;
    }
    let max_descriptors = (directory_size as usize / IMPORT_DESCRIPTOR_SIZE).min(MAX_IMPORT_GROUPS);
    let mut descriptors = Vec::new();
    let mut budget = MAX_IMPORTS;
    for index in 0..max_descriptors {
        let offset =
            (directory_rva as usize).checked_add(index.saturating_mul(IMPORT_DESCRIPTOR_SIZE))?;
        let descriptor = memory.get(offset..offset.saturating_add(IMPORT_DESCRIPTOR_SIZE))?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return (!descriptors.is_empty()).then_some(descriptors);
        }
        let original_thunk = read_u32(memory, offset)?;
        let name_rva = read_u32(memory, offset.saturating_add(12))?;
        let first_thunk = read_u32(memory, offset.saturating_add(16))?;
        if read_ascii(memory, name_rva as usize).is_none()
            || !thunk_table_is_valid(
                memory,
                model.kind(),
                original_thunk,
                first_thunk,
                &mut budget,
            )
        {
            continue;
        }
        descriptors.extend_from_slice(descriptor);
    }
    (!descriptors.is_empty()).then_some(descriptors)
}

fn thunk_table_is_valid(
    memory: &[u8],
    kind: PeKind,
    original: u32,
    first: u32,
    budget: &mut usize,
) -> bool {
    thunk_table_length(memory, kind, original, first, budget).is_some()
}

fn thunk_table_length(
    memory: &[u8],
    kind: PeKind,
    original: u32,
    first: u32,
    budget: &mut usize,
) -> Option<usize> {
    let table = if original != 0 { original } else { first } as usize;
    let width = kind.pointer_width();
    let ordinal_flag = if kind == PeKind::Pe32 {
        0x8000_0000usize
    } else {
        0x8000_0000_0000_0000usize
    };
    for index in 0..*budget {
        let offset = table.checked_add(index.saturating_mul(width))?;
        let value = read_pointer(memory, offset, width)?;
        *budget = budget.saturating_sub(1);
        if value == 0 {
            return (index > 0).then_some(index);
        }
        if value & ordinal_flag == 0 {
            read_ascii(memory, value.checked_add(2)?)?;
        }
    }
    None
}

fn scan_for_orphaned_descriptors(image: &PeImage<'_>) -> Option<Vec<u8>> {
    let memory = image.bytes();
    let model = image.model();
    let mut steps = MAX_DESCRIPTOR_SCAN_STEPS;
    for section in model.sections() {
        if section.characteristics() & IMAGE_SCN_MEM_EXECUTE != 0
            || section.characteristics() & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) == 0
        {
            continue;
        }
        let start = section.virtual_address().as_usize();
        let end = start
            .saturating_add(section.span() as usize)
            .min(memory.len());
        let mut offset = start;
        while offset.saturating_add(IMPORT_DESCRIPTOR_SIZE) <= end && steps > 0 {
            steps = steps.saturating_sub(1);
            if let Some(found) = try_descriptor_array(memory, model.kind(), offset) {
                return Some(found);
            }
            offset = offset.saturating_add(DESCRIPTOR_SCAN_STEP);
        }
    }
    None
}

fn try_descriptor_array(memory: &[u8], kind: PeKind, start: usize) -> Option<Vec<u8>> {
    let mut descriptors = Vec::new();
    let mut thunks = 0usize;
    let mut budget = MAX_IMPORTS;
    for index in 0..MAX_IMPORT_GROUPS {
        let offset = start.checked_add(index.saturating_mul(IMPORT_DESCRIPTOR_SIZE))?;
        let descriptor = memory.get(offset..offset.saturating_add(IMPORT_DESCRIPTOR_SIZE))?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let original_thunk = read_u32(descriptor, DESCRIPTOR_ORIGINAL_THUNK_OFFSET)?;
        let name_rva = read_u32(descriptor, DESCRIPTOR_NAME_OFFSET)? as usize;
        let first_thunk = read_u32(descriptor, DESCRIPTOR_FIRST_THUNK_OFFSET)?;
        if name_rva == 0 || first_thunk == 0 || name_rva >= memory.len() {
            return None;
        }
        read_ascii(memory, name_rva)?;
        let length = thunk_table_length(memory, kind, original_thunk, first_thunk, &mut budget)?;
        thunks = thunks.saturating_add(length);
        descriptors.extend_from_slice(descriptor);
    }
    let count = descriptors.len() / IMPORT_DESCRIPTOR_SIZE;
    (count > 0 && thunks >= count.saturating_mul(MIN_AVERAGE_THUNKS)).then_some(descriptors)
}

fn directory(image: &PeImage<'_>, index: usize) -> Option<(u32, u32)> {
    let directory = image.directory(index).ok()??;
    Some((directory.rva().get(), directory.size()))
}

fn read_ascii(bytes: &[u8], offset: usize) -> Option<()> {
    let rva = u32::try_from(offset).ok().map(Rva)?;
    image::read_ascii(bytes, rva, MAX_IMPORT_NAME).map(|_| ())
}

fn read_pointer(bytes: &[u8], offset: usize, width: usize) -> Option<usize> {
    let kind = match width {
        4 => PeKind::Pe32,
        8 => PeKind::Pe32Plus,
        _ => return None,
    };
    image::read_pointer(bytes, offset, kind).ok()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    image::read_u32(bytes, offset).ok()
}

#[cfg(test)]
mod tests {
    use pelite::PeFile;

    use super::{
        IMPORT_DESCRIPTOR_SIZE, Reference, build_plan, decode_slot_reference, delay_table_range,
        rip_relative_slot, try_descriptor_array,
    };
    use crate::pe::parse::parse_memory_image;
    use crate::pe::{ExportIndex, PeKind, rebuild};

    #[test]
    fn recovers_a_lone_import_when_the_iat_directory_attests_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u64(&mut target, 0x2000, export_base as u64 + 0x1000);
        put_u32(&mut target, 0x98 + 112 + 12 * 8, 0x2000);
        put_u32(&mut target, 0x98 + 112 + 12 * 8 + 4, 8);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, 0x0000_7FF6_0000_0000, &index);

        assert_eq!(plan.recovered, 1);
        assert_eq!(plan.groups.len(), 1);
        Ok(())
    }

    #[test]
    fn still_rejects_a_lone_import_with_only_a_section_name_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u64(&mut target, 0x2000, export_base as u64 + 0x1000);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, 0x0000_7FF6_0000_0000, &index);

        assert_eq!(plan.recovered, 0);
        assert!(plan.groups.is_empty());
        Ok(())
    }

    #[test]
    fn finds_two_adjacent_resolved_imports() -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u64(&mut target, 0x2000, export_base as u64 + 0x1000);
        put_u64(&mut target, 0x2008, export_base as u64 + 0x1010);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, 0x0000_7FF6_0000_0000, &index);

        assert_eq!(plan.recovered, 2);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].module, "fixture.dll");

        let rebuilt = rebuild(&target, &[], 0x0000_7FF6_0000_0000, None, &index, None, &[])?;
        assert_eq!(rebuilt.imports_rebuilt, 2);
        assert_eq!(rebuilt.section_count, 3);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        assert!(
            rebuilt
                .bytes
                .windows(8)
                .any(|window| window == b".mempe\0\0")
        );
        Ok(())
    }

    #[test]
    fn finds_a_single_import_referenced_by_code() -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let target_base = 0x0000_7FF6_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u64(&mut target, 0x2000, export_base as u64 + 0x1000);
        let displacement = 0x2000i32 - 0x1006i32;
        target[0x1000..0x1002].copy_from_slice(&[0xFF, 0x15]);
        target[0x1002..0x1006].copy_from_slice(&displacement.to_le_bytes());
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, target_base, &index);

        assert_eq!(plan.recovered, 1);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].first_thunk, 0x2000);
        assert_eq!(plan.groups[0].entries.len(), 1);

        let rebuilt = rebuild(&target, &[], target_base, None, &index, None, &[])?;
        assert_eq!(rebuilt.imports_rebuilt, 1);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        Ok(())
    }

    #[test]
    fn ignores_an_unreferenced_single_import() -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u64(&mut target, 0x2000, export_base as u64 + 0x1000);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, 0x0000_7FF6_0000_0000, &index);

        assert_eq!(plan.recovered, 0);
        assert!(plan.groups.is_empty());
        Ok(())
    }

    #[test]
    fn merges_recovered_imports_with_a_valid_existing_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let target_base = 0x0000_7FF6_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = fixture_pe64(false);
        put_u32(&mut target, 0x98 + 112 + 8, 0x2100);
        put_u32(&mut target, 0x98 + 112 + 12, 40);
        put_u32(&mut target, 0x2100, 0x2200);
        put_u32(&mut target, 0x2100 + 12, 0x2300);
        put_u32(&mut target, 0x2100 + 16, 0x2400);
        put_u64(&mut target, 0x2200, 0x2280);
        put_u64(&mut target, 0x2400, export_base as u64 + 0x1010);
        target[0x2282..0x228b].copy_from_slice(b"Existing\0");
        target[0x2300..0x230a].copy_from_slice(b"other.dll\0");
        put_u64(&mut target, 0x2500, export_base as u64 + 0x1000);
        let fresh = 0x2500i32 - 0x1006i32;
        target[0x1000..0x1002].copy_from_slice(&[0xFF, 0x15]);
        target[0x1002..0x1006].copy_from_slice(&fresh.to_le_bytes());
        let covered = 0x2400i32 - 0x1016i32;
        target[0x1010..0x1012].copy_from_slice(&[0xFF, 0x15]);
        target[0x1012..0x1016].copy_from_slice(&covered.to_le_bytes());
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, target_base, &index);

        assert_eq!(plan.existing.len(), IMPORT_DESCRIPTOR_SIZE);
        assert_eq!(plan.recovered, 1);
        assert_eq!(plan.groups[0].first_thunk, 0x2500);

        let rebuilt = rebuild(&target, &[], target_base, None, &index, None, &[])?;
        let modules = PeFile::from_bytes(&rebuilt.bytes)?
            .imports()?
            .into_iter()
            .map(|descriptor| descriptor.dll_name().map(|name| name.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(modules, ["other.dll", "fixture.dll"]);
        Ok(())
    }

    #[test]
    fn decodes_an_x86_absolute_iat_reference() {
        let base = 0x0040_0000usize;
        let mut code = [0u8; 6];
        code[0..2].copy_from_slice(&[0xFF, 0x15]);
        code[2..6].copy_from_slice(&0x0040_2000u32.to_le_bytes());

        let slot = decode_slot_reference(&code, base, PeKind::Pe32, 0);

        assert_eq!(slot, Some((0x2000, Reference::Called)));
    }

    #[test]
    fn ignores_a_loaded_pointer_standing_alone_among_unrelated_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = plain_data_fixture();
        target[0x1000..0x1007].copy_from_slice(&[0x48, 0x8B, 0x05, 0xF9, 0x11, 0x00, 0x00]);
        put_u64(&mut target, 0x2200, export_base as u64 + 0x1000);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, 0x0000_7FF6_0000_0000, &index);

        assert_eq!(plan.recovered, 0);
        Ok(())
    }

    #[test]
    fn keeps_a_loaded_pointer_beside_a_slot_from_the_same_module()
    -> Result<(), Box<dyn std::error::Error>> {
        let export_base = 0x0000_7FFB_0000_0000usize;
        let export_image = fixture_pe64(true);
        let index = ExportIndex::build([(export_base, export_image.as_slice(), None)]);
        let mut target = plain_data_fixture();
        target[0x1000..0x1007].copy_from_slice(&[0x48, 0x8B, 0x05, 0xF9, 0x11, 0x00, 0x00]);
        put_u64(&mut target, 0x2200, export_base as u64 + 0x1000);
        put_u64(&mut target, 0x2208, export_base as u64 + 0x1010);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, 0x0000_7FF6_0000_0000, &index);

        assert_eq!(plan.recovered, 1);
        assert_eq!(plan.groups[0].module, "fixture.dll");
        Ok(())
    }

    #[test]
    fn never_records_an_image_as_importing_from_itself() -> Result<(), Box<dyn std::error::Error>> {
        let target_base = 0x0000_7FF6_0000_0000usize;
        let mut target = fixture_pe64(true);
        put_u64(&mut target, 0x2100, target_base as u64 + 0x1000);
        put_u64(&mut target, 0x2108, target_base as u64 + 0x1010);
        let index = ExportIndex::build([(target_base, target.as_slice(), None)]);
        let image = parse_memory_image(&target)?;

        let plan = build_plan(&image, target_base, &index);

        assert_eq!(plan.recovered, 0);
        assert!(plan.groups.is_empty());
        Ok(())
    }

    fn plain_data_fixture() -> Vec<u8> {
        let mut image = fixture_pe64(false);
        image[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
        image
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

    #[test]
    fn resolves_rip_relative_targets_in_both_directions() {
        let base = 0x0000_0001_4000_0000usize;
        assert_eq!(rip_relative_slot(base, 0x1000, 6, 0x100), Some(0x1106));
        assert_eq!(rip_relative_slot(base, 0x1000, 6, -0x100), Some(0x0F06));
        assert_eq!(rip_relative_slot(base, 0x1000, 7, 0), Some(0x1007));
        assert_eq!(rip_relative_slot(0, 0, 6, -100), None);
        assert_eq!(rip_relative_slot(base, 0x1000, 6, -0x4000_0000), None);
    }

    #[test]
    fn decodes_call_jump_and_register_load_forms() {
        let call = [0xFFu8, 0x15, 0x00, 0x01, 0x00, 0x00, 0x90];
        let jump = [0xFFu8, 0x25, 0x00, 0x01, 0x00, 0x00, 0x90];
        let mov_rax = [0x48u8, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00];
        let mov_r9 = [0x4Cu8, 0x8B, 0x0D, 0x00, 0x01, 0x00, 0x00];

        assert_eq!(
            decode_slot_reference(&call, 0, PeKind::Pe32Plus, 0),
            Some((0x106, Reference::Called))
        );
        assert_eq!(
            decode_slot_reference(&jump, 0, PeKind::Pe32Plus, 0),
            Some((0x106, Reference::Called))
        );
        assert_eq!(
            decode_slot_reference(&mov_rax, 0, PeKind::Pe32Plus, 0),
            Some((0x107, Reference::Loaded))
        );
        assert_eq!(
            decode_slot_reference(&mov_r9, 0, PeKind::Pe32Plus, 0),
            Some((0x107, Reference::Loaded))
        );
    }

    #[test]
    fn rejects_register_loads_that_are_not_rip_relative() {
        let mov_rbp = [0x48u8, 0x8B, 0x45, 0x00, 0x01, 0x00, 0x00];
        let add = [0x48u8, 0x03, 0x05, 0x00, 0x01, 0x00, 0x00];
        let mov_rax = [0x48u8, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00];

        assert_eq!(
            decode_slot_reference(&mov_rbp, 0, PeKind::Pe32Plus, 0),
            None
        );
        assert_eq!(decode_slot_reference(&add, 0, PeKind::Pe32Plus, 0), None);
        assert_eq!(decode_slot_reference(&mov_rax, 0, PeKind::Pe32, 0), None);
    }

    fn delay_fixture() -> Vec<u8> {
        let mut memory = vec![0u8; 0x200];
        memory[0x30..0x34].copy_from_slice(b"a.d\0");
        put_u64(&mut memory, 0x40, 0x1111);
        put_u64(&mut memory, 0x48, 0x2222);
        put_u64(&mut memory, 0x60, 0x3333);
        put_u64(&mut memory, 0x68, 0x4444);
        memory
    }

    fn delay_descriptor(attributes: u32, iat: u32, int: u32) -> Vec<u8> {
        let mut descriptor = vec![0u8; 32];
        descriptor[0..4].copy_from_slice(&attributes.to_le_bytes());
        descriptor[4..8].copy_from_slice(&0x30u32.to_le_bytes());
        descriptor[12..16].copy_from_slice(&iat.to_le_bytes());
        descriptor[16..20].copy_from_slice(&int.to_le_bytes());
        descriptor
    }

    #[test]
    fn accepts_a_delay_descriptor_whose_tables_agree() {
        let memory = delay_fixture();
        let descriptor = delay_descriptor(1, 0x40, 0x60);
        let mut budget = 1_000usize;

        assert_eq!(
            delay_table_range(&memory, &descriptor, 8, &mut budget),
            Some((0x40, 0x50))
        );
    }

    #[test]
    fn rejects_delay_descriptors_that_fail_any_gate() {
        let mut memory = delay_fixture();
        let mut budget = 1_000usize;

        let not_rva_based = delay_descriptor(0, 0x40, 0x60);
        assert_eq!(
            delay_table_range(&memory, &not_rva_based, 8, &mut budget),
            None
        );

        let misaligned = delay_descriptor(1, 0x41, 0x60);
        assert_eq!(
            delay_table_range(&memory, &misaligned, 8, &mut budget),
            None
        );

        put_u64(&mut memory, 0x70, 0x5555);
        let uneven = delay_descriptor(1, 0x40, 0x60);
        assert_eq!(delay_table_range(&memory, &uneven, 8, &mut budget), None);
    }

    fn descriptor_array_fixture(thunks: usize) -> Vec<u8> {
        let mut memory = vec![0u8; 0x400];
        memory[0x100..0x104].copy_from_slice(b"a.d\0");
        let descriptor = 0x200usize;
        memory[descriptor..descriptor + 4].copy_from_slice(&0x120u32.to_le_bytes());
        memory[descriptor + 12..descriptor + 16].copy_from_slice(&0x100u32.to_le_bytes());
        memory[descriptor + 16..descriptor + 20].copy_from_slice(&0x180u32.to_le_bytes());
        for index in 0..thunks {
            put_u64(&mut memory, 0x120 + index * 8, 0x8000_0000_0000_0001);
        }
        memory
    }

    #[test]
    fn accepts_a_descriptor_array_with_enough_thunks() {
        let memory = descriptor_array_fixture(2);

        let found = try_descriptor_array(&memory, PeKind::Pe32Plus, 0x200);

        assert_eq!(found.map(|bytes| bytes.len()), Some(IMPORT_DESCRIPTOR_SIZE));
    }

    #[test]
    fn rejects_a_descriptor_array_shaped_like_a_decoy() {
        let memory = descriptor_array_fixture(1);

        assert_eq!(try_descriptor_array(&memory, PeKind::Pe32Plus, 0x200), None);
    }
}
