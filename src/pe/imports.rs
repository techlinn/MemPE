use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use crate::pe::exports::{ExportIndex, ResolvedExport, embedded_module_name};
use crate::pe::image;
use crate::pe::packers::{ImportedFunction, ModuleImports};
use crate::pe::{
    DELAY_IMPORT_DIRECTORY, IAT_DIRECTORY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, IMPORT_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeImage, PeKind, Rva,
};

const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const MAX_IMPORTS: usize = 65_536;
const MAX_IMPORT_GROUPS: usize = 4_096;
const MAX_IMPORT_NAME: usize = 4_096;
const MAX_THUNK_DEPTH: usize = 4;
const MAX_CODE_REFERENCE_BYTES: usize = 256 * 1024 * 1024;
const GUARD_CHECK_POINTER_PE32: usize = 0x48;
const GUARD_CHECK_POINTER_PE32_PLUS: usize = 0x70;
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
    aliased: bool,
}

struct SlotCandidate {
    slot: u32,
    symbol: ResolvedExport,
    aliased: bool,
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
    Packer,
}

#[derive(Default)]
pub(super) struct ImportPlan {
    pub(super) groups: Vec<ImportGroup>,
    pub(super) recovered: usize,
    pub(super) ambiguous: usize,
    pub(super) aliased_names: usize,
    pub(super) unresolved_delay: usize,
    pub(super) unresolved_other_module: usize,
    pub(super) unresolved_outside_image: usize,
    pub(super) unresolved_unknown_stub: usize,
    pub(super) unresolved_chain_exhausted: usize,
    pub(super) slots_outside_data_sections: usize,
    pub(super) recovered_attested: usize,
    pub(super) recovered_scanned: usize,
    pub(super) recovered_delayed: usize,
    pub(super) recovered_inferred: usize,
    pub(super) recovered_packer: usize,
    pub(super) mixed_module_runs: usize,
    pub(super) slots_with_call_sites: usize,
    pub(super) unrepresentable: usize,
    pub(super) keep_iat_directory: bool,
    pub(super) existing: Vec<u8>,
    own: Option<String>,
    ambiguous_slots: BTreeSet<u32>,
    unbound_delay_slots: BTreeSet<u32>,
}

impl ImportPlan {
    pub(super) fn import_tables(&self, kind: PeKind) -> Vec<Range<usize>> {
        self.groups
            .iter()
            .map(|group| {
                let start = group.first_thunk as usize;
                start
                    ..start.saturating_add(group.entries.len().saturating_mul(kind.pointer_width()))
            })
            .collect()
    }
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
    plan.ambiguous = plan.ambiguous_slots.len();
    plan.unresolved_delay = plan.unbound_delay_slots.len();
    plan
}

pub(super) fn build_restored_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    modules: Option<&[ModuleImports]>,
) -> ImportPlan {
    let mut plan = ImportPlan {
        keep_iat_directory: true,
        ..ImportPlan::default()
    };

    let referenced = find_referenced_slots(image, observed_base);

    match modules {
        Some(modules) => {
            for module in modules {
                add_packed_module(
                    image,
                    observed_base,
                    exports,
                    module,
                    &referenced,
                    &mut plan,
                );
            }
        }
        None => plan.existing = existing_descriptors(image).unwrap_or_default(),
    }

    scan_delay_imports(image, observed_base, exports, &referenced, &mut plan);
    plan.unresolved_delay = plan.unbound_delay_slots.len();
    plan
}

pub(super) fn build_iat_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    iat: (u32, u32),
) -> ImportPlan {
    let mut plan = ImportPlan {
        keep_iat_directory: true,
        ..ImportPlan::default()
    };

    let referenced = find_referenced_slots(image, observed_base);
    let (start, size) = (iat.0 as usize, iat.1 as usize);
    let scan = ImportScan {
        start,
        end: start.saturating_add(size),
        minimum: ATTESTED_MINIMUM_ENTRIES,
        source: ImportSource::Packer,
    };

    let kind = image.model().kind();
    scan_import_range(
        image.bytes(),
        observed_base,
        kind,
        exports,
        scan,
        &referenced,
        &mut plan,
    );
    scan_delay_imports(image, observed_base, exports, &referenced, &mut plan);
    recover_referenced_imports(image, observed_base, exports, &referenced, &mut plan);
    plan.ambiguous = plan.ambiguous_slots.len();
    plan.unresolved_delay = plan.unbound_delay_slots.len();
    plan
}

fn add_packed_module(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    module: &ModuleImports,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let width = image.model().kind().pointer_width();
    let slot_at = |index: usize| {
        u32::try_from(index.saturating_mul(width))
            .ok()
            .and_then(|offset| module.first_thunk.checked_add(offset))
    };

    let name = match module.module.is_empty() {
        true => owning_module(image, observed_base, exports, module, slot_at),
        false => Some(module.module.clone()),
    };
    let Some(name) = name else {
        plan.unrepresentable = plan.unrepresentable.saturating_add(module.functions.len());
        return;
    };

    let mut current: Option<ImportGroup> = None;
    for (index, function) in module.functions.iter().enumerate() {
        let slot = slot_at(index);
        let entry = slot.and_then(|slot| {
            let entry = packed_entry(image, observed_base, exports, &name, function, slot)?;
            is_representable(&name, entry.name.as_deref(), entry.ordinal).then_some(entry)
        });

        match (entry, slot) {
            (Some(entry), Some(slot)) => current
                .get_or_insert_with(|| ImportGroup {
                    module: name.clone(),
                    first_thunk: slot,
                    entries: Vec::new(),
                    source: ImportSource::Packer,
                })
                .entries
                .push(entry),
            _ => {
                plan.unrepresentable = plan.unrepresentable.saturating_add(1);

                if let Some(group) = current.take() {
                    commit_group(group, 1, width, referenced, plan);
                }
            }
        }
    }

    if let Some(group) = current {
        commit_group(group, 1, width, referenced, plan);
    }
}

fn owning_module(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    module: &ModuleImports,
    slot_at: impl Fn(usize) -> Option<u32>,
) -> Option<String> {
    let memory = image.bytes();
    let kind = image.model().kind();
    let resolved = |index: usize| {
        let value = read_pointer(memory, slot_at(index)? as usize, kind.pointer_width())?;
        resolve_value(memory, observed_base, kind, value, exports)
            .ok()
            .map(|(symbol, _, _)| symbol)
    };

    let matching = module
        .functions
        .iter()
        .enumerate()
        .find_map(|(index, function)| {
            let ImportedFunction::Name(name) = function else {
                return None;
            };

            resolved(index).filter(|symbol| symbol.name.as_deref() == Some(name.as_str()))
        });
    matching
        .map(|symbol| symbol.module)
        .or_else(|| covering_module(memory, kind, exports, module.functions.len(), &slot_at))
        .or_else(|| {
            (0..module.functions.len())
                .find_map(resolved)
                .map(|symbol| symbol.module)
        })
}

fn covering_module(
    memory: &[u8],
    kind: PeKind,
    exports: &ExportIndex,
    slots: usize,
    slot_at: impl Fn(usize) -> Option<u32>,
) -> Option<String> {
    let mut coverage = HashMap::<String, (usize, usize)>::new();
    for index in 0..slots {
        let Some(value) = slot_at(index)
            .and_then(|slot| read_pointer(memory, slot as usize, kind.pointer_width()))
        else {
            continue;
        };

        let mut seen = HashSet::new();
        for (module, forwarded) in exports.modules_at(value) {
            let module = module.to_ascii_lowercase();

            if seen.insert(module.clone()) {
                let counts = coverage.entry(module).or_default();
                counts.0 += 1;
                counts.1 += usize::from(forwarded);
            }
        }
    }

    coverage
        .into_iter()
        .max_by(|(left, left_counts), (right, right_counts)| {
            left_counts.cmp(right_counts).then_with(|| right.cmp(left))
        })
        .map(|(module, _)| module)
}

fn packed_entry(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    module: &str,
    function: &ImportedFunction,
    slot: u32,
) -> Option<ImportEntry> {
    match function {
        ImportedFunction::Name(name) => Some(ImportEntry {
            name: Some(name.clone()),
            ordinal: 0,
            aliased: false,
        }),
        ImportedFunction::Ordinal(ordinal) => Some(ImportEntry {
            name: None,
            ordinal: u32::from(*ordinal),
            aliased: false,
        }),
        ImportedFunction::NameFromAddress => {
            let value = slot_value(image, slot)?;
            exports
                .name_in(value, module)
                .map(|name| ImportEntry {
                    name: Some(name),
                    ordinal: 0,
                    aliased: false,
                })
                .or_else(|| exported_entry(image, observed_base, exports, value))
        }
        ImportedFunction::NameFromAddressAmong(listed) => {
            let value = slot_value(image, slot)?;
            let listed_name = exports
                .names_in(value, module)
                .find(|name| listed.contains(*name))
                .or_else(|| exports.names_at(value).find(|name| listed.contains(*name))); // api set names only match their host
            match listed_name {
                Some(name) => Some(ImportEntry {
                    name: Some(name.to_owned()),
                    ordinal: 0,
                    aliased: false,
                }),
                None => exports
                    .ordinal_in(value, module)
                    .map(|ordinal| ImportEntry {
                        name: None,
                        ordinal,
                        aliased: false,
                    }) // imported by ordinal, so no name was ever stored
                    .or_else(|| exported_entry(image, observed_base, exports, value)),
            }
        }
        ImportedFunction::OrdinalFromAddress => {
            let value = slot_value(image, slot)?;
            exports
                .ordinal_in(value, module)
                .map(|ordinal| ImportEntry {
                    name: None,
                    ordinal,
                    aliased: false,
                })
                .or_else(|| exported_entry(image, observed_base, exports, value))
        }
    }
}

fn slot_value(image: &PeImage<'_>, slot: u32) -> Option<usize> {
    read_pointer(
        image.bytes(),
        slot as usize,
        image.model().kind().pointer_width(),
    )
}

fn exported_entry(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    value: usize,
) -> Option<ImportEntry> {
    let kind = image.model().kind();
    let (symbol, ambiguous, aliased) =
        resolve_value(image.bytes(), observed_base, kind, value, exports).ok()?;
    (!ambiguous).then_some(ImportEntry {
        name: symbol.name,
        ordinal: symbol.ordinal,
        aliased,
    })
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

        let unbound = unbound_delay_slots(memory, observed_base, kind, exports, &scan);
        plan.unbound_delay_slots.extend(unbound);
        scan_import_range(memory, observed_base, kind, exports, scan, referenced, plan);
    }
}

fn unbound_delay_slots(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    scan: &ImportScan,
) -> BTreeSet<u32> {
    let width = kind.pointer_width();
    let mut unbound = BTreeSet::new();
    let mut offset = scan.start;

    while offset.saturating_add(width) <= scan.end {
        let Some(value) = read_pointer(memory, offset, width) else {
            break;
        };

        if resolve_value(memory, observed_base, kind, value, exports).is_err()
            && let Ok(slot) = u32::try_from(offset)
        {
            unbound.insert(slot);
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
        let mut entries = Vec::<SlotCandidate>::new();
        while offset.saturating_add(width) <= end && entries.len() < MAX_IMPORTS {
            let Some(value) = read_pointer(memory, offset, width) else {
                break;
            };

            let Ok(slot) = u32::try_from(offset) else {
                break;
            };

            let Ok((symbol, ambiguous, aliased)) =
                resolve_value(memory, observed_base, kind, value, exports)
            else {
                break;
            };

            if ambiguous {
                plan.ambiguous_slots.insert(slot);
                break;
            }

            entries.push(SlotCandidate {
                slot,
                symbol,
                aliased,
            });

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
    recovered.append(&mut guard_pointer_slots(image, observed_base)); // hold own no-op stubs without cfg
    let remaining = MAX_IMPORTS.saturating_sub(plan.recovered);
    let mut entries = Vec::with_capacity(referenced.len().min(remaining));
    for (&slot, &reference) in referenced {
        if recovered.contains(&slot)
            || plan.unbound_delay_slots.contains(&slot)
            || entries.len() >= remaining
        {
            continue;
        }

        if !slot_is_in_data_section(image, slot, width) {
            if reference == Reference::Called
                && slot_holds_import(memory, observed_base, kind, exports, slot)
            {
                plan.slots_outside_data_sections =
                    plan.slots_outside_data_sections.saturating_add(1);
            }

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
            plan.ambiguous_slots.insert(slot);
            continue;
        }

        if reference == Reference::Loaded
            && !neighbor_shares_module(memory, observed_base, kind, exports, slot, &symbol.module)
        {
            continue;
        }

        entries.push(SlotCandidate {
            slot,
            symbol,
            aliased,
        });
    }

    append_groups(entries, width, 1, ImportSource::Inferred, referenced, plan);
}

fn image_offset(observed_base: usize, memory_length: usize, value: usize) -> Option<usize> {
    let offset = value.checked_sub(observed_base)?;
    (offset < memory_length).then_some(offset)
}

fn guard_pointer_slots(image: &PeImage<'_>, observed_base: usize) -> BTreeSet<u32> {
    let Some((directory_rva, _)) = directory(image, LOAD_CONFIG_DIRECTORY) else {
        return BTreeSet::new();
    };

    let memory = image.bytes();
    let kind = image.model().kind();
    let width = kind.pointer_width();
    let directory_rva = directory_rva as usize;
    let declared = read_u32(memory, directory_rva).unwrap_or(0) as usize; // the load configs own size field

    let check_pointer = match kind {
        PeKind::Pe32 => GUARD_CHECK_POINTER_PE32,
        PeKind::Pe32Plus => GUARD_CHECK_POINTER_PE32_PLUS,
    };

    let dispatch_pointer = check_pointer.saturating_add(width);
    [check_pointer, dispatch_pointer]
        .into_iter()
        .filter(|offset| offset.saturating_add(width) <= declared)
        .filter_map(|offset| read_pointer(memory, directory_rva.checked_add(offset)?, width))
        .filter_map(|address| u32::try_from(address.checked_sub(observed_base)?).ok())
        .collect()
}

fn slot_holds_import(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    slot: u32,
) -> bool {
    let width = kind.pointer_width();

    if !(slot as usize).is_multiple_of(width) {
        return false;
    }

    read_pointer(memory, slot as usize, width)
        .and_then(|value| resolve_value(memory, observed_base, kind, value, exports).ok())
        .is_some_and(|(_, ambiguous, _)| !ambiguous)
}

fn record_unresolved_call(plan: &mut ImportPlan, reference: Reference, reason: Unresolved) {
    if reference != Reference::Called {
        return;
    }

    let counter = match reason {
        Unresolved::OwnImage => return,
        Unresolved::OtherModule => &mut plan.unresolved_other_module,
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
    for descriptor in descriptors.as_chunks::<IMPORT_DESCRIPTOR_SIZE>().0 {
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
    entries: Vec<SlotCandidate>,
    width: usize,
    minimum_entries: usize,
    source: ImportSource,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let mut current: Option<ImportGroup> = None;
    for SlotCandidate {
        slot,
        symbol,
        aliased,
    } in entries
    {
        if plan
            .own
            .as_deref()
            .is_some_and(|own| own.eq_ignore_ascii_case(&symbol.module))
        {
            continue;
        }

        if !is_representable(&symbol.module, symbol.name.as_deref(), symbol.ordinal) {
            plan.unrepresentable = plan.unrepresentable.saturating_add(1);
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
                aliased,
            });
        }
    }

    if let Some(group) = current {
        commit_group(group, minimum_entries, width, referenced, plan);
    }
}

fn is_representable(module: &str, name: Option<&str>, ordinal: u32) -> bool {
    module.is_ascii()
        && match name {
            Some(name) => name.is_ascii(),
            None => u16::try_from(ordinal).is_ok(), // ordinal thunks hold 16 bits
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
    let aliased = group.entries.iter().filter(|entry| entry.aliased).count();
    let source = group.source;

    if !push_group(group, minimum_entries, plan) {
        return;
    }

    plan.aliased_names = plan.aliased_names.saturating_add(aliased);

    if !carries_call_site_evidence(source) {
        return;
    }

    plan.slots_with_call_sites = plan.slots_with_call_sites.saturating_add(agreeing);
}

fn carries_call_site_evidence(source: ImportSource) -> bool {
    matches!(
        source,
        ImportSource::Attested | ImportSource::Scanned | ImportSource::Packer
    )
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

fn record_mixed_module_run(plan: &mut ImportPlan, entries: &[SlotCandidate]) {
    let modules = entries
        .iter()
        .map(|entry| entry.symbol.module.to_ascii_lowercase())
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
        ImportSource::Packer => &mut plan.recovered_packer,
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
    OtherModule,
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

        let Some(rva) = image_offset(observed_base, memory.len(), value) else {
            return Err(match exports.covers(value) {
                true => Unresolved::OtherModule,
                false => Unresolved::OutsideImage,
            });
        };

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
