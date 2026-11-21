mod code_references;
mod delay_imports;
mod descriptors;
mod iat_scan;
mod module_lookup;
mod resolve_slot;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

pub(crate) use self::code_references::code_referenced_slots;
use self::code_references::{
    Addressed, CodeReferences, Reference, find_code_references, recover_referenced_imports,
};
use self::delay_imports::scan_delay_imports;
use self::descriptors::{read_descriptors, rescan_rejected, scan_for_orphaned_descriptors};
use self::iat_scan::{ImportScan, append_groups, scan_import_range, scan_trusted_ranges};
use self::module_lookup::add_packed_module;
use self::resolve_slot::{Unresolved, resolve_value};
use crate::pe::bytes;
use crate::pe::exports::{ExportIndex, ExportSymbol, embedded_module_name};
use crate::pe::import_list::{ModuleImports, NameHint, NameHints};
use crate::pe::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, PeImage, PeKind, SectionModel};
use crate::pe::{MAX_IMPORT_DESCRIPTORS, MAX_IMPORTS, MAX_NAME_LENGTH};
use crate::unpack::x86::compiler_entry::{MSVC_STARTUP_IMPORTS, msvc_startup_slots};

pub(crate) struct ImportEntry {
    pub(crate) name: Option<String>,
    pub(crate) ordinal: u32,
    aliased: bool,
}

struct SlotCandidate {
    slot: u32,
    value: usize,
    symbol: ExportSymbol,
    aliased: bool,
}

pub(crate) struct ImportGroup {
    pub(crate) module: String,
    pub(crate) first_thunk: u32,
    pub(crate) entries: Vec<ImportEntry>,
    source: ImportSource,
}

impl ImportGroup {
    fn end(&self, width: usize) -> usize {
        (self.first_thunk as usize).saturating_add(self.entries.len().saturating_mul(width))
    }

    fn slots(&self, width: usize) -> impl Iterator<Item = u32> + '_ {
        (0..self.entries.len()).filter_map(move |index| {
            let offset = u32::try_from(index.checked_mul(width)?).ok()?;
            self.first_thunk.checked_add(offset)
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ImportSource {
    Attested,
    Scanned,
    Delayed,
    Inferred,
    Packer,
}

counters!(ImportCounts {
    lost_import_slots,
    unresolved_delay,
    unresolved_other_module,
    unresolved_outside_image,
    unresolved_unknown_stub,
    unresolved_chain_exhausted,
    slots_outside_data_sections,
    recovered_attested,
    recovered_scanned,
    recovered_delayed,
    recovered_inferred,
    recovered_packer,
    mixed_module_runs,
    tied_module_runs,
    runtime_lookup_slots,
    packer_slots_skipped,
    skipped_delay_descriptors,
    rival_import_tables,
    table_located_by_scan, // flags count images, 0 or 1 per plan
    descriptor_scan_truncated,
    code_scan_truncated,
    unreliable_section_flags,
    slots_with_call_sites,
    ambiguous_imports,
    aliased_names,
});

#[derive(Default)]
pub(crate) struct ImportPlan {
    pub(crate) groups: Vec<ImportGroup>,
    pub(crate) recovered: usize,
    pub(crate) counts: ImportCounts,
    pub(crate) unrepresentable: usize,
    pub(crate) keep_iat_directory: bool,
    pub(crate) existing: Vec<u8>,
    pub(crate) rejected_descriptors: usize,
    pub(crate) unresolved_table_slots: usize, // these six fold into counts.lost_import_slots
    pub(crate) refused_scanned_slots: usize,
    pub(crate) refused_variable_slots: usize,
    pub(crate) lone_slots_dropped: usize,
    pub(crate) undetermined_module_slots: usize,
    pub(crate) own_module_slots: usize,
    name_hints: NameHints,
    startup_hints: NameHints,
    own: Option<String>,
    ambiguous_slots: BTreeSet<u32>,
    unbound_delay_slots: BTreeSet<u32>,
    stored_slots: BTreeSet<u32>,
    stores_unseen: bool,
    packer_ranges: Vec<Range<usize>>,
}

impl ImportPlan {
    pub(crate) fn import_tables(&self, kind: PeKind) -> Vec<Range<usize>> {
        self.groups
            .iter()
            .map(|group| group.first_thunk as usize..group.end(kind.pointer_width()))
            .collect()
    }

    fn stores_to(&self, slot: u32) -> bool {
        self.stored_slots.contains(&slot) // the loader alone writes a linker import slot
    }

    fn packer_owns(&self, slot: u32) -> bool {
        self.packer_ranges
            .iter()
            .any(|range| range.contains(&(slot as usize)))
    }
}

pub(crate) fn build_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    packer: &[Range<usize>],
) -> ImportPlan {
    let (mut plan, referenced) = start_plan(image, observed_base, packer);

    let declared = read_descriptors(image, exports);
    let rejected = declared.rejected;
    let existing = Some(declared.kept)
        .filter(|kept| !kept.is_empty())
        .or_else(|| sole_orphaned_table(image, exports, &mut plan));

    match existing {
        Some(existing) => {
            plan.existing = existing;
            plan.rejected_descriptors = rejected.len();
            rescan_rejected(
                image,
                observed_base,
                exports,
                &rejected,
                &referenced,
                &mut plan,
            );
        }
        None => scan_trusted_ranges(image, observed_base, exports, &referenced, &mut plan),
    }

    scan_delay_imports(image, observed_base, exports, &referenced, &mut plan);
    recover_referenced_imports(image, observed_base, exports, &referenced, &mut plan);
    finish_plan(&mut plan, image.model().kind.pointer_width());
    plan
}

pub(crate) fn build_restored_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    modules: Option<&[ModuleImports]>,
    packer: &[Range<usize>],
) -> ImportPlan {
    let (mut plan, referenced) = start_plan(image, observed_base, packer);
    plan.keep_iat_directory = true;

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
        None => {
            let declared = read_descriptors(image, exports);
            plan.existing = declared.kept;
            plan.rejected_descriptors = declared.rejected.len();
            let rejected = &declared.rejected;
            rescan_rejected(
                image,
                observed_base,
                exports,
                rejected,
                &referenced,
                &mut plan,
            );
        }
    }

    scan_delay_imports(image, observed_base, exports, &referenced, &mut plan);
    finish_plan(&mut plan, image.model().kind.pointer_width());
    plan
}

pub(crate) fn build_iat_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    iat: (u32, u32),
    names: &NameHints,
    packer: &[Range<usize>],
) -> ImportPlan {
    let (mut plan, mut referenced) = start_plan(image, observed_base, packer);
    plan.keep_iat_directory = true;
    plan.name_hints = names.clone();

    let (start, size) = (iat.0 as usize, iat.1 as usize);
    let scan = ImportScan {
        start,
        end: start.saturating_add(size),
        source: ImportSource::Packer,
    };

    let kind = image.model().kind;
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

    let pointed_at = pointed_at_variable_slots(image, observed_base, exports, &plan);
    for slot in &pointed_at.accepted {
        referenced.entry(*slot).or_insert(Reference::Loaded);
    }
    recover_referenced_imports(image, observed_base, exports, &referenced, &mut plan);

    let recovered = collect_recovered_slots(&plan, kind.pointer_width());
    let refused = pointed_at
        .refused
        .iter()
        .filter(|slot| !referenced.contains_key(slot) && !recovered.contains(slot))
        .count();
    plan.refused_variable_slots = plan.refused_variable_slots.saturating_add(refused);

    finish_plan(&mut plan, kind.pointer_width());
    plan
}

// an indexed array runs on to its section's end, or to the first slot code calls through
fn program_arrays(image: &PeImage<'_>, references: &CodeReferences) -> BTreeSet<u32> {
    let model = image.model();
    let width = model.kind.pointer_width();
    let starts: Vec<(usize, Addressed)> = references
        .addressed
        .iter()
        .map(|(slot, how)| (*slot as usize, *how))
        .collect();
    let mut owned = BTreeSet::new();

    for (index, (start, how)) in starts.iter().enumerate() {
        let Some(section) = model
            .sections
            .iter()
            .find(|section| section.range().contains(start) && !section.is_executable())
        else {
            continue;
        };

        let next = starts.get(index + 1).map_or(usize::MAX, |(next, _)| *next);
        let end = match how {
            Addressed::Slot => start.saturating_add(width),
            Addressed::IndexedArray => section.range().end.min(next.max(start + width)),
        };

        for slot in (*start..end).step_by(width) {
            let Ok(slot) = u32::try_from(slot) else {
                break;
            };
            if references.slots.get(&slot) == Some(&Reference::Called) {
                break;
            }
            owned.insert(slot);
        }
    }

    owned
}

fn start_plan(
    image: &PeImage<'_>,
    observed_base: usize,
    packer: &[Range<usize>],
) -> (ImportPlan, BTreeMap<u32, Reference>) {
    let references = find_code_references(image, observed_base, packer);
    let mut owned = references.stored.clone();
    owned.extend(program_arrays(image, &references));

    let mut plan = ImportPlan {
        own: embedded_module_name(image.bytes()),
        stored_slots: owned,
        stores_unseen: references.stores_unseen,
        packer_ranges: packer.to_vec(),
        startup_hints: startup_hints(image, observed_base),
        ..ImportPlan::default()
    };

    plan.counts.code_scan_truncated |= usize::from(references.truncated);
    plan.counts.unreliable_section_flags |=
        usize::from(every_section_is_writable_code(&image.model().sections));

    (plan, references.slots)
}

// aliases at one address (ucrt's _exit and _Exit) are told apart by who calls them: msvc's
// startup code, linked into every msvc exe, imports its own fixed names
fn startup_hints(image: &PeImage<'_>, observed_base: usize) -> NameHints {
    let bytes = image.bytes();
    let model = image.model();
    let Some(entry) = read_u32(bytes, model.entry_point_offset) else {
        return NameHints::new();
    };

    let x64 = model.kind == PeKind::Pe32Plus;
    msvc_startup_slots(bytes, entry as usize, x64, observed_base)
        .into_iter()
        .filter_map(|slot| {
            Some((
                u32::try_from(slot).ok()?,
                NameHint::Among(MSVC_STARTUP_IMPORTS),
            ))
        })
        .collect()
}

fn finish_plan(plan: &mut ImportPlan, width: usize) {
    plan.counts.ambiguous_imports = plan.ambiguous_slots.len();
    plan.counts.unresolved_delay = plan.unbound_delay_slots.len();

    let left_out = [
        plan.unresolved_table_slots,
        plan.refused_scanned_slots,
        plan.refused_variable_slots,
        plan.lone_slots_dropped,
        plan.undetermined_module_slots,
        plan.own_module_slots,
    ];
    plan.counts.lost_import_slots = left_out
        .into_iter()
        .fold(plan.counts.lost_import_slots, usize::saturating_add);

    join_touching_groups(&mut plan.groups, width);
}

fn sole_orphaned_table(
    image: &PeImage<'_>,
    exports: &ExportIndex,
    plan: &mut ImportPlan,
) -> Option<Vec<u8>> {
    let scan = scan_for_orphaned_descriptors(image, exports);
    plan.counts.descriptor_scan_truncated |= usize::from(scan.truncated);

    let rivals = scan.tables.len();
    let table = sole_table(scan.tables, scan.truncated);

    plan.counts.table_located_by_scan |= usize::from(table.is_some());
    if rivals > 1 {
        plan.counts.rival_import_tables = plan.counts.rival_import_tables.max(rivals);
    }
    table
}

fn sole_table(mut tables: Vec<Vec<u8>>, truncated: bool) -> Option<Vec<u8>> {
    let table = tables.pop()?;
    (tables.is_empty() && !truncated).then_some(table)
}

fn every_section_is_writable_code(sections: &[SectionModel]) -> bool {
    let writable_code = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    !sections.is_empty()
        && sections
            .iter()
            .all(|section| section.characteristics() & writable_code == writable_code)
}

#[derive(Default)]
struct PointerEvidence {
    accepted: BTreeSet<u32>,
    refused: BTreeSet<u32>,
}

fn pointed_at_variable_slots(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    plan: &ImportPlan,
) -> PointerEvidence {
    let width = image.model().kind.pointer_width();
    let memory = image.bytes();
    let holds_variable = |slot: u32| {
        slot_is_in_data_section(image, slot, width)
            && read_pointer(memory, slot as usize, width)
                .is_some_and(|value| exports.is_variable(value))
    };
    let mut evidence = PointerEvidence::default();

    for at in (0..=memory.len().saturating_sub(width)).step_by(width) {
        let Some(pointer) = u32::try_from(at)
            .ok()
            .and_then(|at| data_section_at(image, at, width))
        else {
            continue;
        };

        let slot = read_pointer(memory, at, width)
            .and_then(|value| value.checked_sub(observed_base))
            .and_then(|slot| u32::try_from(slot).ok())
            .filter(|slot| holds_variable(*slot));
        let Some(slot) = slot else {
            continue;
        };

        // gcc's .refptr is read-only; an indirect store cannot be seen
        let constant = pointer.characteristics() & IMAGE_SCN_MEM_WRITE == 0;
        match constant && !plan.stores_unseen && !plan.stores_to(slot) {
            true => evidence.accepted.insert(slot),
            false => evidence.refused.insert(slot),
        };
    }

    evidence
        .refused
        .retain(|slot| !evidence.accepted.contains(slot));
    evidence
}

fn slot_value(image: &PeImage<'_>, slot: u32) -> Option<usize> {
    read_pointer(
        image.bytes(),
        slot as usize,
        image.model().kind.pointer_width(),
    )
}

fn data_section_at<'a>(
    image: &'a PeImage<'_>,
    slot: u32,
    width: usize,
) -> Option<&'a SectionModel> {
    let start = slot as usize;
    let end = start + width;
    if !start.is_multiple_of(width) || end > image.bytes().len() {
        return None;
    }

    image.model().sections.iter().find(|section| {
        let range = section.range();
        section.is_data() && range.start <= start && end <= range.end
    })
}

fn slot_is_in_data_section(image: &PeImage<'_>, slot: u32, width: usize) -> bool {
    data_section_at(image, slot, width).is_some()
}

fn collect_recovered_slots(plan: &ImportPlan, width: usize) -> BTreeSet<u32> {
    plan.groups
        .iter()
        .flat_map(|group| group.slots(width))
        .collect()
}

fn is_representable(module: &str, name: Option<&str>, ordinal: u32) -> bool {
    module.is_ascii()
        && match name {
            Some(name) => name.is_ascii(),
            None => u16::try_from(ordinal).is_ok(),
        }
}

fn join_touching_groups(groups: &mut Vec<ImportGroup>, width: usize) {
    loop {
        let before = groups.len();
        let mut joined: Vec<ImportGroup> = Vec::with_capacity(before);

        for mut group in groups.drain(..) {
            let touching = joined.iter_mut().find(|kept| {
                kept.module.eq_ignore_ascii_case(&group.module)
                    && (kept.end(width) == group.first_thunk as usize
                        || group.end(width) == kept.first_thunk as usize)
            });
            match touching {
                Some(kept) if kept.first_thunk < group.first_thunk => {
                    kept.entries.append(&mut group.entries);
                }
                Some(kept) => {
                    group.entries.append(&mut kept.entries);
                    kept.entries = group.entries;
                    kept.first_thunk = group.first_thunk;
                }
                None => joined.push(group),
            }
        }

        *groups = joined;
        if groups.len() == before {
            return;
        }
    }
}

fn commit_group(
    group: ImportGroup,
    width: usize,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let agreeing = group
        .slots(width)
        .filter(|slot| referenced.contains_key(slot))
        .count();
    let aliased = group.entries.iter().filter(|entry| entry.aliased).count();
    let source = group.source;

    if !push_group(group, plan) {
        return;
    }

    plan.counts.aliased_names = plan.counts.aliased_names.saturating_add(aliased);

    if !carries_call_site_evidence(source) {
        return;
    }

    plan.counts.slots_with_call_sites = plan.counts.slots_with_call_sites.saturating_add(agreeing);
}

fn carries_call_site_evidence(source: ImportSource) -> bool {
    matches!(
        source,
        ImportSource::Attested | ImportSource::Scanned | ImportSource::Packer
    )
}

fn push_group(group: ImportGroup, plan: &mut ImportPlan) -> bool {
    let recovered = plan.recovered.saturating_add(group.entries.len());

    if recovered > MAX_IMPORTS || plan.groups.len() >= MAX_IMPORT_DESCRIPTORS {
        let lost = &mut plan.counts.lost_import_slots;
        *lost = lost.saturating_add(group.entries.len());
        return false;
    }

    record_recovered_tier(plan, group.source, group.entries.len());
    plan.recovered = recovered;
    plan.groups.push(group);
    true
}

fn record_recovered_tier(plan: &mut ImportPlan, source: ImportSource, entries: usize) {
    let counter = match source {
        ImportSource::Attested => &mut plan.counts.recovered_attested,
        ImportSource::Scanned => &mut plan.counts.recovered_scanned,
        ImportSource::Delayed => &mut plan.counts.recovered_delayed,
        ImportSource::Inferred => &mut plan.counts.recovered_inferred,
        ImportSource::Packer => &mut plan.counts.recovered_packer,
    };

    *counter = counter.saturating_add(entries);
}

fn read_printable_name(bytes: &[u8], offset: usize) -> Option<&str> {
    (offset != 0).then_some(())?; // a zero rva names nothing
    bytes::read_ascii(bytes, offset, MAX_NAME_LENGTH).filter(|name| {
        name.bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    })
}

fn read_pointer(bytes: &[u8], offset: usize, width: usize) -> Option<usize> {
    match *bytes.get(offset..offset.checked_add(width)?)? {
        [a, b, c, d] => Some(u32::from_le_bytes([a, b, c, d]) as usize),
        [a, b, c, d, e, f, g, h] => {
            usize::try_from(u64::from_le_bytes([a, b, c, d, e, f, g, h])).ok()
        }
        _ => None,
    }
}

fn count_until_zero(memory: &[u8], start: usize, width: usize, limit: usize) -> usize {
    (0..limit)
        .map_while(|index| {
            read_pointer(memory, start.checked_add(index.checked_mul(width)?)?, width)
        })
        .take_while(|value| *value != 0)
        .count()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes::read_u32(bytes, offset).ok()
}
