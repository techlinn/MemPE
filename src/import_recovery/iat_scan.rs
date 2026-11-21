use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use super::code_references::{Reference, image_offset};
use super::resolve_slot::resolve_value;
use super::{
    ImportEntry, ImportGroup, ImportPlan, ImportSource, SlotCandidate, commit_group,
    is_representable, read_pointer,
};
use crate::pe::exports::{ExportIndex, ExportSymbol};
use crate::pe::import_list::NameHint;
use crate::pe::{IAT_DIRECTORY, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeImage, PeKind};

pub(super) fn scan_trusted_ranges(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let memory = image.bytes();
    let model = image.model();
    let declared_iat = image.directory(IAT_DIRECTORY).and_then(|iat| {
        let rva = iat.rva().get();
        Some(rva as usize..rva.checked_add(iat.size())? as usize)
    });

    for section in &model.sections {
        if section.characteristics() & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) == 0 {
            continue;
        }

        let range = section.range();
        let attested = declared_iat.as_ref().and_then(|iat| {
            let start = iat.start.max(range.start);
            let end = iat.end.min(range.end);
            (start < end).then_some(ImportScan {
                start,
                end,
                source: ImportSource::Attested,
            })
        });
        let scanned = (!section.is_executable()).then_some(ImportScan {
            start: range.start,
            end: range.end,
            source: ImportSource::Scanned,
        });
        let Some(mut scan) = attested.or(scanned) else {
            continue;
        };

        scan.end = scan.end.min(memory.len());
        scan_import_range(
            memory,
            observed_base,
            model.kind,
            exports,
            scan,
            referenced,
            plan,
        );
    }
}

pub(super) struct ImportScan {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) source: ImportSource,
}

#[derive(Default)]
struct Segment {
    entries: Vec<SlotCandidate>,
    unresolved: usize,
    ambiguous: usize,
}

enum Missing {
    Unresolved,
    Ambiguous,
}

pub(super) fn scan_import_range(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    scan: ImportScan,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let ImportScan { start, end, source } = scan;

    let width = kind.pointer_width();
    let mut offset = start.saturating_add((width - start % width) % width);
    let mut segment = Segment::default();
    let mut segments = Vec::new();

    while offset.saturating_add(width) <= end {
        let (Some(value), Ok(slot)) = (read_pointer(memory, offset, width), u32::try_from(offset))
        else {
            break;
        };
        offset = offset.saturating_add(width);

        if value == 0 {
            segments.push(std::mem::take(&mut segment));
            continue;
        }

        let scanned = source == ImportSource::Scanned;
        let thunked = image_offset(observed_base, memory.len(), value).is_some();
        let found = match scanned && thunked {
            true => Err(Missing::Unresolved), // an exact export address, not a path through a stub
            false => slot_candidate(memory, observed_base, kind, exports, slot, &segment, plan),
        };

        match found {
            Ok(candidate) => segment.entries.push(candidate),
            Err(Missing::Unresolved) => segment.unresolved += 1,
            Err(Missing::Ambiguous) => segment.ambiguous += 1,
        }
    }

    segments.push(segment);

    let mut tables: Vec<Vec<SlotCandidate>> = segments
        .iter_mut()
        .map(|segment| std::mem::take(&mut segment.entries))
        .collect();
    let tied = settle_runs(&mut tables, width, exports); // the table's runs name each other
    for ((mut segment, entries), tied) in segments.into_iter().zip(tables).zip(tied) {
        segment.entries = entries;
        close_segment(segment, tied, width, source, referenced, plan);
    }
}

fn slot_candidate(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    slot: u32,
    segment: &Segment,
    plan: &mut ImportPlan,
) -> Result<SlotCandidate, Missing> {
    let width = kind.pointer_width();
    let value = read_pointer(memory, slot as usize, width).ok_or(Missing::Unresolved)?;
    let found = resolve_value(memory, observed_base, kind, value, exports)
        .map_err(|_| Missing::Unresolved)?;

    let run_module = segment
        .entries
        .last()
        .filter(|entry| entry.slot.checked_add(width as u32) == Some(slot))
        .map(|entry| entry.symbol.module.clone());
    let settled = match found.ambiguous {
        true => run_module
            .or_else(|| {
                let next = read_pointer(memory, (slot as usize).checked_add(width)?, width)?;
                resolve_value(memory, observed_base, kind, next, exports)
                    .ok()
                    .filter(|next| !next.ambiguous)
                    .map(|next| next.symbol.module.clone())
            })
            .and_then(|module| named_in(exports, value, &module)),
        false => Some((found.symbol.clone(), found.aliased)),
    };
    let Some((symbol, aliased)) = settled else {
        plan.ambiguous_slots.insert(slot);
        return Err(Missing::Ambiguous);
    };

    let apply = |hint: &NameHint| match hint {
        NameHint::Length(length) => exports
            .resolve_fitting(value, |name| length.contains(&name.len()))
            .cloned(),
        NameHint::Among(names) => exports
            .resolve_fitting(value, |name| names.contains(&name))
            .cloned(),
        NameHint::Ordinal(ordinal) => exports.resolve_ordinal(value, *ordinal),
    };
    let hinted = [&plan.name_hints, &plan.startup_hints]
        .into_iter()
        .find_map(|hints| hints.get(&slot).and_then(apply)); // the packer's record first
    let (symbol, aliased) = match hinted {
        Some(hinted) => (hinted, false),
        None => (symbol, aliased),
    };

    Ok(SlotCandidate {
        slot,
        value,
        symbol,
        aliased,
    })
}

fn close_segment(
    segment: Segment,
    tied: usize,
    width: usize,
    source: ImportSource,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    if matches!(source, ImportSource::Attested | ImportSource::Packer) {
        plan.unresolved_table_slots = plan
            .unresolved_table_slots
            .saturating_add(segment.unresolved); // unbound delay slots are counted apart
    }

    if segment.entries.is_empty() {
        return;
    }

    if source == ImportSource::Scanned {
        let stored = segment
            .entries
            .iter()
            .any(|entry| plan.stores_to(entry.slot));
        let whole = segment.unresolved == 0 && segment.ambiguous == 0;
        let refusal = match (stored, whole && is_one_module(&segment.entries)) {
            (true, _) => Some(&mut plan.counts.runtime_lookup_slots),
            (false, false) => Some(&mut plan.refused_scanned_slots),
            (false, true) => None,
        };

        if let Some(counter) = refusal {
            *counter = counter.saturating_add(segment.entries.len());
            return;
        }
    }

    plan.counts.tied_module_runs = plan.counts.tied_module_runs.saturating_add(tied);
    record_mixed_module_run(plan, &segment.entries);
    append_groups(segment.entries, width, source, referenced, plan);
}

fn is_one_module(entries: &[SlotCandidate]) -> bool {
    entries.windows(2).all(|pair| {
        pair[0]
            .symbol
            .module
            .eq_ignore_ascii_case(&pair[1].symbol.module)
    })
}

pub(super) fn append_groups(
    entries: Vec<SlotCandidate>,
    width: usize,
    source: ImportSource,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let mut current: Option<ImportGroup> = None;
    for SlotCandidate {
        slot,
        symbol,
        aliased,
        ..
    } in entries
    {
        if plan
            .own
            .as_deref()
            .is_some_and(|own| own.eq_ignore_ascii_case(&symbol.module))
        {
            plan.own_module_slots = plan.own_module_slots.saturating_add(1);
            continue;
        }

        if !is_representable(&symbol.module, symbol.name.as_deref(), symbol.ordinal) {
            plan.unrepresentable = plan.unrepresentable.saturating_add(1);
            continue;
        }

        let same_module = current.as_ref().is_some_and(|group| {
            group.module.eq_ignore_ascii_case(&symbol.module) && group.end(width) == slot as usize
        });

        if !same_module {
            if let Some(group) = current.take() {
                commit_group(group, width, referenced, plan);
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
        commit_group(group, width, referenced, plan);
    }
}

pub(super) fn named_in(
    exports: &ExportIndex,
    value: usize,
    module: &str,
) -> Option<(ExportSymbol, bool)> {
    let mut names = exports.names_in(value, module); // the shared alias rule
    let name = names.next()?;
    let aliased = names.next().is_some();

    Some((exports.export_named(value, module, name)?, aliased))
}

fn named_by(
    exports: &ExportIndex,
    entry: &SlotCandidate,
    module: &str,
) -> Option<(ExportSymbol, bool)> {
    let name = entry.symbol.name.as_deref()?;
    exports
        .export_named(entry.value, module, name)
        .map(|symbol| (symbol, entry.aliased))
        .or_else(|| named_in(exports, entry.value, module)) // a forwarder keeps its own name
}

struct Tie {
    table: usize,
    at: Range<usize>, // in that table's entries
    modules: Vec<String>,
}

// a linker writes one descriptor, so one run, per dll: a tied run takes the one dll no other
// run of the table takes or ties on
pub(super) fn settle_runs(
    tables: &mut [Vec<SlotCandidate>],
    width: usize,
    exports: &ExportIndex,
) -> Vec<usize> {
    let adjacent = |left: &SlotCandidate, right: &SlotCandidate| {
        left.slot.checked_add(width as u32) == Some(right.slot)
    };
    let mut ties = Vec::new();
    for (table, entries) in tables.iter_mut().enumerate() {
        let mut from = 0;
        for run in entries.chunk_by_mut(adjacent) {
            ties.extend(
                settle_run_module(run, exports)
                    .into_iter()
                    .map(|(at, modules)| Tie {
                        table,
                        at: at.start + from..at.end + from,
                        modules,
                    }),
            );
            from += run.len();
        }
    }

    let in_tie = |table: usize, index: usize| {
        ties.iter()
            .any(|tie| tie.table == table && tie.at.contains(&index))
    };
    let named_by_settled = |module: &str| {
        tables.iter().enumerate().any(|(table, entries)| {
            entries.iter().enumerate().any(|(index, entry)| {
                !in_tie(table, index) && entry.symbol.module.eq_ignore_ascii_case(module)
            })
        })
    };
    let settled: Vec<(usize, Range<usize>, String)> = ties
        .iter()
        .zip(unshared(&ties, named_by_settled))
        .filter_map(|(tie, module)| Some((tie.table, tie.at.clone(), module?)))
        .collect();

    for (table, at, module) in &settled {
        let entries = tables
            .get_mut(*table)
            .and_then(|entries| entries.get_mut(at.clone()))
            .unwrap_or_default();
        for entry in entries {
            if let Some((symbol, aliased)) = named_by(exports, entry, module) {
                entry.symbol = symbol;
                entry.aliased = aliased;
            }
        }
    }

    let mut tied = vec![0; tables.len()];
    for tie in &ties {
        let resolved = settled
            .iter()
            .any(|(table, at, _)| (*table, at) == (tie.table, &tie.at));
        if let (false, Some(count)) = (resolved, tied.get_mut(tie.table)) {
            *count += 1;
        }
    }
    tied
}

// for each tie, the one name no other run takes or ties on
fn unshared(ties: &[Tie], named_by_settled: impl Fn(&str) -> bool) -> Vec<Option<String>> {
    let taken_elsewhere = |tie: &Tie, module: &str| {
        named_by_settled(module)
            || ties.iter().any(|other| {
                (other.table, &other.at) != (tie.table, &tie.at)
                    && other.modules.iter().any(|name| name == module)
            })
    };

    ties.iter()
        .map(|tie| {
            let left: Vec<&String> = tie
                .modules
                .iter()
                .filter(|module| !taken_elsewhere(tie, module))
                .collect();
            match left[..] {
                [only] => Some(only.clone()),
                _ => None,
            }
        })
        .collect()
}

fn settle_run_module(
    entries: &mut [SlotCandidate],
    exports: &ExportIndex,
) -> Vec<(Range<usize>, Vec<String>)> {
    let named = |entry: &SlotCandidate, module: &str| named_by(exports, entry, module);

    let mut ties = Vec::new();
    let mut from = 0;
    while let Some(rest) = entries.get_mut(from..).filter(|rest| !rest.is_empty()) {
        let mut modules: Vec<String> = exports
            .modules_at(rest[0].value)
            .map(|(module, _)| module.to_ascii_lowercase())
            .collect();
        modules.sort_unstable();
        modules.dedup();

        let reach = |module: &str| {
            rest.iter()
                .take_while(|entry| named(entry, module).is_some())
                .count()
        };
        let Reach {
            module,
            length,
            tied,
        } = longest_reach(&modules, reach);
        if tied {
            let tied_on = modules
                .iter()
                .filter(|module| reach(module) == length)
                .cloned()
                .collect();
            ties.push((from..from + length, tied_on));
        }

        if let Some(module) = module {
            for entry in rest.iter_mut().take(length) {
                if let Some((symbol, aliased)) = named(entry, module) {
                    entry.symbol = symbol;
                    entry.aliased = aliased;
                }
            }
        }

        from += length.max(1);
    }

    ties
}

struct Reach<'a> {
    module: Option<&'a String>,
    length: usize,
    tied: bool,
}

fn longest_reach(modules: &[String], reach: impl Fn(&str) -> usize) -> Reach<'_> {
    let reached: Vec<(&String, usize)> = modules
        .iter()
        .map(|module| (module, reach(module)))
        .collect();
    let length = reached.iter().map(|(_, length)| *length).max().unwrap_or(0);
    let furthest: Vec<&String> = reached
        .iter()
        .filter(|(_, reached)| *reached == length && length > 0)
        .map(|(module, _)| *module)
        .collect();

    let module = match furthest[..] {
        [only] => Some(only),
        _ => None,
    };
    Reach {
        module,
        length,
        tied: furthest.len() > 1,
    }
}

fn record_mixed_module_run(plan: &mut ImportPlan, entries: &[SlotCandidate]) {
    let modules = entries
        .iter()
        .map(|entry| entry.symbol.module.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if modules.len() > 1 {
        plan.counts.mixed_module_runs = plan.counts.mixed_module_runs.saturating_add(1);
    }
}
