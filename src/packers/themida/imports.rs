use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use super::Packed;
use crate::import_recovery::code_referenced_slots;
use crate::pe::bytes::{read_pointer, write_pointer};
use crate::pe::{HINT_SIZE, IAT_DIRECTORY, PeKind, first_section_rva};
use crate::unpack::tables::unique;
use crate::unpack::x86::{StubRunner, WrapperLeadsTo};
use crate::unpack::{NameHint, NameHints, PackerImports, PackerReport, Part};

const MIN_TABLE_SLOTS: usize = 2;
const MAX_FAILED_TRACES: usize = 64;
const ORDINAL_MASK: usize = 0xFFFF;

#[derive(Default)]
pub(super) struct Imports {
    range: Option<Range<usize>>,
    traced: usize,
    through_vm: usize, // traced through themida's virtual machine
    untraced: usize,
    virtualized: usize,
    other_tables: usize,
    lone_slots: usize,
    gave_up: bool,
}

impl Imports {
    pub(super) fn wrapped(&self) -> bool {
        self.traced + self.through_vm > 0 || self.virtualized > 0
    }

    pub(super) fn table_start(&self) -> Option<usize> {
        self.range.as_ref().map(|range| range.start)
    }

    pub(super) fn declare(
        &self,
        restored: &mut [u8],
        packed: &Packed<'_>,
        report: &mut PackerReport,
    ) -> Option<PackerImports> {
        let Some(range) = &self.range else {
            report.failed_with(
                Part::Imports,
                "no table slot traced to an api: themida had not started the program, or wraps imports in a way that is not traced",
            );
            self.describe_limits(report);
            return Some(PackerImports::Unknown);
        };

        self.describe(report);
        packed
            .model()
            .set_directory(restored, IAT_DIRECTORY, range.start, range.len())?; // themida wipes the header entry, not the table

        let end = packed.layout.original_end;
        let program = first_section_rva(&packed.image.model().sections).unwrap_or(end)..end;

        Some(PackerImports::FilledIat {
            rva: u32::try_from(range.start).ok()?,
            size: u32::try_from(range.len()).ok()?,
            names: name_hints(packed.image.bytes(), packed.kind(), program, range),
        })
    }

    fn describe(&self, report: &mut PackerReport) {
        let failed = self.untraced + self.virtualized;
        let traced = self.traced + self.through_vm;
        match (traced, failed) {
            (_, 0) => report.restored(Part::Imports),
            (0, _) => report.partly_failed(Part::Imports, "no wrapper traced to an api"),
            _ => {
                report.restored_with(Part::Imports, "those that traced");
                report.partly_failed(Part::Imports, "their wrappers did not trace to an api");
            }
        }

        if traced + failed > 0 {
            report.notes.push(format!(
                "{traced} wrapped imports traced to their apis, {failed} did not and still point into themida's sections"
            ));
        }

        if self.through_vm > 0 {
            report.notes.push(format!(
                "{} of the traced imports were followed through themida's virtual machine to the api it jumps to on the caller's frame",
                self.through_vm
            ));
        }

        if self.virtualized > 0 {
            report.notes.push(format!(
                "{} of the untraced import slots lead into themida's virtual machine, which hides the api behind them",
                self.virtualized
            ));
        }

        if self.other_tables > 0 {
            report.notes.push(format!(
                "{} more wrapped import table(s) were unwrapped too; only the largest is declared as the import address table, the rest are named from the calls that use them",
                self.other_tables
            ));
        }

        self.describe_limits(report);
    }

    fn describe_limits(&self, report: &mut PackerReport) {
        if self.lone_slots > 0 {
            report.notes.push(format!(
                "{} wrapped import slot(s) with no neighbour were not taken as an import table",
                self.lone_slots
            ));
        }

        if self.gave_up {
            report.notes.push(format!(
                "import tracing stopped after {MAX_FAILED_TRACES} wrappers that did not trace: later wrappers count as untraced, and a table none of whose earlier slots traced was not found"
            ));
        }
    }
}

enum Slot {
    Empty,
    Api,
    Wrapped(usize),
    Other,
}

struct Tracer<'a> {
    packed: &'a Packed<'a>,
    runner: StubRunner<'a>,
    engine: Range<u64>,
    destinations: HashMap<usize, Option<WrapperLeadsTo>>,
    failed: usize,
    lone_slots: usize,
}

impl Tracer<'_> {
    fn slot(&self, at: usize) -> Slot {
        let exports = self.packed.origin.exports;
        match read_pointer(self.runner.image, at, self.packed.kind()) {
            Ok(0) => Slot::Empty,
            Ok(value) if self.engine.contains(&(value as u64)) => Slot::Wrapped(value),
            Ok(value) if exports.resolve(value).is_some() => Slot::Api,
            _ => Slot::Other,
        }
    }

    fn destination(&mut self, wrapper: usize) -> Option<WrapperLeadsTo> {
        if let Some(known) = self.destinations.get(&wrapper) {
            return *known;
        }
        if self.failed >= MAX_FAILED_TRACES {
            return None;
        }

        let exports = self.packed.origin.exports;
        let destination = self
            .runner
            .destination(wrapper as u64, &self.engine)
            .filter(|destination| match destination {
                WrapperLeadsTo::Api(api) => exports.resolve(*api as usize).is_some(),
                WrapperLeadsTo::VirtualMachine => true,
            });

        self.failed += usize::from(destination.is_none());
        self.destinations.insert(wrapper, destination);
        destination
    }

    fn proven_import(&mut self, at: usize) -> bool {
        match self.slot(at) {
            Slot::Api => true,
            Slot::Wrapped(wrapper) => self.destination(wrapper).is_some(),
            Slot::Empty | Slot::Other => false,
        }
    }

    fn in_table(&self, at: usize) -> bool {
        matches!(self.slot(at), Slot::Api | Slot::Wrapped(_)) // a wrapper that will not trace is still a slot
    }
}

pub(super) fn restore(restored: &mut [u8], packed: &Packed<'_>) -> Imports {
    let kind = packed.kind();
    let width = kind.pointer_width();
    let base = packed.origin.base;
    let mut tracer = Tracer {
        packed,
        runner: packed.runner(),
        engine: packed.va(&packed.layout.engine),
        destinations: HashMap::new(),
        failed: 0,
        lone_slots: 0,
    };

    let referenced = code_referenced_slots(packed.image, base, &[]);
    let mut imports = Imports::default();

    for table in wrapped_tables(&mut tracer, &referenced) {
        imports.other_tables += usize::from(imports.range.is_some());
        for slot in table.clone().step_by(width) {
            let Slot::Wrapped(wrapper) = tracer.slot(slot) else {
                continue;
            };

            match tracer.destination(wrapper) {
                Some(WrapperLeadsTo::Api(api)) => match write_pointer(restored, slot, kind, api) {
                    Ok(()) => imports.traced += 1,
                    Err(_) => imports.untraced += 1,
                },
                Some(WrapperLeadsTo::VirtualMachine) => {
                    let exports = packed.origin.exports;
                    let api = tracer
                        .runner
                        .through_vm(wrapper as u64)
                        .filter(|api| exports.resolve(*api as usize).is_some());
                    match api.map(|api| write_pointer(restored, slot, kind, api)) {
                        Some(Ok(())) => imports.through_vm += 1,
                        _ => imports.virtualized += 1,
                    }
                }
                None => imports.untraced += 1,
            }
        }

        let larger = imports
            .range
            .as_ref()
            .is_none_or(|known| table.len() > known.len());
        if larger {
            imports.range = Some(table);
        }
    }

    imports.lone_slots = tracer.lone_slots;
    imports.gave_up = tracer.failed >= MAX_FAILED_TRACES;
    imports
}

fn wrapped_tables(tracer: &mut Tracer<'_>, referenced: &BTreeSet<usize>) -> Vec<Range<usize>> {
    let packed = tracer.packed;
    let width = packed.kind().pointer_width();
    let image_end = packed.image.bytes().len();
    let mut tables: Vec<Range<usize>> = Vec::new();

    for section in &packed.model().sections {
        let range = section.range();
        let bounds = range.start..range.end.min(image_end);
        if bounds.start >= packed.layout.original_end {
            continue;
        }

        for anchor in referenced.range(bounds.clone()) {
            let covered = tables.last().is_some_and(|table| table.contains(anchor));
            if covered || !tracer.proven_import(*anchor) {
                continue;
            }

            let table = grow(tracer, *anchor, &bounds, width);
            match table.len() / width >= MIN_TABLE_SLOTS {
                true => tables.push(table),
                false => tracer.lone_slots += 1,
            }
        }
    }

    tables
}

fn grow(tracer: &Tracer<'_>, anchor: usize, bounds: &Range<usize>, width: usize) -> Range<usize> {
    let mut first = anchor;
    while let Some(before) = neighbour(tracer, first, bounds, width, false) {
        first = before;
    }

    let mut last = anchor;
    while let Some(after) = neighbour(tracer, last, bounds, width, true) {
        last = after;
    }

    let terminator = match neighbour_slot(last, bounds, width, true) {
        Some(after) if matches!(tracer.slot(after), Slot::Empty) => width,
        _ => 0,
    };

    first..last + width + terminator
}

fn neighbour(
    tracer: &Tracer<'_>,
    slot: usize,
    bounds: &Range<usize>,
    width: usize,
    forward: bool,
) -> Option<usize> {
    let next = neighbour_slot(slot, bounds, width, forward)?;
    if tracer.in_table(next) {
        return Some(next);
    }

    let beyond = neighbour_slot(next, bounds, width, forward)?;
    (matches!(tracer.slot(next), Slot::Empty) && tracer.in_table(beyond)).then_some(beyond)
}

fn neighbour_slot(
    slot: usize,
    bounds: &Range<usize>,
    width: usize,
    forward: bool,
) -> Option<usize> {
    let next = match forward {
        true => slot.checked_add(width)?,
        false => slot.checked_sub(width)?,
    };

    (bounds.start <= next && next + width <= bounds.end).then_some(next)
}

fn name_hints(image: &[u8], kind: PeKind, program: Range<usize>, iat: &Range<usize>) -> NameHints {
    let width = kind.pointer_width();
    let ordinal = kind.ordinal_flag() as usize;
    // names wiped, lookup table left
    let Some(lookups) = lookup_table(image, kind, program, iat) else {
        return NameHints::new();
    };

    let (ordinals, named): (Vec<_>, Vec<_>) = lookups
        .into_iter()
        .partition(|(_, value)| value & ordinal != 0);
    let by_ordinal = ordinals
        .into_iter()
        .map(|(index, value)| (index, NameHint::Ordinal((value & ORDINAL_MASK) as u32)));

    by_ordinal
        .chain(name_lengths(&named))
        .filter_map(|(index, hint)| Some((u32::try_from(iat.start + index * width).ok()?, hint)))
        .collect()
}

fn lookup_table(
    image: &[u8],
    kind: PeKind,
    names: Range<usize>,
    iat: &Range<usize>,
) -> Option<Vec<(usize, usize)>> {
    let width = kind.pointer_width();
    let ordinal = kind.ordinal_flag() as usize;
    let filled: Vec<bool> = iat
        .clone()
        .step_by(width)
        .map(|slot| read_pointer(image, slot, kind).is_ok_and(|value| value != 0))
        .collect();

    let entry = |table: usize, index: usize| read_pointer(image, table + index * width, kind).ok();
    let mirrors = |table: &usize| {
        let overlaps = *table < iat.end && iat.start < table + filled.len() * width;
        !overlaps
            && filled.iter().enumerate().all(|(index, filled)| {
                entry(*table, index).is_some_and(|value| match filled {
                    true => value & ordinal != 0 || names.contains(&value),
                    false => value == 0,
                })
            })
    };
    let table = unique(names.clone().step_by(width).filter(mirrors))?;

    Some(
        (0..filled.len())
            .filter_map(|index| Some((index, entry(table, index)?)))
            .filter(|(_, value)| *value != 0)
            .collect(),
    )
}

fn name_lengths(named: &[(usize, usize)]) -> Vec<(usize, NameHint)> {
    let mut records: Vec<usize> = named.iter().map(|(_, record)| *record).collect();
    records.sort_unstable();
    let mut hints = Vec::with_capacity(named.len());

    for module in named.chunk_by(|(left, _), (right, _)| left + 1 == *right) {
        let last = module.iter().map(|(_, record)| *record).max();

        for (index, record) in module {
            let next = records.partition_point(|other| other <= record);
            let Some(gap) = records.get(next).map(|after| after - record) else {
                continue;
            };

            let longest = gap.saturating_sub(HINT_SIZE + 1); // hint, name, nul, even padding
            let shortest = match Some(*record) == last {
                true => 1, // module name follows its last record
                false => longest.saturating_sub(1),
            };
            hints.push((*index, NameHint::Length(shortest..=longest)));
        }
    }

    hints
}
