use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use super::{Layout, Packed};
use crate::pe::image::{read_pointer, write_pointer};
use crate::pe::imports::code_referenced_slots;
use crate::pe::packers::emu::{Destination, Snapshot};
use crate::pe::packers::tables::{FIRST_SECTION_RVA, HINT_SIZE, set_directory, unique};
use crate::pe::packers::{NameHint, NameHints, PackerImports, PackerReport};
use crate::pe::{IAT_DIRECTORY, PeKind};

const MIN_TABLE_SLOTS: usize = 2;
const MAX_FAILED_TRACES: usize = 64; // each can cost the emulator's whole step budget
const EXIT_MODULE: &str = "kernel32.dll";
const EXIT_API: &str = "ExitProcess";
const ORDINAL_MASK: usize = 0xFFFF;

#[derive(Default)]
pub(super) struct Imports {
    range: Option<Range<usize>>,
    traced: usize,
    untraced: usize,
    exit_hook: bool,
}

impl Imports {
    pub(super) fn wrapped(&self) -> bool {
        self.traced > 0 || self.exit_hook
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
            report.unrestored.push(
                "imports (no table holds api addresses yet, so themida had not started the program)",
            );
            return Some(PackerImports::Unknown);
        };

        self.describe(report);
        set_directory(
            restored,
            packed.model(),
            IAT_DIRECTORY,
            range.start,
            range.len(),
        )?; // themida wipes it from the header and leaves the table itself in place

        Some(PackerImports::FilledIat {
            rva: u32::try_from(range.start).ok()?,
            size: u32::try_from(range.len()).ok()?,
            names: name_hints(packed.image.bytes(), packed.kind(), &packed.layout, range),
        })
    }

    fn describe(&self, report: &mut PackerReport) {
        match self.untraced {
            0 => report.restored.push("imports"),
            _ => {
                report.restored.push("imports (those that traced)");
                report
                    .unrestored
                    .push("some imports (their wrappers did not trace to an api)");
            }
        }

        if self.traced > 0 {
            report.notes.push(format!(
                "{} wrapped imports traced to their apis, {} did not",
                self.traced, self.untraced
            ));
        }

        if self.exit_hook {
            report.notes.push(format!(
                "one import slot holds themida's shutdown routine, which runs in its virtual machine and cannot be traced; it is named {EXIT_API}, the import themida hooks"
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
    snapshot: Snapshot<'a>, // wrappers run against the image as captured, not the half-restored one
    engine: Range<u64>,
    destinations: HashMap<usize, Option<Destination>>,
    failed: usize,
}

impl Tracer<'_> {
    fn slot(&self, at: usize) -> Slot {
        let exports = self.packed.origin.exports;
        match read_pointer(self.snapshot.image, at, self.packed.kind()) {
            Ok(0) => Slot::Empty,
            Ok(value) if self.engine.contains(&(value as u64)) => Slot::Wrapped(value),
            Ok(value) if exports.resolve(value).is_some() => Slot::Api,
            _ => Slot::Other,
        }
    }

    fn destination(&mut self, wrapper: usize) -> Option<Destination> {
        if let Some(known) = self.destinations.get(&wrapper) {
            return *known;
        }
        if self.failed >= MAX_FAILED_TRACES {
            return None; // a real table has a few odd slots, not this many dead ends
        }

        let exports = self.packed.origin.exports;
        let destination = self
            .snapshot
            .destination(wrapper as u64, &self.engine)
            .filter(|destination| match destination {
                Destination::Api(api) => exports.resolve(*api as usize).is_some(),
                Destination::VirtualMachine => true,
            });

        self.failed += usize::from(destination.is_none());
        self.destinations.insert(wrapper, destination);
        destination
    }

    fn imports(&mut self, at: usize) -> bool {
        match self.slot(at) {
            Slot::Api => true,
            Slot::Wrapped(wrapper) => self.destination(wrapper).is_some(),
            Slot::Empty | Slot::Other => false,
        }
    }
}

pub(super) fn restore(restored: &mut [u8], packed: &Packed<'_>) -> Imports {
    let kind = packed.kind();
    let width = kind.pointer_width();
    let base = packed.origin.base;
    let mut tracer = Tracer {
        packed,
        snapshot: packed.snapshot(),
        engine: packed.engine(),
        destinations: HashMap::new(),
        failed: 0,
    };

    let referenced = code_referenced_slots(packed.image, base);
    let mut imports = Imports::default();
    let mut hooks = Vec::new();

    for table in wrapped_tables(&mut tracer, &referenced) {
        for slot in table.clone().step_by(width) {
            let Slot::Wrapped(wrapper) = tracer.slot(slot) else {
                continue;
            };

            match tracer.destination(wrapper) {
                Some(Destination::Api(api)) => match write_pointer(restored, slot, kind, api) {
                    Ok(()) => imports.traced += 1,
                    Err(_) => imports.untraced += 1,
                },
                Some(Destination::VirtualMachine) => hooks.push(slot),
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

    imports.exit_hook = name_exit_hook(restored, packed, &hooks);
    imports.untraced += hooks.len() - usize::from(imports.exit_hook);
    imports
}

fn name_exit_hook(restored: &mut [u8], packed: &Packed<'_>, hooks: &[usize]) -> bool {
    let [slot] = hooks else {
        return false; // themida hooks one import: the one that ends the process
    };

    packed
        .origin
        .exports
        .address_of(EXIT_MODULE, EXIT_API)
        .is_some_and(|api| write_pointer(restored, *slot, packed.kind(), api as u64).is_ok())
}

fn wrapped_tables(tracer: &mut Tracer<'_>, referenced: &BTreeSet<usize>) -> Vec<Range<usize>> {
    let packed = tracer.packed;
    let width = packed.kind().pointer_width();
    let image_end = packed.image.bytes().len();
    let mut tables: Vec<Range<usize>> = Vec::new();

    for section in packed.model().sections() {
        let range = section.range();
        let bounds = range.start..range.end.min(image_end);
        if bounds.start >= packed.layout.original_end {
            continue;
        }

        for anchor in referenced.range(bounds.clone()) {
            let covered = tables.last().is_some_and(|table| table.contains(anchor));
            if covered || !tracer.imports(*anchor) {
                continue; // data that only looks like a pointer is never called through
            }

            let table = grow(tracer, *anchor, &bounds, width);
            if table.len() / width >= MIN_TABLE_SLOTS {
                tables.push(table);
            }
        }
    }

    tables
}

fn grow(
    tracer: &mut Tracer<'_>,
    anchor: usize,
    bounds: &Range<usize>,
    width: usize,
) -> Range<usize> {
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
    tracer: &mut Tracer<'_>,
    slot: usize,
    bounds: &Range<usize>,
    width: usize,
    forward: bool,
) -> Option<usize> {
    let next = neighbour_slot(slot, bounds, width, forward)?;
    if tracer.imports(next) {
        return Some(next);
    }

    let beyond = neighbour_slot(next, bounds, width, forward)?;
    (matches!(tracer.slot(next), Slot::Empty) && tracer.imports(beyond)).then_some(beyond) // one empty slot ends a module's list
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

fn name_hints(image: &[u8], kind: PeKind, layout: &Layout, iat: &Range<usize>) -> NameHints {
    let width = kind.pointer_width();
    let ordinal = 1usize << (width * 8 - 1);
    let Some(lookups) = lookup_table(image, kind, layout, iat) else {
        return NameHints::new(); // themida wipes the names but leaves the linker's lookup table
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
    layout: &Layout,
    iat: &Range<usize>,
) -> Option<Vec<(usize, usize)>> {
    let width = kind.pointer_width();
    let ordinal = 1usize << (width * 8 - 1);
    let filled: Vec<bool> = iat
        .clone()
        .step_by(width)
        .map(|slot| read_pointer(image, slot, kind).is_ok_and(|value| value != 0))
        .collect();

    let names = FIRST_SECTION_RVA..layout.original_end;
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
    }; // the lookup table has an entry wherever the iat has an address, and a zero wherever it has none
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

            let longest = gap.saturating_sub(HINT_SIZE + 1); // a hint, the name, its terminator, then padding to an even size
            let shortest = match Some(*record) == last {
                true => 1, // the module's own name follows its last record
                false => longest.saturating_sub(1),
            };
            hints.push((*index, NameHint::Length(shortest..=longest)));
        }
    }

    hints
}
