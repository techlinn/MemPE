use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use super::{Functions, Packed, jumps_into, opens_section_or_follows_padding};
use crate::pe::PeKind;
use crate::pe::bytes::{read_pointer, write_u32};
use crate::unpack::tables::unique;
use crate::unpack::x86::branches::{CALL_REL32, JUMP_REL32, rel32_target};
use crate::unpack::x86::compiler_entry::{compiler_entry, msvc_startup_stub, sets_cookie};
use crate::unpack::x86::{Landing, WrapperLeadsTo};
use crate::unpack::{PackerReport, Part};

const MAX_ENTRY_CANDIDATES: usize = 64;
const MAX_STORED_POINTERS: usize = 16;
const STARTUP_LANDINGS: usize = 2; // cookie call, then main jmp

pub(super) fn restore(
    restored: &mut [u8],
    packed: &Packed<'_>,
    report: &mut PackerReport,
) -> Option<usize> {
    let model = packed.model();
    let mut search = Search {
        packed,
        landings: HashMap::new(),
    };
    let compiled = compiler_entry(restored, model, &packed.code, packed.origin.base);
    let stored = compiled
        .is_none()
        .then(|| stored_entry(restored, packed))
        .flatten();
    let obfuscated = match compiled {
        Some(_) => None,
        None => search.obfuscated_entry(stored, report),
    };
    let entry = compiled.or(obfuscated).or(stored);

    let written = entry
        .and_then(|entry| u32::try_from(entry).ok())
        .is_some_and(|entry| write_u32(restored, model.entry_point_offset, entry).is_ok());
    let entry = entry.filter(|_| written);
    let rebuilt = obfuscated
        .filter(|_| written)
        .and_then(|at| search.msvc_startup(restored, at));

    let found_by = match (compiled, obfuscated) {
        (Some(_), _) => "the only match for a known compiler's startup code",
        (None, Some(_)) => "the only function start whose jump into themida's virtual machine fits",
        (None, None) => "the only uncalled function address themida kept",
    };
    match (entry, obfuscated, rebuilt) {
        (None, _, _) => report.failed_with(Part::EntryPoint, "no known runtime entry, no jump into themida, and no single address themida kept for it"),
        (Some(at), None, _) => {
            report.inferred(Part::EntryPoint, found_by);
            if jumps_into(restored, at, &packed.layout.engine) {
                report.lost_with(Part::EntryCode, "it jumps into themida's sections");
            }
        }
        (Some(_), Some(_), Some(())) => {
            report.inferred(Part::EntryPoint, found_by);
            report.inferred(Part::EntryCode, "msvc startup, rebuilt from where themida's virtual machine went");
        }
        (Some(at), Some(_), None) => {
            report.inferred(Part::EntryPoint, found_by);
            report.lost_with(Part::EntryCode, "virtualized");
            if let Some(note) = search.where_entry_leads(at) {
                report.notes.push(note);
            }
        }
    }

    entry
}

struct Search<'a> {
    packed: &'a Packed<'a>,
    landings: HashMap<(usize, usize), Option<Vec<Landing>>>, // by entry and landings wanted
}

impl Search<'_> {
    fn obfuscated_entry(
        &mut self,
        stored: Option<usize>,
        report: &mut PackerReport,
    ) -> Option<usize> {
        let packed = self.packed;
        let bytes = packed.image.bytes();
        let runner = packed.runner();
        let engine = packed.va(&packed.layout.engine);
        let enters_vm = |at: &usize| {
            runner.destination(runner.base + *at as u64, &engine)
                == Some(WrapperLeadsTo::VirtualMachine)
        };

        let jumps = packed
            .code
            .iter()
            .flat_map(|range| range.clone())
            .filter(|at| {
                opens_section_or_follows_padding(bytes, &packed.code, *at)
                    && jumps_into(bytes, *at, &packed.layout.engine)
            });

        let candidates: Vec<usize> = jumps.take(MAX_ENTRY_CANDIDATES + 1).collect();
        if candidates.len() > MAX_ENTRY_CANDIDATES {
            report.notes.push(format!(
                "more than {MAX_ENTRY_CANDIDATES} function starts jump into themida's sections, so none of them was tried as the entry point"
            ));
            return None;
        }

        unique(
            candidates
                .into_iter()
                .filter(enters_vm)
                .filter(|at| stored == Some(*at) || self.starts_msvc_runtime(*at)),
        )
    }

    fn where_entry_leads(&mut self, entry: usize) -> Option<String> {
        let base = self.packed.origin.base as u64;
        let landings = [STARTUP_LANDINGS, 1]
            .into_iter()
            .find_map(|wanted| self.first_landings(entry, wanted))?;

        let reached: Vec<String> = landings
            .iter()
            .filter_map(|landing| landing.address.checked_sub(base))
            .map(|rva| format!("0x{rva:08X}"))
            .collect();
        Some(format!(
            "the entry point runs in themida's virtual machine and goes on to the program's code at {}, which is where to start reading",
            reached.join(", then ")
        ))
    }

    fn starts_msvc_runtime(&mut self, entry: usize) -> bool {
        let packed = self.packed;
        let base = packed.origin.base as u64;
        let x64 = packed.kind() == PeKind::Pe32Plus;

        self.first_landings(entry, 1)
            .and_then(|landings| landings.first().map(|landing| landing.address))
            .and_then(|cookie| usize::try_from(cookie.checked_sub(base)?).ok())
            .is_some_and(|cookie| sets_cookie(packed.image.bytes(), cookie, x64))
    }

    fn first_landings(&mut self, entry: usize, wanted: usize) -> Option<Vec<Landing>> {
        let longer = self
            .landings
            .get(&(entry, STARTUP_LANDINGS))
            .filter(|_| wanted < STARTUP_LANDINGS);
        if let Some(Some(longer)) = longer {
            return Some(longer[..wanted].to_vec());
        }
        if let Some(landings) = self.landings.get(&(entry, wanted)) {
            return landings.clone();
        }

        let packed = self.packed;
        let runner = packed.runner();
        let native: Vec<Range<u64>> = packed.code.iter().map(|range| packed.va(range)).collect();
        let landings = runner.native_landings(runner.base + entry as u64, &native, &|found| {
            found.len() == wanted
        });
        self.landings.insert((entry, wanted), landings.clone());
        landings
    }

    fn msvc_startup(&mut self, restored: &mut [u8], entry: usize) -> Option<()> {
        let packed = self.packed;
        let base = packed.origin.base as u64;
        let landings = self.first_landings(entry, STARTUP_LANDINGS)?;
        let [cookie, main] = landings[..] else {
            return None;
        };
        if cookie.balanced || !main.balanced {
            return None;
        }
        let cookie = usize::try_from(cookie.address.checked_sub(base)?).ok()?;
        let main = usize::try_from(main.address.checked_sub(base)?).ok()?;

        let x64 = packed.kind() == PeKind::Pe32Plus;
        sets_cookie(restored, cookie, x64).then_some(())?;
        let stub = msvc_startup_stub(entry, cookie, main, x64)?;

        let end = entry + stub.len();
        let overruns = Functions::read(restored, packed.model())
            .containing(entry)
            .is_some_and(|function| end > function.end);
        if overruns {
            return None;
        }

        restored.get_mut(entry..end)?.copy_from_slice(&stub);
        Some(())
    }
}

fn stored_entry(bytes: &[u8], packed: &Packed<'_>) -> Option<usize> {
    let kind = packed.kind();
    let code = &packed.code;
    let variables = &packed.layout.variables;
    let variables = bytes.get(variables.start..variables.end.min(bytes.len()))?;
    let in_code = |rva: usize| code.iter().any(|range| range.contains(&rva));

    let mut pointed = BTreeSet::new();
    for window in variables.windows(kind.pointer_width()) {
        let Ok(value) = read_pointer(window, 0, kind) else {
            continue;
        };
        let Some(rva) = value
            .checked_sub(packed.origin.base)
            .filter(|rva| in_code(*rva))
        else {
            continue;
        };

        pointed.insert(rva);
        if pointed.len() > MAX_STORED_POINTERS {
            return None; // chance hits in big x86 images
        }
    }

    let called: BTreeSet<usize> = code
        .iter()
        .flat_map(|range| range.clone())
        .filter(|at| matches!(bytes.get(*at), Some(&CALL_REL32 | &JUMP_REL32)))
        .filter_map(|at| rel32_target(bytes, at))
        .collect();

    unique(
        pointed.into_iter().filter(|rva| {
            opens_section_or_follows_padding(bytes, code, *rva) && !called.contains(rva)
        }),
    )
}
