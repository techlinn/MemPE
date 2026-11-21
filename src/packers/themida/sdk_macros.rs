use std::collections::BTreeSet;
use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

use super::demutation::{UnmutatedRegions, entries, referenced_starts, region};
use super::{Functions, Packed};
use crate::pe::bytes::{read_u16, write_u16};
use crate::pe::{DYNAMIC_BASE, PeKind};
use crate::unpack::counted;
use crate::unpack::tables::{SectionKind, place_table};
use crate::unpack::x86::branches::{REL32_LEN, instructions};
use crate::unpack::x86::opcodes::{INT3, LEA, MODRM_DISP32, MOV_REG_IMM32, NOP, PUSH_IMM32, REX_W};
use crate::unpack::x86::{Handover, Landing};
use crate::unpack::{PackerReport, Part};

const MAX_VM_REGIONS: usize = 1_024;
const MAX_FAILED_REGIONS: usize = 8;
const MAX_LANDINGS: usize = 64;
const MAX_STRING_STUBS: usize = 4_096;
const MAX_STUCK_STUBS: usize = 64;
const MIN_STRING_BYTES: usize = 3;
const STRING_ALIGNMENT: usize = 4;
const STRING_SECTION: &[u8; 8] = b".strings";
const FILLER_LEN: usize = 2; // mov reg, reg filler
const MIN_FILLER_RUN: usize = 3;
const LEA_LEN: usize = 7; // lea r64, [rip+disp32]
const ZERO_EXTENDING: usize = 4; // x64 clears the upper half on a 32-bit write

pub(super) fn clean(
    restored: &mut Vec<u8>,
    packed: &Packed<'_>,
    unmutated: &UnmutatedRegions,
    report: &mut PackerReport,
) {
    let regions = bound_virtualized(restored, packed, unmutated);
    if regions.entered > 0 {
        report.lost_with(
            Part::VirtualizedCode,
            "behind jumps into themida's sections that are not mutated code",
        );
        report.notes.push(format!(
            "{} from the program's code into themida's sections do not lead to mutated code and are left as they are, taken as entries to its virtual machines; {} of them padded with int3 up to where themida hands back to native code",
            counted(regions.entered, "jump", "jumps"),
            regions.bounded
        ));
    }
    if regions.untried > 0 {
        report.notes.push(format!(
            "{} of those jumps were not followed to where they hand back: only the first {MAX_VM_REGIONS} are, and none after {MAX_FAILED_REGIONS} that never came back",
            regions.untried
        ));
    }

    let calls = hidden_strings(restored, packed);
    let placed = place_strings(restored, packed, &calls.hidden);
    if placed.written > 0 {
        report.inferred(
            Part::EncryptedStrings,
            "what themida's engine calls hand back reads as text",
        );
        report.notes.push(format!(
            "{} handed back by calls into themida's engine written into the image and pointed at from the code",
            counted(placed.written, "string", "strings")
        ));
    }
    if placed.fixed_base {
        report.notes.push(
            "the image is no longer marked as relocatable: the rebuilt string loads hold absolute addresses and no fixups were added for them"
                .to_owned(),
        );
    }
    if calls.unread + calls.untried + (calls.hidden.len() - placed.written) > 0 {
        report.partly_failed(
            Part::EngineCalls,
            "no single string or value came back from them",
        );
    }
    if calls.untried > 0 {
        report.notes.push(format!(
            "{} into themida's engine were not run: only the first {MAX_STRING_STUBS} are, and none after {MAX_STUCK_STUBS} that never came back",
            counted(calls.untried, "call", "calls")
        ));
    }

    let anchors: BTreeSet<usize> = packed
        .branches_into_tail(packed.image.bytes())
        .into_iter()
        .map(|branch| branch.site)
        .collect();
    let filler = clear_filler(restored, &packed.code, packed.kind().bits(), &anchors);
    if filler.cleared > 0 {
        report.notes.push(format!(
            "{} of register moves that change nothing, next to a jump or call into themida's sections, turned into nops; they look like what themida leaves in place of sdk markers",
            counted(filler.cleared, "run", "runs")
        ));
    }
    if filler.left > 0 {
        report.notes.push(format!(
            "{} of such moves left as they are: nothing ties them to themida",
            counted(filler.left, "run", "runs")
        ));
    }
}

struct Regions {
    entered: usize,
    bounded: usize,
    untried: usize,
}

fn bound_virtualized(
    restored: &mut [u8],
    packed: &Packed<'_>,
    unmutated: &UnmutatedRegions,
) -> Regions {
    let runner = packed.runner();
    let base = runner.base;
    let native: Vec<Range<u64>> = packed.code.iter().map(|range| packed.va(range)).collect();
    let functions = Functions::read(restored, packed.model());
    let returned = |found: &[Landing]| {
        found.last().is_some_and(|landing| landing.balanced) || found.len() >= MAX_LANDINGS
    }; // a landing on a lower stack was called: a native callee, not the hand-back

    let branches = packed.branches(restored);
    let jumps = entries(restored, packed, &branches);
    let starts = referenced_starts(restored, &branches, &jumps);
    let sites: Vec<usize> = jumps
        .into_iter()
        .filter(|site| !unmutated.leads_to_mutated_code(*site))
        .collect();
    let mut regions = Regions {
        entered: sites.len(),
        bounded: 0,
        untried: sites.len().saturating_sub(MAX_VM_REGIONS),
    };

    let extents: Vec<(usize, usize)> = sites
        .into_iter()
        .take(MAX_VM_REGIONS)
        .map(|site| (site, region(restored, site, &starts, &functions).0))
        .collect();

    let mut failed = 0;
    for (tried, (site, extent)) in extents.iter().copied().enumerate() {
        if failed >= MAX_FAILED_REGIONS {
            regions.untried += extents.len() - tried;
            break;
        }

        let end = runner
            .native_landings(base + site as u64, &native, &returned)
            .as_deref()
            .and_then(<[Landing]>::last)
            .filter(|landing| landing.balanced)
            .and_then(|landing| landing.address.checked_sub(base))
            .and_then(|end| usize::try_from(end).ok());
        let Some(end) = end else {
            failed += 1;
            continue;
        };
        if end > extent {
            continue;
        }

        if let Some(junk) = restored.get_mut(site + REL32_LEN..end) {
            junk.fill(INT3);
            regions.bounded += 1;
        }
    }

    regions
}

struct Hidden {
    site: usize,
    handover: Handover,
    text: Vec<u8>,
}

struct EngineCalls {
    hidden: Vec<Hidden>,
    unread: usize,
    untried: usize,
}

fn hidden_strings(restored: &[u8], packed: &Packed<'_>) -> EngineCalls {
    let runner = packed.runner();
    let mut calls: Vec<_> = packed
        .branches_into_tail(restored)
        .into_iter()
        .filter(|branch| branch.call) // string push/load swapped for an engine call
        .collect();
    let mut found = EngineCalls {
        hidden: Vec::new(),
        unread: 0,
        untried: calls.len().saturating_sub(MAX_STRING_STUBS),
    };
    calls.truncate(MAX_STRING_STUBS);

    let mut stuck = 0;
    for (tried, branch) in calls.iter().enumerate() {
        if stuck >= MAX_STUCK_STUBS {
            found.untried += calls.len() - tried;
            break;
        }

        let site = runner.base + branch.site as u64;
        let Some(value) = runner.stub_value(site, REL32_LEN as u64) else {
            stuck += 1;
            found.unread += 1;
            continue;
        };
        let rebuildable = match (value.handover, runner.bits) {
            (_, 32) => true,
            (Handover::Register(_), _) => filler_at(restored, branch.site + REL32_LEN, runner.bits),
            (Handover::Pushed, _) => false,
        };
        let hidden = string_bytes(&value.data)
            .filter(|_| rebuildable)
            .map(|text| Hidden {
                site: branch.site,
                handover: value.handover,
                text: text.to_vec(),
            });

        match hidden {
            Some(hidden) => found.hidden.push(hidden),
            None => found.unread += 1,
        }
    }

    found
}

fn string_bytes(data: &[u8]) -> Option<&[u8]> {
    let wide = matches!(data, [first, 0, ..] if *first != 0);
    let end = match wide {
        true => data
            .as_chunks::<2>()
            .0
            .iter()
            .position(|unit| *unit == [0, 0])
            .map(|units| units * 2 + 2)?,
        false => data.iter().position(|byte| *byte == 0)? + 1,
    };

    let text = data
        .get(..end)
        .filter(|text| text.len() >= MIN_STRING_BYTES)?;
    let printable = |unit: u16| unit >= 0x20 || matches!(unit, 0x09 | 0x0A | 0x0D);
    let reads_as_text = match wide {
        true => text[..end - 2]
            .as_chunks::<2>()
            .0
            .iter()
            .all(|unit| printable(u16::from_le_bytes(*unit))),
        false => text[..end - 1]
            .iter()
            .all(|byte| printable(u16::from(*byte))),
    };

    reads_as_text.then_some(text)
}

struct Placed {
    written: usize,
    fixed_base: bool,
}

fn place_strings(restored: &mut Vec<u8>, packed: &Packed<'_>, hidden: &[Hidden]) -> Placed {
    let mut placed = Placed {
        written: 0,
        fixed_base: false,
    };
    if hidden.is_empty() {
        return placed;
    }

    let mut blob = Vec::new();
    let mut offsets = Vec::with_capacity(hidden.len());
    for string in hidden {
        blob.resize(blob.len().next_multiple_of(STRING_ALIGNMENT), 0);
        offsets.push(blob.len());
        blob.extend_from_slice(&string.text);
    }

    let program = 0..packed.layout.original_end;
    let Some(at) = place_table(
        restored,
        packed.model(),
        &program,
        &blob,
        STRING_SECTION,
        SectionKind::ReadOnly,
    ) else {
        return placed;
    };

    let base = packed.origin.base;
    for (string, offset) in hidden.iter().zip(offsets) {
        let load = string_load(
            string,
            packed.kind(),
            base + string.site,
            base + at + offset,
        );
        let slot = load.as_deref().and_then(|load| {
            Some((
                load,
                restored.get_mut(string.site..string.site + load.len())?,
            ))
        });
        if let Some((load, slot)) = slot {
            slot.copy_from_slice(load);
            placed.written += 1;
        }
    }

    if placed.written > 0 && packed.kind() == PeKind::Pe32 {
        let flags = packed.model().dll_characteristics_offset;
        let relocatable = read_u16(restored, flags)
            .ok()
            .filter(|value| value & DYNAMIC_BASE != 0);
        if let Some(value) = relocatable {
            placed.fixed_base = write_u16(restored, flags, value & !DYNAMIC_BASE).is_ok(); // x86 loads are absolute
        }
    }

    placed
}

fn string_load(string: &Hidden, kind: PeKind, site: usize, text: usize) -> Option<Vec<u8>> {
    let absolute = || u32::try_from(text).ok().map(u32::to_le_bytes);

    Some(match (string.handover, kind) {
        (Handover::Pushed, _) => [&[PUSH_IMM32][..], &absolute()?].concat(),
        (Handover::Register(reg), PeKind::Pe32) => {
            [&[MOV_REG_IMM32 + reg.number()][..], &absolute()?].concat()
        }
        (Handover::Register(reg), PeKind::Pe32Plus) => {
            let reg = reg.number();
            let disp = i32::try_from(text as i64 - (site + LEA_LEN) as i64).ok()?;
            let rex = REX_W | ((reg >> 3) << 2);
            [
                &[rex, LEA, ((reg & 7) << 3) | MODRM_DISP32][..],
                &disp.to_le_bytes(),
            ]
            .concat()
        }
    })
}

fn filler_at(bytes: &[u8], at: usize, bits: u32) -> bool {
    bytes
        .get(at..at + FILLER_LEN)
        .is_some_and(|window| self_move(&Decoder::new(bits, window, DecoderOptions::NONE).decode()))
}

fn self_move(insn: &Instruction) -> bool {
    insn.len() == FILLER_LEN
        && insn.mnemonic() == Mnemonic::Mov
        && insn.op0_kind() == OpKind::Register
        && insn.op1_kind() == OpKind::Register
        && insn.op0_register() == insn.op1_register()
}

fn changes_nothing(insn: &Instruction, bits: u32) -> bool {
    self_move(insn) && !(bits == 64 && insn.op0_register().size() == ZERO_EXTENDING)
}

struct Filler {
    cleared: usize,
    left: usize,
}

fn clear_filler(
    restored: &mut [u8],
    code: &[Range<usize>],
    bits: u32,
    engine_branches: &BTreeSet<usize>,
) -> Filler {
    let mut runs = Vec::new();
    let mut keep = |run: &Range<usize>| {
        if run.len() >= MIN_FILLER_RUN * FILLER_LEN {
            runs.push(run.clone());
        }
    };

    for range in code {
        let mut run = range.start..range.start;
        for insn in instructions(restored, 0, bits, range) {
            let at = insn.ip() as usize;
            if changes_nothing(&insn, bits) {
                if run.end != at {
                    keep(&run);
                    run = at..at;
                }
                run.end = at + FILLER_LEN;
                continue;
            }

            keep(&run);
            run = at..at;
        }
        keep(&run);
    }

    let beside_themida = |run: &Range<usize>| {
        let follows = run
            .start
            .checked_sub(REL32_LEN)
            .is_some_and(|site| engine_branches.contains(&site));
        follows || engine_branches.contains(&run.end)
    };
    let mut filler = Filler {
        cleared: 0,
        left: 0,
    };
    for run in &runs {
        let area = restored
            .get_mut(run.clone())
            .filter(|_| beside_themida(run));
        match area {
            Some(area) => {
                area.fill(NOP);
                filler.cleared += 1;
            }
            None => filler.left += 1,
        }
    }

    filler
}
