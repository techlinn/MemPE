use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

use super::{Packed, counted};
use crate::pe::PeKind;
use crate::pe::packers::PackerReport;
use crate::pe::packers::branches::REL32_LEN;
use crate::pe::packers::emu::{Handover, Landing};
use crate::pe::packers::tables::{READ_ONLY_SECTION, place_table};

const MAX_VM_REGIONS: usize = 1_024;
const MAX_VM_REGION: usize = 0x1_0000;
const MAX_FAILED_REGIONS: usize = 8; // a run that never comes back costs the emulator's whole budget, seconds each
const MAX_LANDINGS: usize = 64;
const MAX_STRING_STUBS: usize = 4_096;
const MIN_STRING_BYTES: usize = 3;
const STRING_ALIGNMENT: usize = 4;
const STRING_SECTION: &[u8; 8] = b".strings";
const FILLER_LEN: usize = 2; // themida pads with two byte moves of a register to itself
const MIN_FILLER_RUN: usize = 3;
const LEA_LEN: usize = 7; // lea r64 [rip+disp32], the load an x64 string stub replaces
const PUSH_IMM32: u8 = 0x68;
const MOV_IMM32: u8 = 0xB8; // plus the register number
const LEA: u8 = 0x8D;
const REX_W: u8 = 0x48;
const RIP_RELATIVE: u8 = 0x05; // modrm mod 00 rm 101
const NOP: u8 = 0x90;
const INT3: u8 = 0xCC;

pub(super) fn clean(restored: &mut Vec<u8>, packed: &Packed<'_>, report: &mut PackerReport) {
    let regions = bound_virtualized(restored, packed);
    if regions.entered > 0 {
        report.lost.push("virtualized code");
        report.notes.push(format!(
            "{} from the program's code into themida's virtual machines left as they are, {} of them padded with int3 up to where the virtual machine hands back to native code",
            counted(regions.entered, "jump", "jumps"),
            regions.bounded
        ));
    }

    let (hidden, unread) = hidden_strings(restored, packed);
    let decrypted = place_strings(restored, packed, &hidden);
    if decrypted > 0 {
        report.restored.push("encrypted strings");
        report.notes.push(format!(
            "{} themida decrypts on use run through its virtual machine, written back into the image and pointed at from the code",
            counted(decrypted, "string", "strings")
        ));
    }
    if unread + (hidden.len() - decrypted) > 0 {
        report.unrestored.push(
            "some calls into themida's engine (no single string or value came back from them)",
        );
    }

    let markers = clear_filler(restored, packed.code(), packed.kind().bits());
    if markers > 0 {
        report.notes.push(format!(
            "{} themida left where sdk markers sat turned into nops",
            counted(markers, "run of filler", "runs of filler")
        ));
    }
}

struct Regions {
    entered: usize,
    bounded: usize,
}

fn bound_virtualized(restored: &mut [u8], packed: &Packed<'_>) -> Regions {
    let snapshot = packed.snapshot();
    let base = snapshot.base;
    let native: Vec<Range<u64>> = packed
        .code()
        .iter()
        .map(|range| base + range.start as u64..base + range.end as u64)
        .collect();
    let returned = |found: &[Landing]| {
        found.last().is_some_and(|landing| landing.balanced) || found.len() >= MAX_LANDINGS
    }; // a landing with the stack lower is native code the virtualized code calls

    let sites: Vec<usize> = packed
        .branches_into_tail(restored)
        .into_iter()
        .filter(|branch| !branch.call) // themida enters its virtual machines with a jump
        .map(|branch| branch.site)
        .collect();
    let mut regions = Regions {
        entered: sites.len(),
        bounded: 0,
    };
    let mut failed = 0;

    for site in sites.into_iter().take(MAX_VM_REGIONS) {
        if failed >= MAX_FAILED_REGIONS {
            break;
        }

        let end = snapshot
            .native_landings(base + site as u64, &native, &returned)
            .as_deref()
            .and_then(<[Landing]>::last)
            .filter(|landing| landing.balanced)
            .and_then(|landing| landing.address.checked_sub(base))
            .and_then(|end| usize::try_from(end).ok());
        let Some(junk) = end.and_then(|end| restored.get_mut(site + REL32_LEN..end)) else {
            failed += 1;
            continue;
        };
        if junk.len() > MAX_VM_REGION {
            continue; // the vm went somewhere else in the program, not back past its own region
        }

        junk.fill(INT3);
        regions.bounded += 1;
    }

    regions
}

struct Hidden {
    site: usize,
    handover: Handover,
    text: Vec<u8>,
}

fn hidden_strings(restored: &[u8], packed: &Packed<'_>) -> (Vec<Hidden>, usize) {
    let snapshot = packed.snapshot();
    let mut found = Vec::new();
    let mut failed = 0;

    let calls = packed
        .branches_into_tail(restored)
        .into_iter()
        .filter(|branch| branch.call); // themida swaps the string's push or load for a call into its engine
    for branch in calls.take(MAX_STRING_STUBS) {
        let site = snapshot.base + branch.site as u64;
        let hidden = snapshot
            .stub_value(site, REL32_LEN as u64)
            .and_then(|value| {
                let rebuildable = match (value.handover, snapshot.bits) {
                    (_, 32) => true, // a push or a mov of an immediate, both as long as the call
                    (Handover::Register(_), _) => {
                        filler_at(restored, branch.site + REL32_LEN, snapshot.bits)
                    }
                    (Handover::Pushed, _) => false,
                };

                rebuildable.then_some(Hidden {
                    site: branch.site,
                    handover: value.handover,
                    text: string_bytes(&value.data)?.to_vec(),
                })
            });

        match hidden {
            Some(hidden) => found.push(hidden),
            None => failed += 1,
        }
    }

    (found, failed)
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

    data.get(..end)
        .filter(|text| text.len() >= MIN_STRING_BYTES)
}

fn place_strings(restored: &mut Vec<u8>, packed: &Packed<'_>, hidden: &[Hidden]) -> usize {
    if hidden.is_empty() {
        return 0;
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
        READ_ONLY_SECTION,
    ) else {
        return 0;
    };

    let base = packed.origin.base;
    let mut written = 0;
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
            written += 1;
        }
    }

    written
}

fn string_load(string: &Hidden, kind: PeKind, site: usize, text: usize) -> Option<Vec<u8>> {
    let absolute = || u32::try_from(text).ok().map(u32::to_le_bytes);

    Some(match (string.handover, kind) {
        (Handover::Pushed, _) => [&[PUSH_IMM32][..], &absolute()?].concat(),
        (Handover::Register(reg), PeKind::Pe32) => [&[MOV_IMM32 + reg][..], &absolute()?].concat(),
        (Handover::Register(reg), PeKind::Pe32Plus) => {
            let disp = i32::try_from(text as i64 - (site + LEA_LEN) as i64).ok()?;
            let rex = REX_W | ((reg >> 3) << 2);
            [
                &[rex, LEA, ((reg & 7) << 3) | RIP_RELATIVE][..],
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

fn clear_filler(restored: &mut [u8], code: &[Range<usize>], bits: u32) -> usize {
    let mut runs = Vec::new();
    for range in code {
        let Some(bytes) = restored.get(range.clone()) else {
            continue;
        };

        let mut decoder = Decoder::with_ip(bits, bytes, range.start as u64, DecoderOptions::NONE);
        let mut run = range.start..range.start;
        while decoder.can_decode() {
            let insn = decoder.decode();
            let at = insn.ip() as usize;
            if self_move(&insn) {
                if run.end != at {
                    run = at..at;
                }
                run.end = at + FILLER_LEN;
                continue;
            }

            if run.len() >= MIN_FILLER_RUN * FILLER_LEN {
                runs.push(run.clone()); // what themida leaves where an sdk marker sat; compilers never emit such a run
            }
            run = at..at;
        }
    }

    for run in &runs {
        if let Some(area) = restored.get_mut(run.clone()) {
            area.fill(NOP);
        }
    }

    runs.len()
}
