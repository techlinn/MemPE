use std::collections::HashMap;
use std::ops::{Range, RangeInclusive};

use super::layout::Layout;
use super::mutation::Payload;
use crate::pe::image::{write_pointer, write_u32};
use crate::pe::packers::branches::{REL32_LEN, direct_branches};
use crate::pe::packers::emu::{self, Flow};
use crate::pe::packers::tables::{DATA_SECTION, append};
use crate::pe::packers::{NameHints, Origin, PackerImports};
use crate::pe::{IAT_DIRECTORY, PeKind, PeModel};

const MAX_STUB_SITES: usize = 200_000;
const MODULE_GAP: u64 = 0x1_0000; // api addresses this far apart get a zero slot between them
const IAT_SECTION: &[u8; 8] = b".vmpiat\0";

const PUSH_OR_POP: RangeInclusive<u8> = 0x50..=0x5F;
const PUSHF: u8 = 0x9C;
const NOP: u8 = 0x90;
const REX: RangeInclusive<u8> = 0x40..=0x4F;
const REX_W: u8 = 0x48;
const INDIRECT: u8 = 0xFF;
const CALL_MEMORY: u8 = 0x15; // modrm of ff /2 with a 32-bit address
const JUMP_MEMORY: u8 = 0x25; // modrm of ff /4 with a 32-bit address
const LOAD: u8 = 0x8B;
const LOAD_EAX: u8 = 0xA1;
const ADDRESS_ONLY: u8 = 0x05; // modrm mod 00 rm 101
const INDIRECT_LEN: usize = 6;
const LOAD_EAX_LEN: usize = 5;
const REX_LEN: usize = 1;
const EAX: u8 = 0;

pub(super) struct Import {
    site: usize,
    len: usize, // the bytes vmp rewrote from `site`
    flow: Flow,
    target: u64,
}

enum Reading {
    Import(Import),
    Refused, // a stub no single sound reading settles
    Stray,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Stray, // a call that only lands in vmp code by chance
    Stub,
}

pub(super) fn is_stub(bytes: &[u8], origin: &Origin<'_>, bits: u32, site: usize) -> bool {
    place(bytes, origin, bits, site, site).is_ok()
}

pub(super) fn resolve(
    bytes: &[u8],
    bits: u32,
    layout: &Layout,
    code: &[Range<usize>],
    vm_code: &Payload<'_>,
    origin: &Origin<'_>,
) -> (Vec<Import>, usize) {
    let stubs = layout
        .stubs
        .clone()
        .unwrap_or(layout.payload()..bytes.len()); // every direct branch in here is an import stub and any other is coincidence
    let mut found = Vec::new();
    let mut refused = 0;

    let resume = |insn: &_| vm_code.resume_after(insn);
    for branch in direct_branches(bytes, origin.base as u64, bits, code, &resume) {
        if found.len() >= MAX_STUB_SITES {
            break;
        }
        if !stubs.contains(&branch.target) {
            continue;
        }

        match read_site(bytes, origin, bits, branch.site) {
            Reading::Import(site) => found.push(site),
            Reading::Refused => refused += 1,
            Reading::Stray => {}
        }
    }

    let total = found.len();
    let kept = drop_overlaps(found);
    refused += total - kept.len();
    (kept, refused)
}

pub(super) fn rebuild(
    restored: &mut Vec<u8>,
    model: &PeModel,
    sites: &[Import],
    base: usize,
) -> Option<PackerImports> {
    (!sites.is_empty()).then_some(())?;
    let width = model.kind().pointer_width();
    let table = table_layout(sites);

    let iat_size = table.slots.len().checked_mul(width)?;
    let iat_rva = append(
        restored,
        model,
        IAT_SECTION,
        DATA_SECTION,
        &vec![0; iat_size],
    )?;
    for (index, target) in table.slots.iter().enumerate() {
        if let Some(target) = target {
            write_pointer(restored, iat_rva + index * width, model.kind(), *target).ok()?;
        }
    }

    for site in sites {
        let slot_rva = iat_rva + table.slot_of.get(&site.target)? * width;
        let end = site.site.checked_add(site.len)?;
        let disp = match model.kind() {
            PeKind::Pe32Plus => i32::try_from(slot_rva as i64 - end as i64).ok()?, // x64 reads the slot rip relative and x86 absolute
            PeKind::Pe32 => i32::from_ne_bytes(u32::try_from(base + slot_rva).ok()?.to_ne_bytes()),
        };

        let encoded = encode(site.flow, site.len, model.kind(), disp);
        (encoded.len() == site.len).then_some(())?;
        restored.get_mut(site.site..end)?.copy_from_slice(&encoded);
    }

    let rva = u32::try_from(iat_rva).ok()?;
    let size = u32::try_from(iat_size).ok()?;
    if let Ok(Some(offset)) = model.directory_offset(IAT_DIRECTORY) {
        write_u32(restored, offset, rva).ok()?;
        write_u32(restored, offset + 4, size).ok()?;
    }

    Some(PackerImports::FilledIat {
        rva,
        size,
        names: NameHints::new(),
    })
}

struct Table {
    slots: Vec<Option<u64>>, // None ends one module's run
    slot_of: HashMap<u64, usize>,
}

fn table_layout(sites: &[Import]) -> Table {
    let mut targets: Vec<u64> = sites.iter().map(|site| site.target).collect();
    targets.sort_unstable();
    targets.dedup();

    let mut table = Table {
        slots: Vec::new(),
        slot_of: HashMap::new(),
    };
    let mut previous: Option<u64> = None;
    for target in targets {
        if previous.is_some_and(|previous| target.saturating_sub(previous) >= MODULE_GAP) {
            table.slots.push(None);
        }

        table.slot_of.insert(target, table.slots.len());
        table.slots.push(Some(target));
        previous = Some(target);
    }
    table
}

fn read_site(bytes: &[u8], origin: &Origin<'_>, bits: u32, at: usize) -> Reading {
    let mut chosen: Option<Import> = None;
    let mut conflict = false;
    let mut stub_seen = false;

    for start in candidate_starts(bytes, at, bits) {
        let site = match place(bytes, origin, bits, start, at) {
            Ok(site) => site,
            Err(refusal) => {
                stub_seen |= refusal == Refusal::Stub;
                continue;
            }
        };

        match &chosen {
            None => chosen = Some(site),
            Some(kept) if kept.target == site.target && kept.flow == site.flow => {
                if site.len < kept.len {
                    chosen = Some(site); // a longer reading only swallowed a neutral byte in front
                }
            }
            Some(_) => conflict = true,
        }
    }

    match (chosen, conflict) {
        (Some(site), false) => Reading::Import(site),
        (Some(_), true) => Reading::Refused, // two sound readings, so restoring either would be a guess
        (None, _) if stub_seen => Reading::Refused,
        (None, _) => Reading::Stray,
    }
}

fn candidate_starts(bytes: &[u8], at: usize, bits: u32) -> Vec<usize> {
    let before = |back: usize| {
        at.checked_sub(back)
            .and_then(|position| bytes.get(position))
            .copied()
    };
    let neutral = |byte: u8| PUSH_OR_POP.contains(&byte) || byte == PUSHF || byte == NOP;

    let mut starts = vec![at];
    if before(1).is_some_and(neutral) {
        starts.push(at - 1); // vmp puts one in front of the call
        if bits == 64 && before(2).is_some_and(|byte| REX.contains(&byte)) {
            starts.push(at - 2);
        }
    }
    starts
}

fn place(
    bytes: &[u8],
    origin: &Origin<'_>,
    bits: u32,
    start: usize,
    at: usize,
) -> Result<Import, Refusal> {
    let base = origin.base as u64;
    let address = |offset: usize| base + offset as u64;
    let refusal = |failure| match failure {
        emu::Failure::Stray => Refusal::Stray,
        emu::Failure::Mismatch => Refusal::Stub,
    };
    let resolve =
        |seed| emu::resolve(bytes, base, bits, address(start), address(at), seed).map_err(refusal);
    let first = resolve(0)?;
    let second = resolve(1)?;

    let target = usize::try_from(first.target).map_err(|_| Refusal::Stray)?;
    if origin.exports.resolve(target).is_none() {
        return Err(Refusal::Stray);
    }
    let agree =
        first.target == second.target && first.flow == second.flow && first.end == second.end;
    if !agree {
        return Err(Refusal::Stub);
    }

    let len = match first.end {
        Some(end) => end
            .checked_sub(address(start))
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Refusal::Stub)?,
        None => (at - start + REL32_LEN).max(INDIRECT_LEN), // a jump never returns so its span belongs to vmp
    };
    if !fits(first.flow, len, bits) || start + len > bytes.len() {
        return Err(Refusal::Stub);
    }

    Ok(Import {
        site: start,
        len,
        flow: first.flow,
        target: first.target,
    })
}

fn fits(flow: Flow, len: usize, bits: u32) -> bool {
    let wide = bits == 64;
    match flow {
        Flow::Call | Flow::Jump => len == INDIRECT_LEN || (wide && len == INDIRECT_LEN + REX_LEN), // vmp may leave room for a redundant rex w
        Flow::Load(_) if wide => len == INDIRECT_LEN + REX_LEN,
        Flow::Load(reg) => len == INDIRECT_LEN || (len == LOAD_EAX_LEN && reg == EAX),
    }
}

fn drop_overlaps(mut sites: Vec<Import>) -> Vec<Import> {
    sites.sort_by_key(|site| site.site);

    let mut clash = vec![false; sites.len()];
    let mut reach: Option<(usize, usize)> = None; // furthest end so far and which site owns it
    for (index, site) in sites.iter().enumerate() {
        if let Some((end, owner)) = reach
            && site.site < end
        {
            clash[index] = true;
            clash[owner] = true; // two sites sharing bytes cannot both be real, so neither is restored
        }

        let end = site.site + site.len;
        if reach.is_none_or(|(furthest, _)| end > furthest) {
            reach = Some((end, index));
        }
    }

    sites
        .into_iter()
        .zip(clash)
        .filter_map(|(site, clashed)| (!clashed).then_some(site))
        .collect()
}

fn encode(flow: Flow, len: usize, kind: PeKind, disp: i32) -> Vec<u8> {
    let mut bytes = match flow {
        Flow::Call | Flow::Jump => {
            let modrm = match flow {
                Flow::Call => CALL_MEMORY,
                _ => JUMP_MEMORY,
            };
            match len == INDIRECT_LEN + REX_LEN {
                true => vec![REX_W, INDIRECT, modrm],
                false => vec![INDIRECT, modrm],
            }
        }
        Flow::Load(reg) if kind == PeKind::Pe32Plus => {
            let extended = (reg >> 3) << 2; // rex r carries the register's fourth bit
            vec![REX_W | extended, LOAD, ((reg & 7) << 3) | ADDRESS_ONLY]
        }
        Flow::Load(_) if len == LOAD_EAX_LEN => vec![LOAD_EAX],
        Flow::Load(reg) => vec![LOAD, (reg << 3) | ADDRESS_ONLY],
    };
    bytes.extend_from_slice(&disp.to_le_bytes());
    bytes
}
