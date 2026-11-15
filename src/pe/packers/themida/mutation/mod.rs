mod assembly;
mod body;
mod encodings;
mod synthesis;

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Instruction, Mnemonic};

use self::assembly::{Piece, Style, encode, hot_patchable, layout, nops, retarget, retarget_all};
use self::body::{Body, End};
use super::{Packed, counted};
use crate::pe::packers::PackerReport;
use crate::pe::packers::branches::{
    Branch, JUMP_REL32, REL32_LEN, is_near_immediate, rel32_target, set_rel32_target,
};
use crate::pe::packers::emu::{Agreement, Probe, same_behaviour};
use crate::pe::packers::tables::{CODE_SECTION, append, next_section_rva};

const MAX_REGIONS: usize = 4_096;
const MAX_REGION: usize = 0x1_0000; // a function themida mutated whole, or the code between two sdk markers
const INT3: u8 = 0xCC;
const RET: u8 = 0xC3;
const FUNCTION_ALIGNMENT: usize = 16; // compilers start functions on this boundary and pad up to it with int3
const UNMUTATED_SECTION: &[u8; 8] = b".unmut\0\0";

pub(super) struct Rewrite {
    site: usize,
    entry: u64,
    limit: usize, // where the bytes themida replaced stop: the region's continuation, padding or the next code
    code: Vec<Instruction>,
    instructions: usize,
    junk: usize, // instructions whose junk no single instruction stood in for, kept as themida left them
}

pub(super) struct Unmutated {
    rewrites: Vec<Rewrite>,
    style: Style,
}

pub(super) fn analyse(restored: &[u8], packed: &Packed<'_>) -> Unmutated {
    let snapshot = packed.snapshot();
    let style = Style::of(restored, snapshot.base, snapshot.bits, packed.code());
    let mut rewrites = found(restored, packed);

    let functions: BTreeMap<u64, u64> = rewrites
        .iter()
        .map(|rewrite| (rewrite.entry, snapshot.base + rewrite.site as u64))
        .collect();
    for insn in rewrites
        .iter_mut()
        .flat_map(|rewrite| rewrite.code.iter_mut())
    {
        let start = is_near_immediate(insn)
            .then(|| functions.get(&insn.near_branch_target()))
            .flatten();
        if let Some(start) = start {
            retarget(insn, *start); // themida calls a mutated function's body directly, the clean code calls the function
        }
    }

    rewrites.retain(|rewrite| verified(restored, packed, rewrite, style));
    Unmutated { rewrites, style }
}

pub(super) fn apply(
    restored: &mut Vec<u8>,
    packed: &Packed<'_>,
    unmutated: &Unmutated,
    report: &mut PackerReport,
) {
    let base = packed.origin.base as u64;
    let bits = packed.kind().bits();
    let mut placed = 0;
    let mut moved = Vec::new();

    for rewrite in &unmutated.rewrites {
        let bytes = in_place(rewrite, bits, base, unmutated.style);
        match bytes.zip(restored.get_mut(rewrite.site..rewrite.limit)) {
            Some((bytes, area)) => {
                area.copy_from_slice(&bytes);
                placed += 1;
            }
            None => moved.push(rewrite),
        }
    }
    placed += place_elsewhere(restored, packed, &moved, unmutated.style);
    if placed == 0 {
        return;
    }

    let instructions: usize = unmutated
        .rewrites
        .iter()
        .map(|rewrite| rewrite.instructions)
        .sum();
    let junk: usize = unmutated.rewrites.iter().map(|rewrite| rewrite.junk).sum();
    report.restored.push("mutated code");
    report.notes.push(format!(
        "{} unmutated back to the {instructions} instructions themida mutated, {junk} of them still wrapped in its junk",
        counted(placed, "mutated region", "mutated regions"),
    ));
}

fn found(restored: &[u8], packed: &Packed<'_>) -> Vec<Rewrite> {
    let snapshot = packed.snapshot();
    let probe = Probe {
        image: snapshot.image,
        base: snapshot.base,
        bits: snapshot.bits,
    };
    let tail = packed.tail();
    let packer = snapshot.base + tail.start as u64..snapshot.base + tail.end as u64;
    let branches = packed.branches(restored);
    let entries = entries(restored, packed, &branches);
    let starts = referenced_starts(restored, &branches, &entries);

    entries
        .into_iter()
        .take(MAX_REGIONS)
        .filter_map(|site| {
            let entry = snapshot.trampoline_target(snapshot.base + site as u64, &packer)?; // none for a virtual machine
            let body = body::decode(snapshot.image, snapshot.base, snapshot.bits, entry, &packer)?;
            let mut rewrite = rewrite(&probe, &body, site, limit(packed, &body, site, &starts))?;
            if starts_function(restored, site) {
                hot_patchable(&mut rewrite.code, snapshot.bits);
            }
            Some(rewrite)
        })
        .collect()
}

fn entries(restored: &[u8], packed: &Packed<'_>, branches: &[Branch]) -> BTreeSet<usize> {
    let tail = packed.tail();
    let swept = branches
        .iter()
        .filter(|branch| !branch.call && tail.contains(&branch.target))
        .map(|branch| branch.site);

    let starting = packed.code().iter().cloned().flatten().filter(|at| {
        starts_function(restored, *at)
            && restored.get(*at) == Some(&JUMP_REL32)
            && rel32_target(restored, *at).is_some_and(|target| tail.contains(&target))
    }); // a sweep through the junk of the function before can step over a mutated function's entry jump

    swept.chain(starting).collect()
}

fn starts_function(image: &[u8], at: usize) -> bool {
    at.is_multiple_of(FUNCTION_ALIGNMENT)
        || at.checked_sub(1).and_then(|before| image.get(before)) == Some(&INT3)
}

fn rewrite(probe: &Probe<'_>, body: &Body, site: usize, limit: usize) -> Option<Rewrite> {
    let loop_heads = body.loop_heads();
    let fall_throughs = body.fall_throughs();
    let mut pieces = BTreeMap::new();
    let mut junk = 0;
    for (start, block) in &body.blocks {
        let piece = match (simplify_block(probe, &block.code), &block.end) {
            (Some(clean), End::Next(next)) if clean.is_empty() => {
                match (loop_heads.contains(next), fall_throughs.contains(start)) {
                    (true, _) if !block.code.is_empty() => Piece::Padding,
                    (_, false) => Piece::Jump,
                    (_, true) => Piece::Code(clean), // themida's own jump past a conditional one
                }
            }
            (Some(clean), _) => Piece::Code(clean),
            (None, _) => {
                junk += 1;
                Piece::Code(block.code.clone())
            }
        };
        pieces.insert(*start, piece);
    }

    Some(Rewrite {
        site,
        entry: body.entry,
        limit,
        code: layout(body, &pieces, probe.bits)?,
        instructions: body.blocks.len(),
        junk,
    })
}

fn simplify_block(probe: &Probe<'_>, code: &[Instruction]) -> Option<Vec<Instruction>> {
    let is_call = |insn: &Instruction| insn.is_call_near() || insn.is_call_near_indirect();
    let mut clean = Vec::new();

    for piece in code.split_inclusive(is_call) {
        let (call, around) = match piece.split_last() {
            Some((last, rest)) if is_call(last) => (Some(*last), rest),
            _ => (None, piece),
        };
        clean.extend(synthesis::simplify(probe, around)?); // a call is never rewritten, the junk around it is
        clean.extend(call);
    }

    Some(clean)
}

fn in_place(rewrite: &Rewrite, bits: u32, base: u64, style: Style) -> Option<Vec<u8>> {
    let site = base + rewrite.site as u64;
    let end = base + rewrite.limit as u64;
    let room = rewrite.limit.checked_sub(rewrite.site)?;

    let mut code = rewrite.code.clone();
    let continues = code.last().is_some_and(|last| {
        last.mnemonic() == Mnemonic::Jmp
            && is_near_immediate(last)
            && last.near_branch_target() == end
    });
    if continues {
        let jump = code.pop()?;
        retarget_all(&mut code, jump.ip(), end);
    }

    let mut bytes = encode(&code, bits, site, style).filter(|bytes| bytes.len() <= room)?;
    let rest = room - bytes.len();
    match continues {
        true => bytes.extend(nops(rest)),  // where themida's end marker sat
        false => bytes.resize(room, INT3), // the rest of what themida overwrote is never reached
    }
    Some(bytes)
}

fn place_elsewhere(
    restored: &mut Vec<u8>,
    packed: &Packed<'_>,
    rewrites: &[&Rewrite],
    style: Style,
) -> usize {
    let model = packed.model();
    let base = packed.origin.base as u64;
    let bits = packed.kind().bits();
    let Some(start) = next_section_rva(restored, model) else {
        return 0;
    };

    let mut section = Vec::new();
    let mut jumps = Vec::new();
    for rewrite in rewrites {
        let at = start + section.len();
        let Some(bytes) = encode(&rewrite.code, bits, base + at as u64, style) else {
            continue;
        };
        section.extend_from_slice(&bytes);
        jumps.push((rewrite.site, at));
    }
    if section.is_empty()
        || append(restored, model, UNMUTATED_SECTION, CODE_SECTION, &section) != Some(start)
    {
        return 0;
    }

    jumps
        .into_iter()
        .filter(|(site, at)| set_rel32_target(restored, *site, *at).is_some())
        .count()
}

fn verified(restored: &[u8], packed: &Packed<'_>, rewrite: &Rewrite, style: Style) -> bool {
    let base = packed.origin.base as u64;
    let bits = packed.kind().bits();
    let tail = packed.tail();
    let mut patched = restored.to_vec(); // imports already traced, so calls reach their apis and not themida's wrappers
    let written = match in_place(rewrite, bits, base, style) {
        Some(bytes) => patched
            .get_mut(rewrite.site..rewrite.limit)
            .map(|area| area.copy_from_slice(&bytes)),
        None => {
            let at = tail.start; // themida's own pages stand in for wherever the code ends up
            encode(&rewrite.code, bits, base + at as u64, style).and_then(|bytes| {
                patched
                    .get_mut(at..at + bytes.len())?
                    .copy_from_slice(&bytes);
                set_rel32_target(&mut patched, rewrite.site, at)
            })
        }
    };

    let private = base + tail.start as u64..base + tail.end as u64;
    written.is_some()
        && same_behaviour(
            restored,
            &patched,
            base,
            bits,
            base + rewrite.site as u64,
            &private,
            Agreement::Finished,
        )
}

fn limit(packed: &Packed<'_>, body: &Body, site: usize, starts: &BTreeSet<usize>) -> usize {
    let base = packed.origin.base;
    let image = packed.image.bytes();
    let continuation = body
        .blocks
        .values()
        .filter_map(|block| match &block.end {
            End::Exit(exit) if is_near_immediate(exit) => {
                usize::try_from(exit.near_branch_target())
                    .ok()?
                    .checked_sub(base)
            }
            _ => None,
        })
        .filter(|target| *target > site)
        .min();
    let next = starts.range(site + 1..).next().copied();
    let padding = padding_after(image, site);

    [continuation, next, padding, Some(site + MAX_REGION)]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(site)
}

fn padding_after(image: &[u8], site: usize) -> Option<usize> {
    (site + REL32_LEN..site + MAX_REGION).find(|at| is_padding(image, *at))
}

fn is_padding(image: &[u8], at: usize) -> bool {
    let aligned = at.next_multiple_of(FUNCTION_ALIGNMENT);
    let Some(run) = image.get(at..aligned).filter(|run| !run.is_empty()) else {
        return false;
    };

    let after_return = at.checked_sub(1).and_then(|before| image.get(before)) == Some(&RET);
    run.iter().all(|byte| *byte == INT3) && (run.len() > 1 || after_return) // a lone 0xcc is as likely themida's random fill
}

fn referenced_starts(
    restored: &[u8],
    branches: &[Branch],
    entries: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let filled: BTreeMap<usize, usize> = entries
        .iter()
        .map(|site| {
            (
                *site,
                padding_after(restored, *site).unwrap_or(site + REL32_LEN),
            )
        })
        .collect();
    let in_fill = |at: usize| {
        filled
            .range(..=at)
            .next_back()
            .is_some_and(|(_, end)| at < *end)
    };

    let referenced = branches
        .iter()
        .filter(|branch| !in_fill(branch.site)) // themida's random fill decodes as branches too
        .map(|branch| branch.target);

    referenced.chain(entries.iter().copied()).collect()
}
