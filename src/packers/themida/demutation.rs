use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Instruction, Mnemonic};

use super::mutated_function::{Body, End};
use super::original_instruction::{Simplified, distinct, encoded_length, simplify};
use super::reassembly::{
    Habits, Laid, Piece, Style, encode, lay_out, nops, pad_opening_push, retarget_all,
};
use super::{FUNCTION_ALIGNMENT, Functions, Packed, aligned_or_after_int3, jumps_into};
use crate::unpack::counted;
use crate::unpack::tables::{SectionKind, append, next_section_rva};
use crate::unpack::x86::branches::{
    Branch, REL32_LEN, STATUS_RFLAGS, is_near_immediate, retarget, set_rel32_target,
};
use crate::unpack::x86::opcodes::{INT3, RET};
use crate::unpack::x86::{Agreement, Probe, same_behaviour};
use crate::unpack::{PackerReport, Part};

const MAX_REGIONS: usize = 4_096;
const MAX_REGION: usize = 0x1_0000;
const MAX_STRETCH: usize = 64; // instructions themida spends on one of the program's
const UNMUTATED_SECTION: &[u8; 8] = b".unmut\0\0";

pub(super) struct Rewrite {
    site: usize,
    entry: u64,
    limit: usize,
    exact: bool, // limit is where the mutated code jumps back to
    code: Vec<Instruction>,
    padding: BTreeSet<u64>,
    chunks: usize,
    unproven: usize,
    flags_dead: usize,
}

pub(super) struct UnmutatedRegions {
    rewrites: Vec<Rewrite>,
    trampolines: BTreeSet<usize>,
    unexamined: usize,
}

impl UnmutatedRegions {
    pub(super) fn leads_to_mutated_code(&self, site: usize) -> bool {
        self.trampolines.contains(&site)
    }
}

pub(super) fn analyse(restored: &[u8], packed: &Packed<'_>) -> UnmutatedRegions {
    let runner = packed.runner();
    let functions = Functions::read(restored, packed.model());
    let style = Style::of(
        restored,
        runner.base,
        runner.bits,
        &packed.code,
        functions.starts(),
    );
    let habits = Habits::of(restored, runner.base, runner.bits, &packed.code);
    let mut regions = found(restored, packed, &functions, style, &habits);

    let moved: BTreeMap<u64, u64> = regions
        .rewrites
        .iter()
        .map(|rewrite| (rewrite.entry, runner.base + rewrite.site as u64))
        .collect();
    for insn in regions
        .rewrites
        .iter_mut()
        .flat_map(|rewrite| rewrite.code.iter_mut())
    {
        let start = is_near_immediate(insn)
            .then(|| moved.get(&insn.near_branch_target()))
            .flatten();
        if let Some(start) = start {
            retarget(insn, *start);
        }
    }

    let mut scratch = restored.to_vec();
    regions
        .rewrites
        .retain(|rewrite| verified(restored, &mut scratch, packed, rewrite));
    regions
}

pub(super) fn apply(
    restored: &mut Vec<u8>,
    packed: &Packed<'_>,
    unmutated: &UnmutatedRegions,
    report: &mut PackerReport,
) {
    let base = packed.origin.base as u64;
    let bits = packed.kind().bits();
    let mut placed = Vec::new();
    let mut moved = Vec::new();

    for rewrite in &unmutated.rewrites {
        let written = in_place(rewrite, bits, base).and_then(|bytes| {
            let end = rewrite.site.checked_add(bytes.len())?;
            restored.get_mut(rewrite.site..end)?.copy_from_slice(&bytes);
            Some(())
        });
        match written {
            Some(()) => placed.push(rewrite),
            None => moved.push(rewrite),
        }
    }
    placed.extend(place_elsewhere(restored, packed, &moved));

    if unmutated.unexamined > 0 {
        report.notes.push(format!(
            "{} into themida's sections were not examined: only the first {MAX_REGIONS} are",
            counted(unmutated.unexamined, "jump", "jumps"),
        ));
    }

    let left = unmutated.trampolines.len().saturating_sub(placed.len());
    if left > 0 {
        report.notes.push(format!(
            "{} could not be rebuilt and proven to run the same, and still jump into themida's sections",
            counted(left, "mutated region", "mutated regions"),
        ));
    }
    if placed.is_empty() {
        if left > 0 {
            report.failed_with(Part::MutatedCode, "no region could be rebuilt and proven");
        }
        return;
    }

    let chunks: usize = placed.iter().map(|rewrite| rewrite.chunks).sum();
    let unproven: usize = placed.iter().map(|rewrite| rewrite.unproven).sum();
    let flags_dead: usize = placed.iter().map(|rewrite| rewrite.flags_dead).sum();
    if flags_dead > 0 {
        report.notes.push(format!(
            "{flags_dead} chunks matched on registers and memory only: themida's junk leaves other flags, which it does only where the program reads none, so each is the instruction form this program's own code uses most among those that run the same"
        ));
    }
    report.inferred(
        Part::MutatedCode,
        "rebuilt code that ran the same as themida's on test inputs",
    );
    if left > 0 {
        report.partly_failed(Part::MutatedCode, "regions that could not be proven");
    }
    report.notes.push(format!(
        "{} rebuilt from {chunks} chunks of themida's mutated code; {unproven} of the chunks could not be proven to be one instruction and keep themida's own; where blocks sit after a jump or return is inferred",
        counted(placed.len(), "mutated region", "mutated regions"),
    ));
}

fn found(
    restored: &[u8],
    packed: &Packed<'_>,
    functions: &Functions,
    style: Style,
    habits: &Habits,
) -> UnmutatedRegions {
    let runner = packed.runner();
    let probe = Probe {
        image: runner.image,
        base: runner.base,
        bits: runner.bits,
    };
    let tail = packed.va(&packed.tail());
    let branches = packed.branches(restored);
    let entries = entries(restored, packed, &branches);
    let starts = referenced_starts(restored, &branches, &entries);

    let mut regions = UnmutatedRegions {
        rewrites: Vec::new(),
        trampolines: BTreeSet::new(),
        unexamined: entries.len().saturating_sub(MAX_REGIONS),
    };
    for site in entries.into_iter().take(MAX_REGIONS) {
        let at = runner.base + site as u64;
        let Some(entry) = runner.trampoline_target(at, &tail) else {
            continue; // none for a virtual machine
        };
        regions.trampolines.insert(site);

        let body =
            super::mutated_function::decode(runner.image, runner.base, runner.bits, entry, &tail);
        let rewrite = body.and_then(|body| {
            let extent = extent(packed, &body, site, &starts, functions);
            rewrite(&probe, &body, site, extent, style, habits)
        });
        let Some(mut rewrite) = rewrite else {
            continue;
        };

        let opens_function = functions
            .containing(site)
            .is_some_and(|function| function.start == site);
        if opens_function {
            pad_opening_push(&mut rewrite.code, style, runner.bits);
        }
        regions.rewrites.push(rewrite);
    }

    regions
}

pub(super) fn entries(
    restored: &[u8],
    packed: &Packed<'_>,
    branches: &[Branch],
) -> BTreeSet<usize> {
    let tail = packed.tail();
    let swept = branches
        .iter()
        .filter(|branch| !branch.call && tail.contains(&branch.target))
        .map(|branch| branch.site);

    let starts_with_jump =
        |at: &usize| aligned_or_after_int3(restored, *at) && jumps_into(restored, *at, &tail); // sweep can skip an entry jmp
    let starting = packed
        .code
        .iter()
        .cloned()
        .flatten()
        .filter(starts_with_jump);

    swept.chain(starting).collect()
}

fn rewrite(
    probe: &Probe<'_>,
    body: &Body,
    site: usize,
    extent: Extent,
    style: Style,
    habits: &Habits,
) -> Option<Rewrite> {
    let loop_heads = body.loop_heads();
    let fall_throughs = body.fall_throughs();
    let mut pieces = BTreeMap::new();
    let mut choices = Vec::new();
    let mut unproven = 0;
    let mut flags_dead = 0;
    for (start, block) in &body.blocks {
        let simplified = simplify_block(probe, &block.code, style, habits).map(|clean| {
            flags_dead += usize::from(clean.flags_dead);
            choices.extend(clean.choices.into_iter().map(|choice| (*start, choice)));
            clean.code
        });
        let piece = match (simplified, &block.end) {
            (Some(clean), End::Next(next)) if clean.is_empty() => {
                match (loop_heads.contains(next), fall_throughs.contains(start)) {
                    (true, _) if !block.code.is_empty() => Piece::Padding,
                    (_, false) => Piece::Jump(*next),
                    (_, true) => Piece::Code(clean),
                }
            }
            (Some(clean), _) => Piece::Code(clean),
            (None, _) => {
                unproven += 1;
                Piece::Code(block.code.clone())
            }
        };
        pieces.insert(*start, piece);
    }

    let choices: Vec<(u64, usize, Vec<Instruction>)> = choices
        .into_iter()
        .map(|(start, choice)| {
            let mut equals = choice.equals;
            if flags_set_after(body, &pieces, start, choice.at + 1) {
                equals.extend(choice.flag_free);
            }
            (start, choice.at, distinct(equals))
        })
        .filter(|(_, _, equals)| equals.len() > 1)
        .collect();

    let laid = lay_out(body, &pieces, probe.bits)?;
    let mut rewrite = Rewrite {
        site,
        entry: body.entry,
        limit: extent.end,
        exact: extent.exact,
        code: laid.code,
        padding: laid.padding,
        chunks: body.blocks.len(),
        unproven,
        flags_dead,
    };
    if let Some(fitted) = fitted(&rewrite, extent, body, pieces, &choices, probe) {
        rewrite.code = fitted.code;
        rewrite.padding = fitted.padding;
    }
    Some(rewrite)
}

// where the compiler's code is known to end, its instructions filled the room exactly: of the
// forms that run the same, the ones whose lengths fill it are the ones it wrote
fn fitted(
    rewrite: &Rewrite,
    extent: Extent,
    body: &Body,
    mut pieces: BTreeMap<u64, Piece>,
    choices: &[(u64, usize, Vec<Instruction>)],
    probe: &Probe<'_>,
) -> Option<Laid> {
    let (bytes, continues) = trimmed(rewrite, probe.bits, probe.base)?;
    let code_end = match continues {
        true => rewrite.limit,
        false => extent.code_end?,
    };
    let room = code_end.checked_sub(rewrite.site)?;
    if bytes.len() == room || choices.is_empty() {
        return None;
    }

    let length = |insn: &Instruction| isize::try_from(encoded_length(insn, probe.bits)).ok();
    let mut reachable: BTreeMap<isize, (usize, Vec<usize>)> =
        BTreeMap::from([(0, (0, Vec::new()))]);
    for (_, _, equals) in choices {
        let current = length(equals.first()?)?;
        let mut next: BTreeMap<isize, (usize, Vec<usize>)> = BTreeMap::new();
        for (grown, (changes, picks)) in &reachable {
            for (pick, equal) in equals.iter().enumerate() {
                let delta = length(equal)? - current;
                let entry = (
                    changes + usize::from(pick > 0),
                    [&picks[..], &[pick]].concat(),
                );
                let best = next.entry(grown + delta).or_insert_with(|| entry.clone());
                if entry.0 < best.0 {
                    *best = entry; // the fewest departures from the program's habits
                }
            }
        }
        reachable = next;
    }

    let short = isize::try_from(room).ok()? - isize::try_from(bytes.len()).ok()?;
    let (_, picks) = reachable.get(&short)?;
    for ((start, at, equals), pick) in choices.iter().zip(picks) {
        if let Some(Piece::Code(code)) = pieces.get_mut(start) {
            *code.get_mut(*at)? = *equals.get(*pick)?;
        }
    }

    let laid = lay_out(body, &pieces, probe.bits)?;
    let fits = Rewrite {
        code: laid.code.clone(),
        padding: laid.padding.clone(),
        ..*rewrite
    };
    let (bytes, _) = trimmed(&fits, probe.bits, probe.base)?;
    (bytes.len() == room).then_some(laid) // branch sizes moved with the code
}

struct Choice {
    at: usize, // index in the block's code
    equals: Vec<Instruction>,
    flag_free: Vec<Instruction>, // equal but for flags
}

struct CleanBlock {
    code: Vec<Instruction>,
    flags_dead: bool,
    choices: Vec<Choice>,
}

fn simplify_block(
    probe: &Probe<'_>,
    code: &[Instruction],
    style: Style,
    habits: &Habits,
) -> Option<CleanBlock> {
    let is_call = |insn: &Instruction| insn.is_call_near() || insn.is_call_near_indirect();
    let mut clean = Vec::new();
    let mut flags_dead = false;
    let mut choices = Vec::new();

    for piece in code.split_inclusive(is_call) {
        let (call, around) = match piece.split_last() {
            Some((last, rest)) if is_call(last) => (Some(*last), rest),
            _ => (None, piece),
        };

        for mut simplified in segmented(probe, around, habits)? {
            flags_dead |= simplified.flags_dead;
            simplified
                .code
                .iter_mut()
                .chain(&mut simplified.alternatives)
                .chain(&mut simplified.flag_free)
                .for_each(|insn| style.apply(insn)); // themida re-encodes the instructions it keeps
            if let [only] = simplified.code[..] {
                choices.push(Choice {
                    at: clean.len(),
                    equals: [vec![only], simplified.alternatives].concat(),
                    flag_free: simplified.flag_free,
                });
            }
            clean.extend(simplified.code);
        }
        clean.extend(call);
    }

    Some(CleanBlock {
        code: clean,
        flags_dead,
        choices,
    })
}

// whether every status flag is set again before any is read, from that instruction on through the
// rebuilt blocks; a call or return ends the question: no calling convention passes status flags
fn flags_set_after(body: &Body, pieces: &BTreeMap<u64, Piece>, start: u64, from: usize) -> bool {
    let mut block = start;
    let mut from = from;
    let mut seen = BTreeSet::new();

    while seen.insert(block) {
        let code = match pieces.get(&block) {
            Some(Piece::Code(code)) => code.get(from..).unwrap_or_default(),
            _ => &[],
        };
        for insn in code {
            if insn.rflags_read() & STATUS_RFLAGS != 0 {
                return false;
            }
            if insn.is_call_near() || insn.is_call_near_indirect() {
                return true;
            }
            if insn.rflags_modified() & STATUS_RFLAGS == STATUS_RFLAGS {
                return true;
            }
        }

        match body.blocks.get(&block).map(|block| &block.end) {
            Some(End::Next(next)) => {
                block = *next;
                from = 0;
            }
            Some(End::Exit(exit)) => return exit.mnemonic() == Mnemonic::Ret,
            _ => return false, // a conditional branch reads them; anything else is not followed
        }
    }
    false
}

#[derive(Default)]
struct Reached {
    cost: (usize, usize), // instructions, then chunks matched with dead flags
    from: usize,
    stretch: Simplified,
}

// themida can run several of the program's instructions through one block with no jump between
// them: the block is then cut into stretches that each run as one instruction, fewest first
fn segmented(probe: &Probe<'_>, code: &[Instruction], habits: &Habits) -> Option<Vec<Simplified>> {
    if let Some(whole) = simplify(probe, code, habits) {
        return Some(vec![whole]);
    }

    let mut best: Vec<Option<Reached>> = Vec::with_capacity(code.len() + 1);
    best.push(Some(Reached::default()));
    let settled = probe.settled(code);
    for end in 1..=code.len() {
        if end < code.len() && !settled[end - 1] {
            best.push(None); // themida's temporaries are still live here
            continue;
        }
        let mut found: Option<Reached> = None;
        for start in end.saturating_sub(MAX_STRETCH)..end {
            let Some(before) = best[start].as_ref().map(|reached| reached.cost) else {
                continue;
            };
            let Some(stretch) = simplify(probe, &code[start..end], habits) else {
                continue;
            };
            let cost = (
                before.0 + stretch.code.len(),
                before.1 + usize::from(stretch.flags_dead),
            );
            if found.as_ref().is_none_or(|known| cost < known.cost) {
                found = Some(Reached {
                    cost,
                    from: start,
                    stretch,
                });
            }
        }
        best.push(found);
    }

    let mut stretches = Vec::new();
    let mut end = code.len();
    while end > 0 {
        let reached = best.get_mut(end)?.take()?;
        stretches.push(reached.stretch);
        end = reached.from;
    }
    stretches.reverse();
    Some(stretches)
}

fn in_place(rewrite: &Rewrite, bits: u32, base: u64) -> Option<Vec<u8>> {
    let room = rewrite.limit.checked_sub(rewrite.site)?;
    let (mut bytes, continues) = trimmed(rewrite, bits, base)?;
    if bytes.len() > room {
        return None;
    }

    let rest = room - bytes.len();
    match (continues, rewrite.exact) {
        (true, _) => bytes.extend(nops(rest)),
        (false, true) => bytes.resize(room, INT3),
        (false, false) => {} // end not proven: what follows stays as it is
    }
    Some(bytes)
}

fn trimmed(rewrite: &Rewrite, bits: u32, base: u64) -> Option<(Vec<u8>, bool)> {
    let site = base + rewrite.site as u64;
    let end = base + rewrite.limit as u64;

    let mut code = rewrite.code.clone();
    let continues = rewrite.exact
        && code.last().is_some_and(|last| {
            last.mnemonic() == Mnemonic::Jmp
                && is_near_immediate(last)
                && last.near_branch_target() == end
        });
    if continues {
        let jump = code.pop()?; // the jump back to the end is dropped: the code runs into it
        retarget_all(&mut code, jump.ip(), end);
    }

    let bytes = encode(&code, &rewrite.padding, bits, site)?;
    Some((bytes, continues))
}

fn place_elsewhere<'a>(
    restored: &mut Vec<u8>,
    packed: &Packed<'_>,
    rewrites: &[&'a Rewrite],
) -> Vec<&'a Rewrite> {
    let model = packed.model();
    let base = packed.origin.base as u64;
    let bits = packed.kind().bits();
    let Some(start) = next_section_rva(restored, model) else {
        return Vec::new();
    };

    let mut section = Vec::new();
    let mut jumps = Vec::new();
    for rewrite in rewrites {
        let at = start + section.len();
        let Some(bytes) = encode(&rewrite.code, &rewrite.padding, bits, base + at as u64) else {
            continue;
        };
        section.extend_from_slice(&bytes);
        jumps.push((*rewrite, at));
    }
    if section.is_empty()
        || append(
            restored,
            model,
            UNMUTATED_SECTION,
            SectionKind::Code,
            &section,
        ) != Some(start)
    {
        return Vec::new();
    }

    jumps
        .into_iter()
        .filter(|(rewrite, at)| set_rel32_target(restored, rewrite.site, *at).is_some())
        .map(|(rewrite, _)| rewrite)
        .collect()
}

fn verified(restored: &[u8], patched: &mut [u8], packed: &Packed<'_>, rewrite: &Rewrite) -> bool {
    let base = packed.origin.base as u64;
    let bits = packed.kind().bits();
    let tail = packed.tail();
    let mut touched = Vec::with_capacity(3);
    touched.push(rewrite.site..rewrite.limit);

    let written = match in_place(rewrite, bits, base) {
        Some(bytes) => patched
            .get_mut(rewrite.site..rewrite.site + bytes.len())
            .map(|area| area.copy_from_slice(&bytes)),
        None => {
            let at = tail.start;
            encode(&rewrite.code, &rewrite.padding, bits, base + at as u64).and_then(|bytes| {
                touched.push(at..at + bytes.len());
                touched.push(rewrite.site..rewrite.site + REL32_LEN);
                patched
                    .get_mut(at..at + bytes.len())?
                    .copy_from_slice(&bytes);
                set_rel32_target(patched, rewrite.site, at)
            })
        }
    };

    let private = packed.va(&tail);
    let same = written.is_some()
        && same_behaviour(
            restored,
            patched,
            base,
            bits,
            base + rewrite.site as u64,
            &private,
            Agreement::Finished,
        );

    for range in touched {
        if let (Some(to), Some(from)) = (patched.get_mut(range.clone()), restored.get(range)) {
            to.copy_from_slice(from);
        }
    }
    same
}

#[derive(Clone, Copy)]
struct Extent {
    end: usize,
    exact: bool,
    code_end: Option<usize>, // where the compiler's code stopped: padding or the unwind table's end
}

fn extent(
    packed: &Packed<'_>,
    body: &Body,
    site: usize,
    starts: &BTreeSet<usize>,
    functions: &Functions,
) -> Extent {
    let base = packed.origin.base;
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

    let (bound, code_end) = region(packed.image.bytes(), site, starts, functions);
    match continuation {
        Some(end) if end <= bound => Extent {
            end,
            exact: true,
            code_end: None,
        },
        _ => Extent {
            end: bound,
            exact: false,
            code_end: code_end.filter(|_| continuation.is_none()),
        },
    }
}

// how far the code behind a jump into themida's sections can reach, and its code end if known
pub(super) fn region(
    image: &[u8],
    site: usize,
    starts: &BTreeSet<usize>,
    functions: &Functions,
) -> (usize, Option<usize>) {
    let function = functions.containing(site).map(|function| function.end);
    let next = starts.range(site + 1..).next().copied();
    let padding = function
        .is_none()
        .then(|| padding_after(image, site))
        .flatten(); // past the jmp lies themida's fill, read only when the unwind table gives no end
    let bound = [function, next, padding]
        .into_iter()
        .flatten()
        .fold(site + MAX_REGION, usize::min);

    let code_end = if [function, padding].contains(&Some(bound)) {
        Some(bound)
    } else if next == Some(bound) {
        Some(padded_from(image, site + REL32_LEN, bound)) // themida fills only the code, not the padding before the next function
    } else {
        None
    };
    (bound, code_end)
}

fn padded_from(image: &[u8], floor: usize, end: usize) -> usize {
    (floor..end)
        .rev()
        .take_while(|at| image.get(*at) == Some(&INT3))
        .last()
        .unwrap_or(end)
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
    run.iter().all(|byte| *byte == INT3) && (run.len() > 1 || after_return) // a lone 0xcc may be random fill
}

pub(super) fn referenced_starts(
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
        .filter(|branch| !in_fill(branch.site)) // random fill decodes as branches
        .map(|branch| branch.target);

    referenced.chain(entries.iter().copied()).collect()
}
