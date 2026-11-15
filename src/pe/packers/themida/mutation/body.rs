use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use crate::pe::packers::branches::is_near_immediate;

const MAX_BLOCKS: usize = 20_000;
const MAX_BLOCK_LEN: usize = 4_096;
const WINDOW: usize = 16;

pub(super) enum End {
    Next(u64),
    Branch(Instruction),
    Exit(Instruction), // back to the program: a jump past the region, a return, or a jump through memory
}

pub(super) struct Block {
    pub(super) code: Vec<Instruction>,
    pub(super) end: End,
}

pub(super) struct Body {
    pub(super) entry: u64,
    pub(super) blocks: BTreeMap<u64, Block>,
}

impl Body {
    pub(super) fn loop_heads(&self) -> BTreeSet<u64> {
        self.blocks
            .iter()
            .filter_map(|(at, block)| match &block.end {
                End::Branch(branch) => Some((*at, branch.near_branch_target())),
                _ => None,
            })
            .filter(|(branching, target)| self.reaches(*target, *branching)) // a branch back to code that leads to it again
            .map(|(_, target)| target)
            .collect()
    }

    pub(super) fn fall_throughs(&self) -> BTreeSet<u64> {
        self.blocks
            .values()
            .filter_map(|block| match &block.end {
                End::Branch(branch) => Some(branch.next_ip()),
                _ => None,
            })
            .collect() // themida follows each conditional jump with a bare jump on to the code after it
    }

    fn reaches(&self, from: u64, to: u64) -> bool {
        let mut seen = BTreeSet::new();
        let mut work = vec![from];
        while let Some(at) = work.pop() {
            if at == to {
                return true;
            }
            if !seen.insert(at) {
                continue;
            }

            match self.blocks.get(&at).map(|block| &block.end) {
                Some(End::Next(next)) => work.push(*next),
                Some(End::Branch(branch)) => {
                    work.extend([branch.next_ip(), branch.near_branch_target()])
                }
                _ => {}
            }
        }
        false
    }
}

pub(super) fn decode(
    image: &[u8],
    base: u64,
    bits: u32,
    entry: u64,
    packer: &Range<u64>,
) -> Option<Body> {
    let mut blocks = BTreeMap::new();
    let mut work = vec![entry];

    while let Some(start) = work.pop() {
        if blocks.contains_key(&start) {
            continue;
        }
        if blocks.len() >= MAX_BLOCKS {
            return None;
        }

        let block = decode_block(image, base, bits, start, packer)?;
        match &block.end {
            End::Next(next) => work.push(*next),
            End::Branch(branch) => {
                work.push(branch.next_ip());
                if packer.contains(&branch.near_branch_target()) {
                    work.push(branch.near_branch_target());
                }
            }
            End::Exit(_) => {}
        }
        blocks.insert(start, block);
    }

    Some(Body { entry, blocks })
}

fn decode_block(
    image: &[u8],
    base: u64,
    bits: u32,
    start: u64,
    packer: &Range<u64>,
) -> Option<Block> {
    let mut code = Vec::new();
    let mut at = start;

    for _ in 0..MAX_BLOCK_LEN {
        let insn = decode_at(image, base, bits, at)?;
        let end = match insn.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => None,
            FlowControl::UnconditionalBranch if is_near_immediate(&insn) => {
                let target = insn.near_branch_target();
                Some(match packer.contains(&target) {
                    true => End::Next(target),
                    false => End::Exit(insn),
                })
            }
            FlowControl::ConditionalBranch if is_near_immediate(&insn) => Some(End::Branch(insn)),
            FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::UnconditionalBranch => Some(End::Exit(insn)),
            _ => return None,
        };

        match end {
            Some(end) => return Some(Block { code, end }),
            None => {
                code.push(insn);
                at = insn.next_ip();
            }
        }
    }

    None
}

fn decode_at(image: &[u8], base: u64, bits: u32, at: u64) -> Option<Instruction> {
    let offset = usize::try_from(at.checked_sub(base)?).ok()?;
    let window = image.get(offset..offset.saturating_add(WINDOW).min(image.len()))?;
    let insn = Decoder::with_ip(bits, window, at, DecoderOptions::NONE).decode();

    (!insn.is_invalid()).then_some(insn)
}
