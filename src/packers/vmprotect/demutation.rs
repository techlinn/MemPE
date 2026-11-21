use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, FlowControl, Instruction, InstructionBlock,
    InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register, RflagsBits,
};

use super::imports;
use crate::unpack::Origin;
use crate::unpack::x86::StubExit;
use crate::unpack::x86::branches::{
    JUMP_REL32, MAX_CALL_PADDING, STATUS_RFLAGS, decode_at, direct_branches, is_immediate,
    is_near_immediate, near_jump, retarget, signed,
};

const GPR_COUNT: usize = 16;
const FAST_FAIL: u8 = 0x29; // int 29h, __fastfail
const UNTRACKED_FLAGS: u32 = RflagsBits::DF | RflagsBits::IF;
const MAX_INSNS: usize = 4_000;
pub(super) const MIN_REAL_INSNS: usize = 4;
pub(super) const MAX_TARGETS: usize = 50_000;
const ALL_BYTES: u8 = 0xFF;

const STACK_WINDOW: i64 = 128;
const WHOLE_STACK: u128 = u128::MAX;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Live {
    regs: [u8; GPR_COUNT], // one bit per live byte
    flags: u32,
    stack: u128, // live bytes below entry sp
}

struct Effect {
    reads: [u8; GPR_COUNT],
    defs: [u8; GPR_COUNT],  // may write: decides kept
    kills: [u8; GPR_COUNT], // must write: ends liveness
    reads_flags: u32,
    writes_flags: u32,
    reads_stack: u128,
    defs_stack: u128,
    kills_stack: u128,
    keep: bool, // branch, unpinnable write, side effect
}

pub(super) struct Payload<'a> {
    range: Range<u64>,
    image: &'a [u8],
    origin: &'a Origin<'a>,
    bits: u32,
    exits: RefCell<HashMap<u64, StubExit>>,
    stubs: RefCell<HashMap<usize, bool>>,
}

impl<'a> Payload<'a> {
    pub(super) fn new(image: &'a [u8], origin: &'a Origin<'a>, bits: u32, start: usize) -> Self {
        let base = origin.base as u64;
        Self {
            range: base + start as u64..base + image.len() as u64,
            image,
            origin,
            bits,
            exits: RefCell::default(),
            stubs: RefCell::default(),
        }
    }

    // a stub returns past vmp's padding byte
    fn exit(&self, site: u64) -> StubExit {
        *self.exits.borrow_mut().entry(site).or_insert_with(|| {
            site.checked_sub(self.origin.base as u64)
                .and_then(|at| usize::try_from(at).ok())
                .map_or(StubExit::Unknown, |at| {
                    imports::site_exit(self.image, self.origin, self.bits, at)
                })
        })
    }

    fn is_import_stub(&self, site: usize) -> bool {
        *self
            .stubs
            .borrow_mut()
            .entry(site)
            .or_insert_with(|| imports::is_stub(self.image, self.origin, self.bits, site))
    }

    pub(super) fn resume_after(&self, insn: &Instruction) -> Option<u64> {
        match self.calls_in(insn).then(|| self.exit(insn.ip())) {
            Some(StubExit::Returns(back)) => Some(back),
            _ => None,
        }
    }

    fn contains(&self, address: u64) -> bool {
        self.range.contains(&address)
    }

    fn calls_in(&self, insn: &Instruction) -> bool {
        insn.flow_control() == FlowControl::Call
            && is_near_immediate(insn)
            && self.contains(insn.near_branch_target())
    }
}

struct Cleaned {
    insns: Vec<Instruction>, // flow order, branches retargeted
    complete: bool,          // false: partly undecodable
}

fn clean(image: &[u8], base: u64, bits: u32, entry: u64, payload: &Payload<'_>) -> Cleaned {
    let insns = decode(image, base, bits, entry, payload);
    let succ = successors(&insns, payload);

    let offsets = stack_offsets(&insns, &succ, entry, bits, payload);

    let mut factory = InstructionInfoFactory::new();
    let effects: BTreeMap<u64, Effect> = insns
        .iter()
        .map(|(&at, insn)| {
            let delta = offsets
                .as_ref()
                .and_then(|at_offset| at_offset.get(&at).copied());
            (at, effect(insn, &mut factory, bits, delta))
        })
        .collect();

    let live_in = liveness(&insns, &effects, &succ);
    let live: BTreeSet<u64> = insns
        .keys()
        .copied()
        .filter(|&at| kept(&effects[&at], &exit_state(at, &insns, &succ, &live_in)))
        .collect();

    layout(&insns, &live, entry, bits, payload)
}

fn is_relay(insn: &Instruction, payload: &Payload<'_>) -> bool {
    insn.flow_control() == FlowControl::UnconditionalBranch
        && is_near_immediate(insn)
        && payload.contains(insn.near_branch_target()) // leaving the payload: a tail call
}

fn layout(
    insns: &BTreeMap<u64, Instruction>,
    live: &BTreeSet<u64>,
    entry: u64,
    bits: u32,
    payload: &Payload<'_>,
) -> Cleaned {
    let land = |mut at: u64| {
        for _ in 0..MAX_INSNS {
            match insns.get(&at) {
                Some(insn) if is_relay(insn, payload) => at = insn.near_branch_target(),
                Some(insn) if !live.contains(&at) && !leaves_payload(insn, payload) => {
                    at = insn.next_ip()
                }
                _ => break,
            }
        }
        at
    };

    let mut out = Vec::new();
    let mut placed = BTreeSet::new();
    let mut complete = true;
    let mut work = vec![entry]; // chunks joined by relays

    while let Some(start) = work.pop() {
        let mut at = land(start);
        let mut falls_through = false;
        loop {
            let Some(&original) = insns.get(&at) else {
                complete = false;
                break;
            };
            if placed.contains(&at) {
                if falls_through {
                    match jump(at, bits, out.len()) {
                        Some(joined) => out.push(joined),
                        None => complete = false,
                    }
                }
                break;
            }
            falls_through = true;

            let mut insn = original;
            placed.insert(at);
            if insn.flow_control() == FlowControl::ConditionalBranch && is_near_immediate(&insn) {
                let target = land(insn.near_branch_target());
                retarget(&mut insn, target);
                work.push(target);
            }
            out.push(insn);

            match insn.flow_control() {
                FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch => break,
                _ if payload.calls_in(&insn) => {
                    let back = match payload.exit(insn.ip()) {
                        StubExit::Returns(back) => back,
                        StubExit::TailJumps => break,
                        StubExit::Unknown => {
                            complete = false;
                            break;
                        }
                    };
                    let Some(padding) = back
                        .checked_sub(insn.next_ip())
                        .filter(|padding| *padding <= MAX_CALL_PADDING)
                        .map(|padding| padding.max(1))
                    // room for a call through an import slot
                    else {
                        complete = false;
                        break;
                    };

                    for _ in 0..padding {
                        out.push(Instruction::with(Code::Nopd));
                    }
                    at = land(back);
                }
                _ => at = land(insn.next_ip()),
            }
        }
    }

    Cleaned {
        insns: out,
        complete,
    }
}

fn jump(target: u64, bits: u32, index: usize) -> Option<Instruction> {
    let mut insn = near_jump(bits, target)?;
    insn.set_ip(u64::MAX - index as u64); // unique ip for the encoder
    Some(insn)
}

fn jump_targets(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    payload: &Payload<'_>,
) -> BTreeMap<usize, usize> {
    let mut targets = BTreeMap::new();
    for branch in direct_branches(image, base, bits, code, &|insn| payload.resume_after(insn)) {
        let rel32 = image.get(branch.site) == Some(&JUMP_REL32);
        if !branch.call && rel32 && payload.contains(base + branch.target as u64) {
            targets.entry(branch.target).or_insert(branch.site);
        }
    }
    targets
}

fn cleanable(cleaned: &Cleaned) -> bool {
    cleaned.complete
        && real_insns(&cleaned.insns) >= MIN_REAL_INSNS
        && !has_indirect_branch(cleaned)
}

fn has_indirect_branch(cleaned: &Cleaned) -> bool {
    cleaned
        .insns
        .iter()
        .any(|insn| insn.flow_control() == FlowControl::IndirectBranch)
}

#[derive(Default)]
pub(super) struct Relocated {
    pub(super) code: Vec<u8>, // new section; vmp reuses emptied space
    pub(super) moved: Vec<Moved>,
    pub(super) rejected: usize, // jumps into the payload that did not clean
    pub(super) unencodable: usize, // cleaned, but the encoder refused them
    pub(super) truncated: bool, // more targets than MAX_TARGETS
}

pub(super) struct Moved {
    pub(super) site: usize,
    pub(super) entry: u64,
}

pub(super) fn reencode(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    payload: &Payload<'_>,
    at: u64,
) -> Relocated {
    let targets = jump_targets(image, base, bits, code, payload);
    let mut relocated = Relocated {
        truncated: targets.len() > MAX_TARGETS,
        ..Relocated::default()
    };

    for (target, site) in targets.into_iter().take(MAX_TARGETS) {
        if payload.is_import_stub(site) {
            continue;
        }

        let cleaned = clean(image, base, bits, base + target as u64, payload);
        if !cleanable(&cleaned) {
            relocated.rejected += 1;
            continue;
        }

        let entry = at + relocated.code.len() as u64;
        let block = InstructionBlock::new(&cleaned.insns, entry);
        let Ok(encoded) = BlockEncoder::encode(bits, block, BlockEncoderOptions::NONE) else {
            relocated.unencodable += 1;
            continue;
        };
        relocated.code.extend(encoded.code_buffer);
        relocated.moved.push(Moved { site, entry });
    }
    relocated
}

fn leaves_payload(insn: &Instruction, payload: &Payload<'_>) -> bool {
    insn.flow_control() == FlowControl::UnconditionalBranch
        && is_near_immediate(insn)
        && !payload.contains(insn.near_branch_target())
}

fn real_insns(insns: &[Instruction]) -> usize {
    insns
        .iter()
        .filter(|insn| insn.flow_control() == FlowControl::Next)
        .count()
}

fn decode(
    image: &[u8],
    base: u64,
    bits: u32,
    entry: u64,
    payload: &Payload<'_>,
) -> BTreeMap<u64, Instruction> {
    let mut insns = BTreeMap::new();
    let mut work = vec![entry];
    while let Some(at) = work.pop() {
        if insns.contains_key(&at) {
            continue;
        }
        let Some(insn) = decode_at(image, base, bits, at) else {
            continue;
        };

        let next = edges(&insn, payload);
        insns.insert(at, insn);
        work.extend(next);
        if insns.len() > MAX_INSNS {
            break;
        }
    }
    insns
}

fn edges(insn: &Instruction, payload: &Payload<'_>) -> Vec<u64> {
    match insn.flow_control() {
        FlowControl::Return | FlowControl::IndirectBranch => Vec::new(),
        FlowControl::Interrupt | FlowControl::Exception
            if matches!(insn.mnemonic(), Mnemonic::Int3 | Mnemonic::Ud2)
                || (insn.mnemonic() == Mnemonic::Int && insn.immediate8() == FAST_FAIL) =>
        {
            Vec::new()
        }
        FlowControl::UnconditionalBranch if is_relay(insn, payload) => {
            vec![insn.near_branch_target()]
        }
        FlowControl::Call if payload.calls_in(insn) => {
            payload.resume_after(insn).into_iter().collect()
        }
        FlowControl::UnconditionalBranch => Vec::new(),
        FlowControl::ConditionalBranch if is_near_immediate(insn) => {
            vec![insn.next_ip(), insn.near_branch_target()]
        }
        _ => vec![insn.next_ip()],
    }
}

fn successors(
    insns: &BTreeMap<u64, Instruction>,
    payload: &Payload<'_>,
) -> BTreeMap<u64, Vec<u64>> {
    insns
        .iter()
        .map(|(&at, insn)| {
            let next = edges(insn, payload)
                .into_iter()
                .filter(|t| insns.contains_key(t))
                .collect();
            (at, next)
        })
        .collect()
}

fn pushes_or_pops(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Push
            | Mnemonic::Pushf
            | Mnemonic::Pushfd
            | Mnemonic::Pushfq
            | Mnemonic::Pop
            | Mnemonic::Popf
            | Mnemonic::Popfd
            | Mnemonic::Popfq
    )
}

fn step_stack(insn: &Instruction, bits: u32, into_stub: bool) -> Option<i64> {
    let into_rsp =
        insn.op0_kind() == OpKind::Register && insn.op0_register().full_register() == Register::RSP;
    let calls = matches!(
        insn.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    );
    if into_stub || (calls && bits == 32) {
        return None; // a stub may take a pushed slot, a 32-bit callee its arguments
    }

    match insn.mnemonic() {
        Mnemonic::Leave
        | Mnemonic::Enter
        | Mnemonic::Pusha
        | Mnemonic::Pushad
        | Mnemonic::Popa
        | Mnemonic::Popad => return None,
        Mnemonic::Pop if into_rsp => return None,
        mnemonic if pushes_or_pops(mnemonic) => {
            return Some(i64::from(insn.stack_pointer_increment()));
        }
        Mnemonic::Lea if insn.memory_base().full_register() == Register::RSP => {
            let simple = insn.memory_index() == Register::None;
            return match into_rsp && simple {
                true => Some(signed(insn.memory_displacement64(), bits)),
                false => None,
            };
        }
        _ => {}
    }

    let as_value = (0..insn.op_count()).any(|index| {
        insn.op_kind(index) == OpKind::Register
            && insn.op_register(index).full_register() == Register::RSP
    });
    if !as_value {
        return Some(0);
    }

    let by = is_immediate(insn.op1_kind()).then(|| signed(insn.immediate(1), bits));

    match (insn.mnemonic(), into_rsp, by) {
        (Mnemonic::Sub, true, Some(amount)) => Some(-amount),
        (Mnemonic::Add, true, Some(amount)) => Some(amount),
        _ => None,
    }
}

fn stack_offsets(
    insns: &BTreeMap<u64, Instruction>,
    succ: &BTreeMap<u64, Vec<u64>>,
    entry: u64,
    bits: u32,
    payload: &Payload<'_>,
) -> Option<BTreeMap<u64, i64>> {
    let mut offset: BTreeMap<u64, i64> = BTreeMap::new();
    let mut work = vec![(entry, 0i64)];

    while let Some((at, delta)) = work.pop() {
        if let Some(&seen) = offset.get(&at) {
            if seen != delta {
                return None;
            }
            continue;
        }

        let insn = insns.get(&at)?;
        offset.insert(at, delta);
        let moved = step_stack(insn, bits, payload.calls_in(insn))?;
        let next = delta.checked_add(moved)?;

        for target in succ.get(&at)?.iter() {
            work.push((*target, next));
        }
    }

    Some(offset)
}

#[derive(Clone, Copy)]
enum Slot {
    Scratch(u128), // window bytes below entry sp
    Elsewhere,     // caller frame or deeper
    Unknown,
}

fn slot(memory: &iced_x86::UsedMemory, insn: &Instruction, delta: i64, bits: u32) -> Slot {
    let mnemonic = insn.mnemonic();
    if pushes_or_pops(mnemonic)
        || matches!(mnemonic, Mnemonic::Call | Mnemonic::Enter | Mnemonic::Leave)
    {
        return Slot::Unknown;
    }
    if memory.base().full_register() != Register::RSP || memory.index() != Register::None {
        return Slot::Unknown;
    }

    let Ok(size) = i64::try_from(memory.memory_size().size()) else {
        return Slot::Unknown;
    };
    let Some(start) = delta.checked_add(signed(memory.displacement(), bits)) else {
        return Slot::Unknown;
    };
    let Some(end) = start.checked_add(size.max(1)) else {
        return Slot::Unknown;
    };

    if start >= 0 || end <= -STACK_WINDOW {
        return Slot::Elsewhere;
    }
    if start < -STACK_WINDOW || end > 0 || !(1..=16).contains(&size) {
        return Slot::Unknown;
    }

    let Ok(first) = u32::try_from(start + STACK_WINDOW) else {
        return Slot::Unknown;
    };

    let span = (1u128 << size) - 1;
    Slot::Scratch(span << first)
}

fn effect(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    bits: u32,
    delta: Option<i64>,
) -> Effect {
    let info = factory.info(insn);
    let mut reads = [0u8; GPR_COUNT];
    let mut defs = [0u8; GPR_COUNT];
    let mut kills = [0u8; GPR_COUNT];
    let mut keep = false;

    for used in info.used_registers() {
        let register = used.register();
        let Some((index, bytes)) = gpr_bytes(register) else {
            if writes_access(used.access()) {
                keep = true; // xmm, segments: not modelled
            }
            continue;
        };
        if reads_access(used.access()) {
            reads[index] |= read_mask(register);
        }
        match used.access() {
            OpAccess::Write | OpAccess::ReadWrite => {
                defs[index] |= bytes;
                kills[index] |= bytes;
            }
            OpAccess::CondWrite | OpAccess::ReadCondWrite => {
                defs[index] |= bytes;
                reads[index] |= read_mask(register); // cmov, bsf: old value may survive
            }
            _ => {}
        }
    }

    let calls = matches!(
        insn.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    );
    if calls {
        reads = [ALL_BYTES; GPR_COUNT]; // ltcg callees take args in any register
    }

    let mut reads_stack = 0u128;
    let mut defs_stack = 0u128;
    let mut kills_stack = 0u128;
    let mut loose_write = false;
    for memory in info.used_memory() {
        let found = delta.map_or(Slot::Unknown, |delta| slot(memory, insn, delta, bits));
        if reads_access(memory.access()) {
            match found {
                Slot::Scratch(mask) => reads_stack |= mask,
                Slot::Elsewhere => {}
                Slot::Unknown => reads_stack = WHOLE_STACK,
            }
        }
        if writes_access(memory.access()) {
            match found {
                Slot::Scratch(mask) => {
                    defs_stack |= mask;
                    if matches!(memory.access(), OpAccess::Write | OpAccess::ReadWrite) {
                        kills_stack |= mask;
                    }
                }
                _ => loose_write = true, // visible to caller, or unplaceable
            }
        }
    }

    if calls {
        reads_stack = WHOLE_STACK;
    }

    keep |= loose_write || side_effect(insn);

    Effect {
        reads,
        defs,
        kills,
        reads_flags: insn.rflags_read() & STATUS_RFLAGS,
        writes_flags: insn.rflags_modified() & STATUS_RFLAGS,
        reads_stack,
        defs_stack,
        kills_stack,
        keep,
    }
}

fn reads_access(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::ReadWrite | OpAccess::CondRead | OpAccess::ReadCondWrite
    )
}

fn writes_access(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn side_effect(insn: &Instruction) -> bool {
    match insn.flow_control() {
        FlowControl::Call
        | FlowControl::IndirectCall
        | FlowControl::Return
        | FlowControl::IndirectBranch
        | FlowControl::ConditionalBranch
        | FlowControl::Interrupt
        | FlowControl::Exception
        | FlowControl::XbeginXabortXend => true,
        FlowControl::Next | FlowControl::UnconditionalBranch
            if matches!(insn.mnemonic(), Mnemonic::Xchg | Mnemonic::Xadd) =>
        {
            insn.has_lock_prefix()
                || (0..insn.op_count()).any(|index| insn.op_kind(index) == OpKind::Memory)
        }
        FlowControl::Next | FlowControl::UnconditionalBranch => {
            pushes_or_pops(insn.mnemonic())
                || matches!(
                    insn.mnemonic(),
                    Mnemonic::In
                        | Mnemonic::Out
                        | Mnemonic::Cpuid
                        | Mnemonic::Rdtsc
                        | Mnemonic::Rdtscp
                        | Mnemonic::Syscall
                        | Mnemonic::Sysenter
                        | Mnemonic::Hlt
                        | Mnemonic::Fldcw
                        | Mnemonic::Ldmxcsr
                        | Mnemonic::Fninit
                        | Mnemonic::Fnclex
                        | Mnemonic::Emms
                        | Mnemonic::Fxrstor
                        | Mnemonic::Xrstor
                        | Mnemonic::Fldenv
                        | Mnemonic::Frstor
                )
                || insn.rflags_modified() & UNTRACKED_FLAGS != 0
        } // df and if outlive the function
    }
}

fn gpr_bytes(register: Register) -> Option<(usize, u8)> {
    if !register.is_gpr() {
        return None;
    }

    let mask = match register.size() {
        4 => ALL_BYTES, // 32-bit write defines all eight bytes
        _ => read_mask(register),
    };
    Some((register.full_register().number(), mask))
}

fn read_mask(register: Register) -> u8 {
    if is_high8(register) {
        return 0b10;
    }
    match register.size() {
        1 => 0b1,
        2 => 0b11,
        4 => 0b1111,
        _ => ALL_BYTES,
    }
}

fn is_high8(register: Register) -> bool {
    matches!(
        register,
        Register::AH | Register::BH | Register::CH | Register::DH
    )
}

fn exit_live(insn: &Instruction) -> Live {
    let stack = match insn.flow_control() {
        FlowControl::Return => 0, // frame below entry sp dead at ret
        _ => WHOLE_STACK,
    };

    Live {
        regs: [ALL_BYTES; GPR_COUNT], // any exit may read anything: no calling convention assumed
        flags: STATUS_RFLAGS,
        stack,
    }
}

fn exit_state(
    at: u64,
    insns: &BTreeMap<u64, Instruction>,
    succ: &BTreeMap<u64, Vec<u64>>,
    live_in: &BTreeMap<u64, Live>,
) -> Live {
    let targets = &succ[&at];
    let mut state = Live::default();
    if targets.is_empty() {
        state = exit_live(&insns[&at]);
    }
    for target in targets {
        let incoming = live_in[target];
        for index in 0..GPR_COUNT {
            state.regs[index] |= incoming.regs[index];
        }
        state.flags |= incoming.flags;
        state.stack |= incoming.stack;
    }
    state
}

fn kept(effect: &Effect, out: &Live) -> bool {
    if effect.keep {
        return true;
    }
    let defs_live = (0..GPR_COUNT).any(|index| effect.defs[index] & out.regs[index] != 0);
    defs_live || effect.writes_flags & out.flags != 0 || effect.defs_stack & out.stack != 0
}

fn liveness(
    insns: &BTreeMap<u64, Instruction>,
    effects: &BTreeMap<u64, Effect>,
    succ: &BTreeMap<u64, Vec<u64>>,
) -> BTreeMap<u64, Live> {
    let mut live_in: BTreeMap<u64, Live> = insns.keys().map(|&at| (at, Live::default())).collect();

    loop {
        let mut changed = false;
        for (&at, _) in insns.iter().rev() {
            let out = exit_state(at, insns, succ, &live_in);
            let effect = &effects[&at];

            let mut state = out;
            if kept(effect, &out) {
                for index in 0..GPR_COUNT {
                    state.regs[index] &= !effect.kills[index];
                    state.regs[index] |= effect.reads[index];
                }
                state.flags &= !effect.writes_flags;
                state.flags |= effect.reads_flags;
                state.stack &= !effect.kills_stack;
                state.stack |= effect.reads_stack;
            }

            if state != live_in[&at] {
                live_in.insert(at, state);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    live_in
}
