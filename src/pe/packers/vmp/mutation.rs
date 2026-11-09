use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register, RflagsBits,
};

const GPR_COUNT: usize = 16;
const RETURN_LIVE: [usize; 11] = [0, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]; // rax and rdx (edx eax) rsp and the callee saved ones x86 has no r12 to r15
const TRACKED_FLAGS: u32 = RflagsBits::CF
    | RflagsBits::PF
    | RflagsBits::AF
    | RflagsBits::ZF
    | RflagsBits::SF
    | RflagsBits::OF
    | RflagsBits::DF;
const MAX_INSNS: usize = 4_000; // a mutated function fits well under this and the cap bounds a runaway
const WINDOW: usize = 16; // longest x86 instruction
const MIN_REAL_INSNS: usize = 4; // fewer than this is not a function worth reporting as recovered
const MAX_TARGETS: usize = 50_000; // bound the survey work on a large image

const STACK_WINDOW: i64 = 128;
const WHOLE_STACK: u128 = u128::MAX;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Live {
    regs: [u8; GPR_COUNT], // one bit per live byte of each general register
    flags: u32,
    stack: u128, // one bit per live byte of the scratch window below the entry stack pointer
}

struct Effect {
    reads: [u8; GPR_COUNT],
    writes: [u8; GPR_COUNT], // only unconditional full writes kill a register
    reads_flags: u32,
    writes_flags: u32,
    reads_stack: u128,
    writes_stack: u128,
    keep: bool, // a call/jump/return or an unpinnable memory write or another side effect
}

pub(super) struct Payload<'a> {
    pub(super) range: Range<u64>, // the vmp appended code
    pub(super) returns_to: &'a dyn Fn(u64) -> Option<u64>, // a stub returns past the padding byte vmp puts after its five byte call
    pub(super) imports: &'a dyn Fn(usize) -> bool, // a jump into it may be an import stub and not a function vmp moved
}

impl Payload<'_> {
    fn contains(&self, address: u64) -> bool {
        self.range.contains(&address)
    }

    fn calls_in(&self, insn: &Instruction) -> bool {
        insn.flow_control() == FlowControl::Call
            && is_near_immediate(insn)
            && self.contains(insn.near_branch_target())
    }

    fn after_call(&self, insn: &Instruction) -> u64 {
        (self.returns_to)(insn.ip()).unwrap_or(insn.next_ip())
    }
}

struct Cleaned {
    pub(super) insns: Vec<Instruction>, // control flow order with each branch aimed at the real instruction it reaches
    pub(super) complete: bool, // false when part of the function would not decode so it must not be used
}

fn clean(
    image: &[u8],
    base: u64,
    bits: u32,
    entry: u64,
    payload: &Payload<'_>,
) -> Cleaned {
    let insns = decode(image, base, bits, entry, payload);
    let succ = successors(&insns, payload);

    let offsets = stack_offsets(&insns, &succ, entry, bits);

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

    let live_in = liveness(&insns, &effects, &succ); // mutation leaves the original instructions in order so liveness alone finds the junk
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
        && payload.contains(insn.near_branch_target()) // one leaving the payload is a tail call into the original code
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
    let mut work = vec![entry]; // control flow order where mutation scatters a function in chunks joined by relays

    while let Some(start) = work.pop() {
        let mut at = land(start);
        let mut falls_through = false; // a branch target starts a chain and only that chain flow needs a jump
        loop {
            let Some(&original) = insns.get(&at) else {
                complete = false;
                break;
            };
            if placed.contains(&at) {
                if falls_through {
                    out.push(jump(at, bits, out.len()));
                }
                break;
            }
            falls_through = true;

            let mut insn = original;
            placed.insert(at);
            if insn.flow_control() == FlowControl::ConditionalBranch && is_near_immediate(&insn) {
                let target = land(insn.near_branch_target());
                set_branch_target(&mut insn, target);
                work.push(target);
            }
            out.push(insn);

            match insn.flow_control() {
                FlowControl::Return => {
                    break;
                }
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => break,
                _ if payload.calls_in(&insn) => {
                    let back = payload.after_call(&insn); // the stub returns past its padding wherever the call now sits
                    for _ in insn.next_ip()..back {
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

fn jump(target: u64, bits: u32, index: usize) -> Instruction {
    let code = if bits == 64 {
        Code::Jmp_rel32_64
    } else {
        Code::Jmp_rel32_32
    };
    let mut insn = Instruction::with_branch(code, target).unwrap_or_default();
    insn.set_ip(u64::MAX - index as u64); // the encoder keys by address and nothing branches here so any unused ip does
    insn
}

fn set_branch_target(insn: &mut Instruction, target: u64) {
    match insn.op0_kind() {
        iced_x86::OpKind::NearBranch64 => insn.set_near_branch64(target),
        iced_x86::OpKind::NearBranch32 => insn.set_near_branch32(target as u32),
        _ => insn.set_near_branch16(target as u16),
    }
}

pub(super) struct Branch {
    pub(super) site: usize, // offsets into the image not addresses
    pub(super) target: usize,
    pub(super) call: bool,
}

pub(super) fn direct_branches(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    payload: &Payload<'_>,
) -> Vec<Branch> {
    let mut branches = Vec::new();
    for range in code {
        let Some(bytes) = image.get(range.clone()) else {
            continue;
        };
        let start = base + range.start as u64;
        let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);

        while decoder.can_decode() {
            let insn = decoder.decode(); // decoded in order since an e8 inside another operand would match as a call
            let call = insn.flow_control() == FlowControl::Call;
            let jump = insn.flow_control() == FlowControl::UnconditionalBranch;
            if !(call || jump) || !is_near_immediate(&insn) {
                continue;
            }

            if let (Some(site), Some(target)) = (
                insn.ip().checked_sub(base),
                insn.near_branch_target().checked_sub(base),
            ) {
                branches.push(Branch {
                    site: site as usize,
                    target: target as usize,
                    call,
                });
            }

            if payload.calls_in(&insn) {
                let back = payload.after_call(&insn);
                if back > insn.next_ip() && back < start + bytes.len() as u64 {
                    decoder.set_ip(back); // resume where the stub returns past the vmp padding byte
                    let _ = decoder.set_position((back - start) as usize);
                }
            }
        }
    }
    branches
}

fn jump_targets(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    payload: &Payload<'_>,
) -> BTreeMap<usize, usize> {
    let mut targets = BTreeMap::new();
    for branch in direct_branches(image, base, bits, code, payload) {
        if !branch.call && payload.contains(base + branch.target as u64) {
            targets.entry(branch.target).or_insert(branch.site); // a jump into the payload is a mutated or virtualized function entry
        }
    }
    targets
}

fn mutated_functions(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    payload: &Payload<'_>,
) -> Vec<(usize, u64, Cleaned)> {
    jump_targets(image, base, bits, code, payload)
        .into_iter()
        .take(MAX_TARGETS)
        .filter(|&(_, site)| !(payload.imports)(site)) // an import stub is a tail call to an api and not a function vmp moved
        .map(|(target, site)| {
            let entry = base + target as u64;
            (site, entry, clean(image, base, bits, entry, payload)) // the entry jump site the moved code start and the cleaned code
        })
        .filter(|(_, _, cleaned)| {
            cleaned.complete && real_insns(&cleaned.insns) >= MIN_REAL_INSNS && !truncated(cleaned)
        })
        .collect()
}

fn truncated(cleaned: &Cleaned) -> bool {
    cleaned
        .insns
        .iter()
        .any(|insn| insn.flow_control() == FlowControl::IndirectBranch)
}

pub(super) struct Relocated {
    pub(super) code: Vec<u8>, // a new section since vmp parks its import stubs in the regions it emptied
    pub(super) moved: Vec<Moved>,
    pub(super) recoverable: usize, // functions that cleaned to whole code written back or not
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
    let mut relocated = Relocated {
        code: Vec::new(),
        moved: Vec::new(),
        recoverable: 0,
    };

    for (site, _, cleaned) in mutated_functions(image, base, bits, code, payload) {
        relocated.recoverable += 1;

        let entry = at + relocated.code.len() as u64;
        let block = InstructionBlock::new(&cleaned.insns, entry);
        let Ok(encoded) = BlockEncoder::encode(bits, block, BlockEncoderOptions::NONE) else {
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
        if insns.contains_key(&at) || at < base {
            continue;
        }
        let Some(offset) = at.checked_sub(base).map(|o| o as usize) else {
            continue;
        };
        let end = offset.saturating_add(WINDOW).min(image.len());
        let Some(window) = image.get(offset..end) else {
            continue;
        };

        let mut decoder = Decoder::with_ip(bits, window, at, DecoderOptions::NONE);
        let insn = decoder.decode();
        if insn.is_invalid() {
            continue;
        }

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
        FlowControl::UnconditionalBranch if is_relay(insn, payload) => {
            vec![insn.near_branch_target()]
        }
        FlowControl::Call if payload.calls_in(insn) => vec![payload.after_call(insn)],
        FlowControl::UnconditionalBranch => Vec::new(),
        FlowControl::ConditionalBranch if is_near_immediate(insn) => {
            vec![insn.next_ip(), insn.near_branch_target()]
        }
        FlowControl::ConditionalBranch => vec![insn.next_ip()],
        _ => vec![insn.next_ip()],
    }
}

fn is_near_immediate(insn: &Instruction) -> bool {
    matches!(
        insn.op0_kind(),
        iced_x86::OpKind::NearBranch16
            | iced_x86::OpKind::NearBranch32
            | iced_x86::OpKind::NearBranch64
    )
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

fn step_stack(insn: &Instruction, width: i64) -> Option<i64> {
    match insn.mnemonic() {
        Mnemonic::Push | Mnemonic::Pushf | Mnemonic::Pushfd | Mnemonic::Pushfq => {
            return Some(-width);
        }
        Mnemonic::Pop | Mnemonic::Popf | Mnemonic::Popfd | Mnemonic::Popfq => return Some(width),
        Mnemonic::Lea if insn.memory_base().full_register() == Register::RSP => {
            let into_rsp = insn.op0_kind() == iced_x86::OpKind::Register
                && insn.op0_register().full_register() == Register::RSP;
            let simple = insn.memory_index() == Register::None;
            return match into_rsp && simple {
                true => Some(insn.memory_displacement64() as i64),
                false => None,
            };
        }
        _ => {}
    }

    let as_value = (0..insn.op_count()).any(|index| {
        insn.op_kind(index) == iced_x86::OpKind::Register
            && insn.op_register(index).full_register() == Register::RSP
    });
    if !as_value {
        return Some(0); // rsp only as the base of a memory operand or not named at all
    }

    let into_rsp = insn.op0_kind() == iced_x86::OpKind::Register
        && insn.op0_register().full_register() == Register::RSP;
    let by = matches!(
        insn.op1_kind(),
        iced_x86::OpKind::Immediate8
            | iced_x86::OpKind::Immediate8to16
            | iced_x86::OpKind::Immediate8to32
            | iced_x86::OpKind::Immediate8to64
            | iced_x86::OpKind::Immediate16
            | iced_x86::OpKind::Immediate32
            | iced_x86::OpKind::Immediate32to64
    )
    .then(|| insn.immediate(1) as i64);

    match (insn.mnemonic(), into_rsp, by) {
        (Mnemonic::Sub, true, Some(amount)) => Some(-amount),
        (Mnemonic::Add, true, Some(amount)) => Some(amount),
        _ => None, // the pointer went somewhere or came from somewhere that is not a frame move
    }
}

fn stack_offsets(
    insns: &BTreeMap<u64, Instruction>,
    succ: &BTreeMap<u64, Vec<u64>>,
    entry: u64,
    bits: u32,
) -> Option<BTreeMap<u64, i64>> {
    let width = i64::from(bits / 8);
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
        let moved = step_stack(insn, width)?;
        let next = delta.checked_add(moved)?;

        for target in succ.get(&at)?.iter() {
            work.push((*target, next));
        }
    }

    Some(offset)
}

#[derive(Clone, Copy)]
enum Slot {
    Scratch(u128), // bytes of the tracked window below the entry stack pointer
    Elsewhere,     // pinned to the stack but outside the window so the caller frame or deeper
    Unknown,       // not an address this can pin at all
}

fn displacement(memory: &iced_x86::UsedMemory, bits: u32) -> i64 {
    match bits {
        64 => memory.displacement() as i64,
        _ => memory.displacement() as u32 as i32 as i64,
    }
}

fn slot(memory: &iced_x86::UsedMemory, insn: &Instruction, delta: i64, bits: u32) -> Slot {
    if matches!(
        insn.mnemonic(),
        Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Pushf
            | Mnemonic::Pushfd
            | Mnemonic::Pushfq
            | Mnemonic::Popf
            | Mnemonic::Popfd
            | Mnemonic::Popfq
            | Mnemonic::Call
            | Mnemonic::Enter
            | Mnemonic::Leave
    ) {
        return Slot::Unknown;
    }
    if memory.base().full_register() != Register::RSP || memory.index() != Register::None {
        return Slot::Unknown;
    }

    let Ok(size) = i64::try_from(memory.memory_size().size()) else {
        return Slot::Unknown;
    };
    let Some(start) = delta.checked_add(displacement(memory, bits)) else {
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
    let mut writes = [0u8; GPR_COUNT];
    let mut keep = false;

    for used in info.used_registers() {
        let register = used.register();
        let Some((index, bytes)) = gpr_bytes(register) else {
            if writes_access(used.access()) {
                keep = true; // xmm segments and the rest are not modelled so never removable
            }
            continue;
        };
        if reads_access(used.access()) {
            reads[index] |= read_mask(register);
        }
        match used.access() {
            OpAccess::Write | OpAccess::ReadWrite => writes[index] |= bytes,
            OpAccess::CondWrite | OpAccess::ReadCondWrite => reads[index] |= read_mask(register), // a cmov may keep its old value
            _ => {}
        }
    }

    if matches!(
        insn.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) && bits == 64
    {
        for register in [Register::RCX, Register::RDX, Register::R8, Register::R9] {
            if let Some((index, _)) = gpr_bytes(register) {
                reads[index] |= read_mask(register);
            }
        }
    }

    let mut reads_stack = 0u128;
    let mut writes_stack = 0u128;
    let mut loose_write = false;
    for memory in info.used_memory() {
        let found = delta.map_or(Slot::Unknown, |delta| slot(memory, insn, delta, bits));
        if reads_access(memory.access()) {
            match found {
                Slot::Scratch(mask) => reads_stack |= mask,
                Slot::Elsewhere => {} // cannot alias a slot in the window so it holds none alive
                Slot::Unknown => reads_stack = WHOLE_STACK,
            }
        }
        if writes_access(memory.access()) {
            match found {
                Slot::Scratch(mask) => writes_stack |= mask,
                _ => loose_write = true, // the caller can see it or it cannot be placed at all
            }
        }
    }

    if matches!(
        insn.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) {
        reads_stack = WHOLE_STACK;
    }

    keep |= loose_write || side_effect(insn);

    Effect {
        reads,
        writes,
        reads_flags: insn.rflags_read() & TRACKED_FLAGS,
        writes_flags: insn.rflags_modified() & TRACKED_FLAGS,
        reads_stack,
        writes_stack,
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
        FlowControl::Next | FlowControl::UnconditionalBranch => matches!(
            insn.mnemonic(),
            Mnemonic::Push
                | Mnemonic::Pop
                | Mnemonic::Pushf
                | Mnemonic::Pushfd
                | Mnemonic::Pushfq
                | Mnemonic::Popf
                | Mnemonic::Popfd
                | Mnemonic::Popfq
                | Mnemonic::In
                | Mnemonic::Out
                | Mnemonic::Cpuid
                | Mnemonic::Rdtsc
                | Mnemonic::Rdtscp
                | Mnemonic::Syscall
                | Mnemonic::Sysenter
                | Mnemonic::Hlt
        ),
    }
}

fn gpr_bytes(register: Register) -> Option<(usize, u8)> {
    if !register.is_gpr() {
        return None;
    }
    let index = register.full_register().number();
    let mask = if is_high8(register) {
        0b10
    } else {
        match register.size() {
            1 => 0b1,
            2 => 0b11,
            4 | 8 => 0xFF, // a 32 bit write clears the upper half so it defines all eight bytes
            _ => 0xFF,
        }
    };
    Some((index, mask))
}

fn read_mask(register: Register) -> u8 {
    if is_high8(register) {
        return 0b10;
    }
    match register.size() {
        1 => 0b1,
        2 => 0b11,
        4 => 0b1111, // a read of that width touches only the low four
        _ => 0xFF,
    }
}

fn is_high8(register: Register) -> bool {
    matches!(
        register,
        Register::AH | Register::BH | Register::CH | Register::DH
    )
}

fn exit_live(insn: &Instruction) -> Live {
    let mut state = Live::default();
    if insn.flow_control() != FlowControl::Return {
        state.regs = [0xFF; GPR_COUNT]; // a tail jump or any other exit goes to code that may read anything
        state.flags = TRACKED_FLAGS;
        state.stack = WHOLE_STACK;
        return state;
    }
    for reg in RETURN_LIVE {
        state.regs[reg] = 0xFF;
    }
    state // the frame below the entry pointer is gone at a return so none of its slots is live
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
    let writes_live = (0..GPR_COUNT).any(|index| effect.writes[index] & out.regs[index] != 0);
    writes_live || effect.writes_flags & out.flags != 0 || effect.writes_stack & out.stack != 0
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
                    state.regs[index] &= !effect.writes[index];
                    state.regs[index] |= effect.reads[index];
                }
                state.flags &= !effect.writes_flags;
                state.flags |= effect.reads_flags;
                state.stack &= !effect.writes_stack;
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
