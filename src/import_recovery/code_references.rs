use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

use super::descriptors::existing_thunk_slots;
use super::iat_scan::{named_in, settle_runs};
use super::{
    ImportPlan, ImportSource, SlotCandidate, Unresolved, append_groups, collect_recovered_slots,
    read_pointer, read_u32, resolve_value, slot_is_in_data_section,
};
use crate::pe::exports::ExportIndex;
use crate::pe::{GUARD_CHECK_PE32, GUARD_CHECK_PE32_PLUS, LOAD_CONFIG_DIRECTORY, PeImage, PeKind};
use crate::unpack::x86::branches::instructions;
use crate::unpack::x86::opcodes::{CALL_MODRM, INDIRECT_LEN, JUMP_MODRM, MODRM_DISP32_MASK};
use crate::unpack::x86::opcodes::{GROUP_FF, LEA, MODRM_DISP32, MOV_EAX_MOFFS32, MOV_LOAD};
use crate::unpack::x86::opcodes::{MOV_IMM_RM, MOV_MOFFS32_EAX, MOV_STORE, REX_WR};
use crate::unpack::x86::opcodes::{MOV_REG_IMM32, PUSH_IMM32, REX_W};

const MAX_CODE_REFERENCE_BYTES: usize = 256 * 1024 * 1024;
const CALLEE_SAVED: [Register; 8] = [
    Register::RBX,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
const MAX_REFERENCED_SLOTS: usize = super::MAX_IMPORTS;
const REX_RIP_LENGTH: usize = 7; // rex, opcode, modrm, disp32
const MODRM_SIB: u8 = 0x04; // mod 00, rm 100, sib base 101: [index * scale + disp32]
const SIB_NO_BASE: u8 = 0x05;
const SIB_BASE_MASK: u8 = 0x07;
const MOV_IMMEDIATE_LENGTH: usize = 11;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Reference {
    Called,
    Loaded,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Addressed {
    Slot,
    IndexedArray,
}

#[derive(Default)]
pub(super) struct CodeReferences {
    pub(super) slots: BTreeMap<u32, Reference>,
    pub(super) stored: BTreeSet<u32>,
    pub(super) addressed: BTreeMap<u32, Addressed>,
    pub(super) stores_unseen: bool,
    pub(super) truncated: bool,
}

pub(super) fn recover_referenced_imports(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let memory = image.bytes();
    let width = image.model().kind.pointer_width();

    let mut recovered = collect_recovered_slots(plan, width);
    recovered.append(&mut existing_thunk_slots(memory, &plan.existing, width));
    recovered.append(&mut guard_pointer_slots(image, observed_base));

    let mut entries = Vec::new();
    for (&slot, &reference) in referenced {
        if recovered.contains(&slot) || plan.unbound_delay_slots.contains(&slot) {
            continue;
        }

        entries.extend(referenced_candidate(
            image,
            observed_base,
            exports,
            slot,
            reference,
            plan,
        ));
    }

    let taken = |slot: u32| {
        recovered.contains(&slot)
            || plan.unbound_delay_slots.contains(&slot)
            || plan.stores_to(slot)
    };
    let fill = |slot: u32, module: &str| {
        let value = read_pointer(memory, slot as usize, width)?;
        let (symbol, aliased) = named_in(exports, value, module)?;
        Some(SlotCandidate {
            slot,
            value,
            symbol,
            aliased,
        })
    };
    let mut entries = bridge_gaps(entries, width as u32, taken, fill);

    let tied: usize = settle_runs(std::slice::from_mut(&mut entries), width, exports)
        .into_iter()
        .sum();
    plan.counts.tied_module_runs = plan.counts.tied_module_runs.saturating_add(tied);

    append_groups(entries, width, ImportSource::Inferred, referenced, plan);
}

fn referenced_candidate(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    slot: u32,
    reference: Reference,
    plan: &mut ImportPlan,
) -> Option<SlotCandidate> {
    let memory = image.bytes();
    let kind = image.model().kind;
    let width = kind.pointer_width();

    if plan.packer_owns(slot) {
        plan.counts.packer_slots_skipped = plan.counts.packer_slots_skipped.saturating_add(1);
        return None;
    }

    let in_data = slot_is_in_data_section(image, slot, width);
    if !in_data && !(slot as usize).is_multiple_of(width) {
        return None;
    }

    let value = read_pointer(memory, slot as usize, width)?;
    let found = match resolve_value(memory, observed_base, kind, value, exports) {
        Ok(found) => found,
        Err(reason) => {
            if in_data {
                record_unresolved_call(plan, reference, reason);
            }
            return None;
        }
    };
    if found.ambiguous {
        plan.ambiguous_slots.insert(slot);
        return None;
    }

    if !in_data && reference != Reference::Called {
        plan.counts.slots_outside_data_sections =
            plan.counts.slots_outside_data_sections.saturating_add(1);
        return None;
    }

    if plan.stores_to(slot) {
        plan.counts.runtime_lookup_slots = plan.counts.runtime_lookup_slots.saturating_add(1);
        return None;
    }

    // an indirect store cannot be seen
    let imported_variable = in_data && !plan.stores_unseen && exports.is_variable(value);
    let alone = reference == Reference::Loaded || !in_data;
    let module = &found.symbol.module;
    let placed = !alone
        || imported_variable
        || neighbor_shares_module(memory, observed_base, kind, exports, slot, module)
        || (in_data && is_zero_bounded(memory, slot, width));
    if !placed {
        let counter = match in_data {
            true => &mut plan.lone_slots_dropped,
            false => &mut plan.counts.slots_outside_data_sections,
        };
        *counter = counter.saturating_add(1);
        return None;
    }

    Some(SlotCandidate {
        slot,
        value,
        symbol: found.symbol.clone(),
        aliased: found.aliased,
    })
}

fn bridge_gaps(
    entries: Vec<SlotCandidate>,
    width: u32,
    taken: impl Fn(u32) -> bool,
    fill: impl Fn(u32, &str) -> Option<SlotCandidate>,
) -> Vec<SlotCandidate> {
    let mut joined = Vec::<SlotCandidate>::with_capacity(entries.len());

    for entry in entries {
        let between = joined
            .last()
            .filter(|last| {
                last.symbol
                    .module
                    .eq_ignore_ascii_case(&entry.symbol.module)
            })
            .map(|last| last.slot.saturating_add(width)..entry.slot);
        let filled = between.and_then(|gap| {
            gap.step_by(width as usize)
                .map(|slot| (!taken(slot)).then(|| fill(slot, &entry.symbol.module))?)
                .collect::<Option<Vec<_>>>()
        });

        joined.extend(filled.into_iter().flatten());
        joined.push(entry);
    }

    joined
}

fn is_zero_bounded(memory: &[u8], slot: u32, width: usize) -> bool {
    let step = width as u32;
    let is_zero = |neighbor: Option<u32>| {
        neighbor.and_then(|neighbor| read_pointer(memory, neighbor as usize, width)) == Some(0)
    };

    is_zero(slot.checked_sub(step)) && is_zero(slot.checked_add(step))
}

pub(super) fn image_offset(
    observed_base: usize,
    memory_length: usize,
    value: usize,
) -> Option<usize> {
    let offset = value.checked_sub(observed_base)?;
    (offset < memory_length).then_some(offset)
}

fn guard_pointer_slots(image: &PeImage<'_>, observed_base: usize) -> BTreeSet<u32> {
    let Some(directory) = image.directory(LOAD_CONFIG_DIRECTORY) else {
        return BTreeSet::new();
    };

    let memory = image.bytes();
    let kind = image.model().kind;
    let width = kind.pointer_width();
    let directory_rva = directory.rva().as_usize();
    let declared = read_u32(memory, directory_rva).unwrap_or(0) as usize; // load config Size

    let check_pointer = match kind {
        PeKind::Pe32 => GUARD_CHECK_PE32,
        PeKind::Pe32Plus => GUARD_CHECK_PE32_PLUS,
    };

    let dispatch_pointer = check_pointer.saturating_add(width);
    [check_pointer, dispatch_pointer]
        .into_iter()
        .filter(|offset| offset.saturating_add(width) <= declared)
        .filter_map(|offset| read_pointer(memory, directory_rva.checked_add(offset)?, width))
        .filter_map(|address| u32::try_from(address.checked_sub(observed_base)?).ok())
        .collect()
}

fn record_unresolved_call(plan: &mut ImportPlan, reference: Reference, reason: Unresolved) {
    if reference != Reference::Called {
        return;
    }

    let counter = match reason {
        Unresolved::OwnImage => return,
        Unresolved::OtherModule => &mut plan.counts.unresolved_other_module,
        Unresolved::OutsideImage => &mut plan.counts.unresolved_outside_image,
        Unresolved::UnknownStub => &mut plan.counts.unresolved_unknown_stub,
        Unresolved::ChainExhausted => &mut plan.counts.unresolved_chain_exhausted,
    };

    *counter = counter.saturating_add(1);
}

fn neighbor_shares_module(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    slot: u32,
    module: &str,
) -> bool {
    let width = kind.pointer_width();
    let step = width as u32;
    [slot.checked_sub(step), slot.checked_add(step)]
        .into_iter()
        .flatten()
        .filter_map(|neighbor| read_pointer(memory, neighbor as usize, width))
        .filter_map(|value| resolve_value(memory, observed_base, kind, value, exports).ok())
        .any(|found| !found.ambiguous && found.symbol.module.eq_ignore_ascii_case(module))
}

pub(crate) fn code_referenced_slots(
    image: &PeImage<'_>,
    observed_base: usize,
    skip: &[Range<usize>],
) -> BTreeSet<usize> {
    find_code_references(image, observed_base, skip)
        .slots
        .into_keys()
        .map(|slot| slot as usize)
        .collect()
}

// the packer's own code calls its own pointers, never the program's imports
pub(super) fn find_code_references(
    image: &PeImage<'_>,
    observed_base: usize,
    packer: &[Range<usize>],
) -> CodeReferences {
    let memory = image.bytes();
    let model = image.model();
    let kind = model.kind;
    let mut found = CodeReferences::default();
    let mut scanned = 0usize;

    for section in &model.sections {
        if !section.is_executable() {
            continue;
        }

        let range = section.range_in(memory);
        let start = range.start;
        let Some(code) = memory.get(range) else {
            continue;
        };

        let remaining = MAX_CODE_REFERENCE_BYTES.saturating_sub(scanned);
        let scan_length = code.len().min(remaining);
        found.stores_unseen = found.stores_unseen || scan_length < code.len();

        for index in 0..scan_length {
            let instruction = start.saturating_add(index);
            if packer.iter().any(|range| range.contains(&instruction)) {
                continue;
            }

            if let Some(slot) = decode_slot_store(memory, observed_base, kind, instruction) {
                found.stored.insert(slot);
            }
            if let Some((slot, how)) =
                decode_address_taken(memory, observed_base, kind, instruction)
            {
                let seen = found.addressed.entry(slot).or_insert(how);
                if how == Addressed::IndexedArray {
                    *seen = how;
                }
            }

            let Some((slot, reference)) =
                decode_slot_reference(memory, observed_base, kind, instruction)
            else {
                continue;
            };

            if found.slots.len() >= MAX_REFERENCED_SLOTS && !found.slots.contains_key(&slot) {
                found.truncated = true;
                continue;
            }

            let seen = found.slots.entry(slot).or_insert(reference);
            if reference == Reference::Called {
                *seen = Reference::Called;
            }
        }

        for array in indexed_stores(
            memory,
            observed_base,
            kind,
            start..start + scan_length,
            packer,
        ) {
            found.addressed.insert(array, Addressed::IndexedArray);
        }

        scanned = scanned.saturating_add(scan_length);
    }

    found.truncated = found.truncated || found.stores_unseen;
    found
}

fn holds_outside_pointer(memory: &[u8], observed_base: usize, slot: usize, width: usize) -> bool {
    let image = observed_base..observed_base.saturating_add(memory.len());

    slot.is_multiple_of(width)
        && read_pointer(memory, slot, width).is_some_and(|held| held != 0 && !image.contains(&held))
}

pub(super) fn absolute_slot(observed_base: usize, operand: &[u8]) -> Option<usize> {
    read_pointer(operand, 0, operand.len())?.checked_sub(observed_base)
}

fn is_disp32(modrm: u8) -> bool {
    modrm & MODRM_DISP32_MASK == MODRM_DISP32
}

fn decode_x86_load(
    memory: &[u8],
    observed_base: usize,
    instruction: usize,
) -> Option<(u32, Reference)> {
    let code = memory.get(instruction..)?;
    let operand = match *code.first()? {
        MOV_EAX_MOFFS32 => code.get(1..5)?,
        MOV_LOAD if is_disp32(*code.get(1)?) => code.get(2..6)?, // mov reg, [slot]; call reg
        _ => return None,
    };

    let slot = absolute_slot(observed_base, operand)?;
    if !holds_outside_pointer(memory, observed_base, slot, 4) {
        return None;
    }

    Some((u32::try_from(slot).ok()?, Reference::Loaded))
}

fn decode_x64_load(
    memory: &[u8],
    observed_base: usize,
    instruction: usize,
) -> Option<(u32, Reference)> {
    let code = memory.get(instruction..instruction.checked_add(REX_RIP_LENGTH)?)?;
    if !matches!(code[0], REX_W | REX_WR) || code[1] != MOV_LOAD || !is_disp32(code[2]) {
        return None;
    }

    let slot = rip_relative_slot(observed_base, instruction, REX_RIP_LENGTH, &code[3..7])?;
    if !holds_outside_pointer(memory, observed_base, slot as usize, 8) {
        return None;
    }

    Some((slot, Reference::Loaded))
}

fn decode_x86_store(memory: &[u8], observed_base: usize, instruction: usize) -> Option<usize> {
    let code = memory.get(instruction..)?;
    let operand = match *code.first()? {
        MOV_MOFFS32_EAX => code.get(1..5)?,
        MOV_STORE if is_disp32(*code.get(1)?) => code.get(2..6)?,
        MOV_IMM_RM if *code.get(1)? == MODRM_DISP32 => code.get(2..10)?.get(..4)?,
        _ => return None,
    };

    absolute_slot(observed_base, operand)
}

fn decode_x64_store(memory: &[u8], observed_base: usize, instruction: usize) -> Option<usize> {
    let code = memory.get(instruction..)?;
    let rex = *code.first()?;
    if !matches!(rex, REX_W | REX_WR) {
        return None;
    }

    let relative = |length: usize| {
        let field = code.get(..length)?.get(3..7)?;
        Some(rip_relative_slot(observed_base, instruction, length, field)? as usize)
    };

    match *code.get(1)? {
        MOV_STORE if is_disp32(*code.get(2)?) => relative(REX_RIP_LENGTH),
        MOV_IMM_RM if rex == REX_W && *code.get(2)? == MODRM_DISP32 => {
            relative(MOV_IMMEDIATE_LENGTH)
        }
        MOV_MOFFS32_EAX if rex == REX_W => absolute_slot(observed_base, code.get(2..10)?),
        _ => None,
    }
}

// code takes the address of data it owns; it reaches its import slots only through their contents
fn decode_address_taken(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    instruction: usize,
) -> Option<(u32, Addressed)> {
    let code = memory.get(instruction..)?;
    let taken = match kind {
        PeKind::Pe32 => {
            let absolute = |range: Range<usize>| absolute_slot(observed_base, code.get(range)?);
            match *code.first()? {
                PUSH_IMM32 => (absolute(1..5)?, Addressed::Slot),
                opcode if (MOV_REG_IMM32..=MOV_REG_IMM32 + 7).contains(&opcode) => {
                    (absolute(1..5)?, Addressed::Slot)
                }
                LEA if is_disp32(*code.get(1)?) => (absolute(2..6)?, Addressed::Slot),
                LEA if *code.get(1)? & MODRM_DISP32_MASK == MODRM_SIB
                    && *code.get(2)? & SIB_BASE_MASK == SIB_NO_BASE =>
                {
                    (absolute(3..7)?, Addressed::IndexedArray)
                }
                _ => return None,
            }
        }
        PeKind::Pe32Plus => {
            let rex = *code.first()?;
            let lea =
                matches!(rex, REX_W | REX_WR) && *code.get(1)? == LEA && is_disp32(*code.get(2)?);
            if !lea {
                return None;
            }

            let slot =
                rip_relative_slot(observed_base, instruction, REX_RIP_LENGTH, code.get(3..7)?)?;
            (slot as usize, Addressed::Slot)
        }
    };

    let (slot, how) = taken;
    (slot < memory.len() && slot.is_multiple_of(kind.pointer_width()))
        .then(|| Some((u32::try_from(slot).ok()?, how)))?
}

// a register given a data address and then stored through with an index fills an array the program owns
fn indexed_stores(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    code: Range<usize>,
    packer: &[Range<usize>],
) -> BTreeSet<u32> {
    let mut factory = InstructionInfoFactory::new();
    let mut held: HashMap<Register, usize> = HashMap::new(); // full register -> rva it holds
    let mut arrays = BTreeSet::new();

    for insn in instructions(memory, observed_base as u64, kind.bits(), &code) {
        let at = (insn.ip() - observed_base as u64) as usize;
        if insn.is_invalid() || packer.iter().any(|range| range.contains(&at)) {
            held.clear();
            continue;
        }

        let info = factory.info(&insn);
        for used in info.used_memory() {
            let writes = matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            );
            let base = held.get(&used.base().full_register());
            if let Some(base) = base.filter(|_| writes && used.index() != Register::None) {
                let start = base.wrapping_add(used.displacement() as usize);
                if let Ok(start) = u32::try_from(start) {
                    arrays.insert(start);
                }
            }
        }

        for used in info.used_registers() {
            if !matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::NoMemAccess
            ) {
                held.remove(&used.register().full_register());
            }
        }

        match insn.flow_control() {
            FlowControl::Next => {
                if let Some(address) = data_address(&insn, observed_base, memory.len()) {
                    held.insert(insn.op0_register().full_register(), address);
                }
            }
            FlowControl::ConditionalBranch => {} // the fall through keeps every register
            FlowControl::Call | FlowControl::IndirectCall => {
                held.retain(|register, _| CALLEE_SAVED.contains(register)); // windows calling conventions
            }
            _ => held.clear(),
        }
    }

    arrays
}

fn data_address(insn: &Instruction, observed_base: usize, image_len: usize) -> Option<usize> {
    let address = match insn.mnemonic() {
        Mnemonic::Lea if insn.is_ip_rel_memory_operand() => insn.ip_rel_memory_address(),
        Mnemonic::Lea
            if insn.memory_base() == Register::None && insn.memory_index() == Register::None =>
        {
            insn.memory_displacement64()
        }
        Mnemonic::Mov
            if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Immediate32 =>
        {
            insn.immediate32().into()
        }
        _ => return None,
    };

    let rva = usize::try_from(address).ok()?.checked_sub(observed_base)?;
    (rva < image_len).then_some(rva)
}

fn decode_slot_store(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    instruction: usize,
) -> Option<u32> {
    let slot = match kind {
        PeKind::Pe32 => decode_x86_store(memory, observed_base, instruction),
        PeKind::Pe32Plus => decode_x64_store(memory, observed_base, instruction),
    }?;

    holds_outside_pointer(memory, observed_base, slot, kind.pointer_width())
        .then(|| u32::try_from(slot).ok())?
}

fn decode_slot_reference(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    instruction: usize,
) -> Option<(u32, Reference)> {
    if let Some(code) = memory.get(instruction..instruction.checked_add(INDIRECT_LEN)?)
        && code[0] == GROUP_FF
        && matches!(code[1], CALL_MODRM | JUMP_MODRM)
    {
        let operand = &code[2..INDIRECT_LEN];
        let slot = match kind {
            PeKind::Pe32 => u32::try_from(absolute_slot(observed_base, operand)?).ok(),
            PeKind::Pe32Plus => {
                rip_relative_slot(observed_base, instruction, INDIRECT_LEN, operand)
            }
        };

        return Some((slot?, Reference::Called));
    }

    match kind {
        PeKind::Pe32 => decode_x86_load(memory, observed_base, instruction),
        PeKind::Pe32Plus => decode_x64_load(memory, observed_base, instruction),
    }
}

pub(super) fn rip_relative_slot(
    observed_base: usize,
    instruction: usize,
    length: usize,
    displacement: &[u8],
) -> Option<u32> {
    let displacement = i32::from_le_bytes(displacement.try_into().ok()?);
    let next = observed_base
        .checked_add(instruction)?
        .checked_add(length)?;
    let address = next.checked_add_signed(displacement as isize)?;

    u32::try_from(address.checked_sub(observed_base)?).ok()
}
