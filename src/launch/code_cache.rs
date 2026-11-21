use std::collections::{HashMap, HashSet};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock, MemoryOperand, OpKind, Register,
};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::PAGE_EXECUTE_READ;

use super::remote_memory::{allocate_near, free, protect, read, write};
use crate::pe::{PAGE_SIZE, PeKind};
use crate::unpack::x86::branches::{is_near_immediate, near_jump};
use crate::unpack::x86::opcodes::MAX_INSTRUCTION;

const MAX_BLOCK: usize = 0x200;
const ROOM: usize = 0x100 * PAGE_SIZE;

// vmp keeps pieces of its vm inside the functions it virtualized: they run from copies here,
// so the trap on the program's code stays armed for the real entry
pub(super) struct CodeCache {
    kind: PeKind,
    copies: HashMap<usize, usize>,
    pushed: HashSet<usize>, // return addresses the copies push
    room: usize,
    used: usize,
}

pub(super) enum Refusal {
    Unfollowable,
    Full,
}

#[derive(Default)]
struct Block {
    code: Vec<Instruction>,
    pushed: Option<usize>,
}

impl CodeCache {
    pub(super) fn new(process: HANDLE, kind: PeKind, near: usize) -> Option<Self> {
        let room = allocate_near(process, near, ROOM)?;
        let executable = protect(process, room, ROOM, PAGE_EXECUTE_READ).is_some(); // writes still land
        if !executable {
            free(process, room);
            return None;
        }

        Some(Self {
            kind,
            copies: HashMap::new(),
            pushed: HashSet::new(),
            room,
            used: 0,
        })
    }

    pub(super) fn copy_of(&mut self, process: HANDLE, pc: usize) -> Result<usize, Refusal> {
        if let Some(&copy) = self.copies.get(&pc) {
            return Ok(copy);
        }

        let mut code = [0u8; MAX_BLOCK];
        let readable = (MAX_INSTRUCTION..=MAX_BLOCK)
            .rev()
            .step_by(MAX_INSTRUCTION)
            .find(|&length| read(process, pc, &mut code[..length]))
            .ok_or(Refusal::Unfollowable)?;
        let moved = moved_block(&code[..readable], self.kind, pc).ok_or(Refusal::Unfollowable)?;

        let at = self.room + self.used;
        let block = InstructionBlock::new(&moved.code, at as u64);
        let copy = BlockEncoder::encode(self.kind.bits(), block, BlockEncoderOptions::NONE)
            .map_err(|_| Refusal::Unfollowable)?
            .code_buffer;
        if self.used + copy.len() > ROOM {
            return Err(Refusal::Full);
        }
        if !write(process, at, &copy) {
            return Err(Refusal::Unfollowable);
        }

        self.used += copy.len();
        self.copies.insert(pc, at);
        self.pushed.extend(moved.pushed);
        Ok(at)
    }

    pub(super) fn pushed(&self, address: usize) -> bool {
        self.pushed.contains(&address)
    }

    pub(super) fn was_used(&self) -> bool {
        !self.copies.is_empty()
    }

    pub(super) fn release(self, process: HANDLE) {
        free(process, self.room);
    }
}

fn moved_block(code: &[u8], kind: PeKind, pc: usize) -> Option<Block> {
    let mut decoder = Decoder::with_ip(kind.bits(), code, pc as u64, DecoderOptions::NONE);
    let mut moved = Vec::new();
    let ends = |code, pushed| Some(Block { code, pushed });

    while decoder.position() + MAX_INSTRUCTION <= code.len() {
        let instruction = decoder.decode();
        let next = instruction.next_ip();

        match instruction.flow_control() {
            FlowControl::Next | FlowControl::Interrupt => moved.push(instruction),
            FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Return => {
                moved.push(instruction);
                return ends(moved, None);
            }
            FlowControl::ConditionalBranch => {
                moved.push(instruction);
                moved.push(near_jump(kind.bits(), next)?); // junk follows the always-taken ones
                return ends(moved, None);
            }
            FlowControl::Call => {
                if !is_near_immediate(&instruction) {
                    return None; // far calls, syscall and the like have no target to jump to
                }

                push_return(&mut moved, kind, next)?;
                moved.push(near_jump(kind.bits(), instruction.near_branch_target())?);
                return ends(moved, Some(next as usize));
            }
            FlowControl::IndirectCall => {
                if instruction.op0_kind() != OpKind::Register {
                    return None; // a program calling an import, not vmp
                }

                let through = match kind {
                    PeKind::Pe32 => Code::Jmp_rm32,
                    PeKind::Pe32Plus => Code::Jmp_rm64,
                };
                push_return(&mut moved, kind, next)?;
                moved.push(Instruction::with1(through, instruction.op0_register()).ok()?);
                return ends(moved, Some(next as usize));
            }
            FlowControl::Exception | FlowControl::XbeginXabortXend => return None,
        }
    }

    if moved.is_empty() {
        return None;
    }
    moved.push(near_jump(kind.bits(), decoder.ip())?);
    ends(moved, None)
}

// the copy must push the address the original would have
fn push_return(moved: &mut Vec<Instruction>, kind: PeKind, address: u64) -> Option<()> {
    match kind {
        PeKind::Pe32 => {
            moved.push(Instruction::with1(Code::Pushd_imm32, address as i32).ok()?);
        }
        PeKind::Pe32Plus => {
            let top = MemoryOperand::with_base(Register::RSP);
            moved.push(Instruction::with1(Code::Push_r64, Register::RAX).ok()?);
            moved.push(Instruction::with2(Code::Mov_r64_imm64, Register::RAX, address).ok()?);
            moved.push(Instruction::with2(Code::Xchg_rm64_r64, top, Register::RAX).ok()?); // no flags touched
        }
    }
    Some(())
}
