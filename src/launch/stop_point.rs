use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use windows::Win32::Foundation::HANDLE;

use super::execute_trap::Trap;
use super::remote_memory::{read, read_pointer};
use super::system_files::{in_ntdll, in_start_module};
use super::thread_context::StopFrame;
use crate::packers::LayoutBasis;
use crate::pe::{PeKind, TLS_CALLBACKS_FIELD};
use crate::unpack::x86::branches::decode_one;
use crate::unpack::x86::opcodes::MAX_INSTRUCTION;

const MAX_TLS_REASON: usize = 3; // attach and detach reasons
const PROCESS_ATTACH: usize = 1;
const TLS_ARGUMENTS: usize = 3;
const MAX_TLS_CALLBACKS: usize = 64;
const LONGEST_CALL: usize = 7;

#[derive(Clone, Copy)]
pub(crate) enum Reached {
    EntryPoint,
    ThroughPacker,
}

#[derive(Clone, Copy)]
pub(crate) struct Stop {
    pub(crate) rva: u32,
    pub(crate) reached: Reached,
}

pub(super) struct Image {
    pub(super) span: Range<usize>,
    pub(super) entry: usize,
    pub(super) kind: PeKind,
    pub(super) fixer: Option<usize>,
    pub(super) library: bool,
    pub(super) basis: LayoutBasis,
    pub(super) entry_stub_in_code: bool,
    pub(super) tls_directory: Option<usize>,
    pub(super) trap: Trap,
}

pub(super) struct Detour {
    pub(super) operand: usize,
    pub(super) original: [u8; 4],
    pub(super) entry: usize,
}

pub(super) enum Hit {
    Returns { caller: usize, stack: usize },
    Program(Stop),
    Late { caller: usize },
}

pub(super) fn classify(process: HANDLE, image: &Image, frame: &StopFrame) -> Option<Hit> {
    let width = image.kind.pointer_width();
    let caller = read_pointer(process, frame.sp, image.kind)?;

    if let Some(reason) = entry_reason(process, image, frame)? {
        let listed = tls_callbacks(process, image).contains(&frame.pc);
        let callback = match image.library {
            true => listed, // dllmain has the same shape
            false => listed || in_ntdll(process, caller),
        };

        if callback {
            let popped = match image.kind {
                PeKind::Pe32Plus => 1,
                PeKind::Pe32 => 1 + TLS_ARGUMENTS, // stdcall pops its args
            };
            return Some(Hit::Returns {
                caller,
                stack: frame.sp + popped * width,
            });
        }
        if image.library && reason != PROCESS_ATTACH {
            return Some(Hit::Late { caller }); // the attach call came first and was missed
        }
        if image.library {
            return Some(Hit::Program(Stop {
                rva: rva(image, frame.pc)?,
                reached: how_reached(process, image, frame),
            }));
        }
    }

    if image.trap.covers(caller) {
        return Some(Hit::Late { caller });
    }

    let first = decode(process, image, frame.pc);
    if let Some(first) = first.filter(|first| first.flow_control() == FlowControl::Return) {
        return Some(Hit::Returns {
            caller,
            stack: frame.sp + width + first.immediate16() as usize,
        }); // old aspack calls a lone ret in program code
    }

    let jumps_to_packer = first.is_some_and(|first| {
        let target = first.near_branch_target() as usize;
        first.flow_control() == FlowControl::UnconditionalBranch
            && image.span.contains(&target)
            && !image.trap.covers(target) // virtualized entry: one jmp into the vm
    });
    let from_packer = image.span.contains(&caller) || jumps_to_packer;
    let reached = match from_packer {
        true => Reached::ThroughPacker,
        false => how_reached(process, image, frame),
    };

    Some(Hit::Program(Stop {
        rva: rva(image, frame.pc)?,
        reached,
    }))
}

fn how_reached(process: HANDLE, image: &Image, frame: &StopFrame) -> Reached {
    match entered_by_windows(process, image, frame) {
        true => Reached::EntryPoint,
        false => Reached::ThroughPacker,
    }
}

pub(super) fn entered_by_windows(process: HANDLE, image: &Image, frame: &StopFrame) -> bool {
    let Some(caller) = read_pointer(process, frame.sp, image.kind) else {
        return false;
    };
    let from_windows = || {
        let starter = match image.library {
            true => in_ntdll(process, caller),
            false => in_start_module(process, caller),
        };
        starter && returns_into_call(process, image.kind, caller)
    };
    let from_packer = image.span.contains(&caller) && !image.trap.covers(caller); // vmp calls a dll's entry itself

    match image.library {
        true => {
            entry_reason(process, image, frame) == Some(Some(PROCESS_ATTACH))
                && (from_packer || from_windows())
        }
        false => from_windows(),
    }
}

// outer none: the stack could not be read
fn entry_reason(process: HANDLE, image: &Image, frame: &StopFrame) -> Option<Option<usize>> {
    let width = image.kind.pointer_width();
    let pointer = |address| read_pointer(process, address, image.kind);

    let (module, reason) = match frame.registers {
        Some([module, reason]) => (module, reason),
        None => (pointer(frame.sp + width)?, pointer(frame.sp + 2 * width)?), // stdcall args above the return address
    };
    Some((module == image.span.start && reason <= MAX_TLS_REASON).then_some(reason))
}

// a stack value counts as a return address only when a call sits right before it
pub(super) fn returns_into_call(process: HANDLE, kind: PeKind, caller: usize) -> bool {
    let mut before = [0u8; LONGEST_CALL];
    if caller < LONGEST_CALL || !read(process, caller - LONGEST_CALL, &mut before) {
        return false;
    }

    (2..=LONGEST_CALL).any(|length| {
        let code = &before[LONGEST_CALL - length..];
        let call = Decoder::new(kind.bits(), code, DecoderOptions::NONE).decode();

        call.len() == length
            && matches!(
                call.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            )
    })
}

fn rva(image: &Image, pc: usize) -> Option<u32> {
    u32::try_from(pc.checked_sub(image.span.start)?).ok()
}

fn tls_callbacks(process: HANDLE, image: &Image) -> Vec<usize> {
    let width = image.kind.pointer_width();
    let Some(list) = image
        .tls_directory
        .and_then(|directory| {
            read_pointer(
                process,
                image.span.start + directory + TLS_CALLBACKS_FIELD * width,
                image.kind,
            )
        })
        .filter(|list| *list != 0)
    else {
        return Vec::new();
    };

    (0..MAX_TLS_CALLBACKS)
        .map_while(|index| read_pointer(process, list + index * width, image.kind))
        .take_while(|callback| *callback != 0)
        .collect()
}

fn decode(process: HANDLE, image: &Image, pc: usize) -> Option<Instruction> {
    let mut code = [0u8; MAX_INSTRUCTION];
    read(process, pc, &mut code).then_some(())?;

    decode_one(image.kind.bits(), &code, pc as u64)
}
