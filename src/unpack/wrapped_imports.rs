use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use crate::pe::exports::ExportIndex;
use crate::pe::process_memory::ProcessMemory;
use crate::unpack::x86::branches::{fixed_address, is_near_immediate};
use crate::unpack::x86::{Argument, WrappedCall};

const MAX_COPIED: usize = 32; // the few instructions a hook's jump overwrote
const TRAMPOLINE_WINDOW: [usize; 3] = [64, 32, 16];
const MAX_HOPS: usize = 4;

// windows' own a-and-w resource lookups are their ex forms with the type and name swapped and the
// neutral language (MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL) is 0); a wrapper may call either
const SAME_AS: &[(&str, [Argument; 4], &str)] = &[
    (
        "FindResourceExA",
        [
            Argument::Callers(0),
            Argument::Callers(2),
            Argument::Callers(1),
            Argument::Value(0),
        ],
        "FindResourceA",
    ),
    (
        "FindResourceExW",
        [
            Argument::Callers(0),
            Argument::Callers(2),
            Argument::Callers(1),
            Argument::Value(0),
        ],
        "FindResourceW",
    ),
];

// the import a wrapper stands for: the api it calls when it hands the caller's arguments on as they
// came, or the api that call is known to be the same as; any other rearrangement is not named
pub(crate) fn wrapped_import(
    exports: &ExportIndex,
    memory: &ProcessMemory<'_>,
    bits: u32,
    wrapped: &WrappedCall,
) -> Option<u64> {
    let api = match exports.resolve(usize::try_from(wrapped.api).ok()?) {
        Some(_) => wrapped.api,
        None => hooked_export(exports, memory, bits, wrapped.api)
            .or_else(|| through_trampoline(exports, memory, bits, wrapped.api))?,
    };
    let called = exports.resolve(usize::try_from(api).ok()?)?;
    if passed_as_they_came(&wrapped.arguments) {
        return Some(api);
    }

    let name = called.symbol.name.as_deref()?;
    let (_, _, same_as) = SAME_AS
        .iter()
        .find(|(api, arguments, _)| *api == name && wrapped.arguments.starts_with(arguments))?;
    let address = exports.address_of(&called.symbol.module, same_as)?;
    u64::try_from(address).ok()
}

// an inline hook overwrites an export's first instruction with a jump to its own code, and whoever
// reads the api through that jump lands on the way there: the one export whose jumps end where
// this landing's do is the api it stands for
fn hooked_export(
    exports: &ExportIndex,
    memory: &ProcessMemory<'_>,
    bits: u32,
    landing: u64,
) -> Option<u64> {
    let hook = jumps_end(memory, bits, landing)?;
    let mut hooked = exports.addresses().filter(|address| {
        let opens_with_jump =
            copied_then_jump(memory, bits, *address as u64).is_some_and(|(copied, _)| copied == 0);
        opens_with_jump && jumps_end(memory, bits, *address as u64) == Some(hook)
    });
    let export = hooked.next()?;
    hooked.next().is_none().then_some(export as u64)
}

fn jumps_end(memory: &ProcessMemory<'_>, bits: u32, start: u64) -> Option<u64> {
    let mut at = start;
    for _ in 0..MAX_HOPS {
        match copied_then_jump(memory, bits, at) {
            Some((0, next)) => at = next,
            _ => break,
        }
    }
    (at != start).then_some(at)
}

// an inline hook keeps the instructions its jump overwrote in a trampoline that runs them and jumps
// back past them: what the trampoline stands for is the export that far before its jump's target
fn through_trampoline(
    exports: &ExportIndex,
    memory: &ProcessMemory<'_>,
    bits: u32,
    at: u64,
) -> Option<u64> {
    let exported = |address: u64| {
        usize::try_from(address).is_ok_and(|address| exports.resolve(address).is_some())
    };
    let mut at = at;
    for _ in 0..MAX_HOPS {
        let (copied, back) = copied_then_jump(memory, bits, at)?;
        match copied {
            0 if exported(back) => return None, // a relay into another export is someone's hook, not the api
            0 => at = back,
            _ => {
                let api = back.checked_sub(copied as u64)?;
                return exported(api).then_some(api);
            }
        }
    }
    None
}

fn copied_then_jump(memory: &ProcessMemory<'_>, bits: u32, at: u64) -> Option<(usize, u64)> {
    let start = usize::try_from(at).ok()?;
    let bytes = TRAMPOLINE_WINDOW
        .iter()
        .find_map(|length| memory.slice(start, *length))?;

    let mut copied = 0usize;
    for insn in Decoder::with_ip(bits, bytes, at, DecoderOptions::NONE) {
        if insn.is_invalid() || copied > MAX_COPIED {
            return None;
        }
        match insn.flow_control() {
            FlowControl::Next => copied += insn.len(),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                return Some((copied, jump_target(&insn, memory, bits)?));
            }
            _ => return None, // copied code holds no branch of its own
        }
    }
    None
}

fn jump_target(insn: &Instruction, memory: &ProcessMemory<'_>, bits: u32) -> Option<u64> {
    let Some(slot) = fixed_address(insn) else {
        return is_near_immediate(insn).then(|| insn.near_branch_target());
    };

    let width = (bits / 8) as usize;
    let pointer = memory.slice(usize::try_from(slot).ok()?, width)?;
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(pointer);
    Some(u64::from_le_bytes(value))
}

// each argument in its own place; a register past what the api takes may still hold a copy of one
// passed before it
fn passed_as_they_came(arguments: &[Argument]) -> bool {
    arguments
        .iter()
        .enumerate()
        .all(|(index, argument)| match argument {
            Argument::Callers(at) => *at <= index && arguments.get(*at) == Some(argument),
            Argument::Varies => true,
            Argument::Value(_) => false,
        })
}
