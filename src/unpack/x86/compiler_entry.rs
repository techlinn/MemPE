use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic};

use super::branches::{fixed_address, instructions, rel32_target, set_rel32_target};
use crate::pe::bytes::read_u32;
use crate::pe::{PeKind, PeModel};
use crate::unpack::tables::{Search, sole};
use crate::unpack::x86::opcodes::PUSH_IMM32;
use crate::unpack::{find_patterns, hex, pattern_at};

const MSVC_ENTRY_X64: &str = hex("48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ??"); // msvc mainCRTStartup
const MSVC_CALL_X64: usize = 4; // after sub rsp, 28h
const MSVC_ENTRY_X86: &str = hex("CC CC E8 ?? ?? ?? ?? E9 ?? ?? ?? ??"); // __security_init_cookie, jmp __scrt_common_main_seh
const X86_ENTRY_SKIP: usize = 2; // match starts at the int3 padding
const MSVC_STUB_X86: &str = hex("E8 ?? ?? ?? ?? E9 ?? ?? ?? ??");
const MSVC_JUMP_X64: usize = 13; // to __scrt_common_main_seh
const MSVC_JUMP_X86: usize = 5;
const MSVC_MAIN_REACH: usize = 0x400;
// the names __scrt_common_main_seh, linked into every msvc exe, imports from the ucrt
pub(crate) const MSVC_STARTUP_IMPORTS: &[&str] = &[
    "_cexit",
    "_c_exit",
    "_exit",
    "exit",
    "_get_initial_narrow_environment",
    "_get_initial_wide_environment",
    "_initterm",
    "_initterm_e",
    "_register_thread_local_exe_atexit_callback",
    "__p___argc",
    "__p___argv",
    "__p___wargv",
];
const COOKIE_X86: [u8; 4] = 0xBB40_E64E_u32.to_le_bytes(); // msvc's default security cookie
const COOKIE_X64: [u8; 8] = 0x0000_2B99_2DDF_A232_u64.to_le_bytes();
const COOKIE_REACH: usize = 0x80;
const MINGW_CONSOLE_X64: &str =
    hex("48 83 EC 28 48 8B 05 ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? 90 90 48 83 C4 28 C3"); // mingw stores __mingw_app_type 0
const MINGW_GUI_X64: &str =
    hex("48 83 EC 28 48 8B 05 ?? ?? ?? ?? C7 00 01 00 00 00 E8 ?? ?? ?? ?? 90 90 48 83 C4 28 C3"); // 1: WinMainCRTStartup
const GO_RT0_X64: &str = hex("48 8B 3C 24 48 8D 74 24 08 E9"); // go _rt0_amd64
const GO_RT0_X86: &str = hex("83 EC 08 8B 44 24 08 8D 5C 24 0C 89 04 24 89 5C 24 04 E9");
const JUMP: &str = hex("E9 ?? ?? ?? ??");
const VB6_ENTRY: &str = hex("68 ?? ?? ?? ?? E8 ?? ?? ?? ??"); // push VBHeader / call ThunRTMain
const VB6_HEADER_MAGIC: &[u8; 4] = b"VB5!";
const VB6_PROJECT: usize = 0x30; // pointer to project info
const VB6_PROJECT_DATA: usize = 0x20;
const DELPHI_INIT: &str = hex("B8 ?? ?? ?? ?? E8"); // mov eax, InitTable / call @InitExe
const DELPHI_FRAME: &str = hex("55 8B EC");
const DELPHI_FRAME_REACH: usize = 12;
const MAX_DELPHI_UNITS: u32 = 100_000;
const DELPHI_UNIT: usize = 8; // init and finalise pointers
const DELPHI_UNITS_CHECKED: usize = 16;
const VC6_ENTRY: &str = hex(concat!(
    "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ",
    "83 EC ?? 53 56 57 89 65 E8 33 DB 89 5D FC 6A ?? 5F 57 ?? ?? ?? ?? ?? ?? 59 ",
    "83 0D ?? ?? ?? ?? FF 83 0D ?? ?? ?? ?? FF",
));
const SUBSYSTEM_GUI: u16 = 2;
const SUBSYSTEM_CONSOLE: u16 = 3;

pub(crate) fn compiler_entry(
    bytes: &[u8],
    model: &PeModel,
    code: &[Range<usize>],
    base: usize,
) -> Option<usize> {
    let x64 = model.kind == PeKind::Pe32Plus;
    let mut recognised = vec![msvc_entry(bytes, code, x64), go_entry(bytes, code, x64)];

    if x64 {
        recognised.push(mingw_entry(bytes, code, model.subsystem));
    } else {
        recognised.extend([
            vb6_entry(bytes, code, base),
            delphi_entry(bytes, code, base),
            sole(hits(bytes, code, VC6_ENTRY)),
        ]);
    }
    settled(recognised)
}

fn settled(recognised: impl IntoIterator<Item = Search<usize>>) -> Option<usize> {
    let mut found = Vec::new();
    for search in recognised {
        match search {
            Search::One(entry) => found.push(entry),
            Search::None => {}
            Search::Several => return None, // one runtime seen twice settles nothing
        }
    }

    let first = *found.first()?;
    found.iter().all(|other| *other == first).then_some(first)
}

fn hits(bytes: &[u8], code: &[Range<usize>], pattern: &str) -> Vec<usize> {
    code.iter()
        .flat_map(|range| {
            let code = bytes.get(range.clone()).unwrap_or_default();
            find_patterns(code, pattern).map(move |offset| range.start + offset)
        })
        .collect()
}

fn msvc_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Search<usize> {
    let (pattern, skip) = if x64 {
        (MSVC_ENTRY_X64, 0)
    } else {
        (MSVC_ENTRY_X86, X86_ENTRY_SKIP)
    };
    let in_code = |at: usize| code.iter().any(|range| range.contains(&at));

    sole(
        hits(bytes, code, pattern)
            .into_iter()
            .map(|at| at + skip)
            .filter(|&entry| cookie_initialiser(bytes, entry, x64).is_some_and(in_code)),
    )
}

// the function the startup stub at entry calls first, when it seeds msvc's security cookie
fn cookie_initialiser(bytes: &[u8], entry: usize, x64: bool) -> Option<usize> {
    let (stub, call) = match x64 {
        true => (MSVC_ENTRY_X64, MSVC_CALL_X64),
        false => (MSVC_STUB_X86, 0),
    };
    let initialiser =
        rel32_target(bytes, entry + call).filter(|_| pattern_at(bytes, entry, stub))?;

    sets_cookie(bytes, initialiser, x64).then_some(initialiser)
}

// the startup stub as msvc links it at entry: call the cookie initialiser, then jump to main
pub(crate) fn msvc_startup_stub(
    entry: usize,
    initialiser: usize,
    main: usize,
    x64: bool,
) -> Option<Vec<u8>> {
    let (pattern, call, jump) = match x64 {
        true => (MSVC_ENTRY_X64, MSVC_CALL_X64, MSVC_JUMP_X64),
        false => (MSVC_STUB_X86, 0, MSVC_JUMP_X86),
    };
    let mut stub: Vec<u8> = pattern
        .split_whitespace()
        .map(|token| u8::from_str_radix(token, 16).unwrap_or_default()) // ?? is a rel32 byte
        .collect();

    // a target before entry wraps, and set_rel32_target's i64 cast makes it negative again
    let from_entry = |target: usize| target.wrapping_sub(entry);
    set_rel32_target(&mut stub, call, from_entry(initialiser))?;
    set_rel32_target(&mut stub, jump, from_entry(main))?;
    Some(stub)
}

// the import slots msvc's startup calls, when the entry point is its mainCRTStartup
pub(crate) fn msvc_startup_slots(bytes: &[u8], entry: usize, x64: bool, base: usize) -> Vec<usize> {
    let jump = if x64 { MSVC_JUMP_X64 } else { MSVC_JUMP_X86 };
    let Some(main) =
        cookie_initialiser(bytes, entry, x64).and_then(|_| rel32_target(bytes, entry + jump))
    else {
        return Vec::new();
    };

    let bits = if x64 { 64 } else { 32 };
    let decode = |at: usize| {
        let reach = at..at.saturating_add(MSVC_MAIN_REACH).min(bytes.len());
        instructions(bytes, base as u64, bits, &reach)
    };
    let through_thunk = |call: &Instruction| {
        let target = usize::try_from(call.near_branch_target())
            .ok()?
            .checked_sub(base)?;
        let jump = decode(target).next()?;
        (jump.mnemonic() == Mnemonic::Jmp).then(|| memory_slot(&jump, base))? // the linker's import thunk
    };

    decode(main)
        .take_while(|insn| !insn.is_invalid() && insn.mnemonic() != Mnemonic::Int3) // padding ends it
        .filter_map(|insn| match insn.flow_control() {
            FlowControl::IndirectCall => memory_slot(&insn, base),
            FlowControl::Call => through_thunk(&insn),
            _ => None,
        })
        .collect()
}

fn memory_slot(insn: &Instruction, base: usize) -> Option<usize> {
    usize::try_from(fixed_address(insn)?)
        .ok()?
        .checked_sub(base)
}

pub(crate) fn sets_cookie(bytes: &[u8], function: usize, x64: bool) -> bool {
    let cookie: &[u8] = if x64 { &COOKIE_X64 } else { &COOKIE_X86 };
    let end = function.saturating_add(COOKIE_REACH).min(bytes.len());
    bytes
        .get(function..end)
        .is_some_and(|body| body.windows(cookie.len()).any(|window| window == cookie))
}

fn mingw_entry(bytes: &[u8], code: &[Range<usize>], subsystem: u16) -> Search<usize> {
    let pattern = match subsystem {
        SUBSYSTEM_CONSOLE => MINGW_CONSOLE_X64,
        SUBSYSTEM_GUI => MINGW_GUI_X64,
        _ => return Search::None,
    };
    sole(hits(bytes, code, pattern))
}

fn go_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Search<usize> {
    let pattern = if x64 { GO_RT0_X64 } else { GO_RT0_X86 };

    sole(hits(bytes, code, pattern)).and_then(|body| {
        sole(
            hits(bytes, code, JUMP)
                .into_iter()
                .filter(|&at| rel32_target(bytes, at) == Some(body)),
        )
    })
}

fn vb6_entry(bytes: &[u8], code: &[Range<usize>], base: usize) -> Search<usize> {
    sole(
        hits(bytes, code, VB6_ENTRY)
            .into_iter()
            .filter(|&at| vb6_header(bytes, at, base).is_some()),
    )
}

pub(crate) fn vb6_data_start(bytes: &[u8], entry: usize, base: usize) -> Option<usize> {
    let header = vb6_header(bytes, entry, base)?;
    let project = absolute_rva(bytes, header + VB6_PROJECT, base)?;
    absolute_rva(bytes, project + VB6_PROJECT_DATA, base) // runtime's .data start
}

fn vb6_header(bytes: &[u8], push: usize, base: usize) -> Option<usize> {
    (*bytes.get(push)? == PUSH_IMM32).then_some(())?;

    let header = absolute_rva(bytes, push + 1, base)?;
    (bytes.get(header..header + VB6_HEADER_MAGIC.len())? == VB6_HEADER_MAGIC).then_some(header)
}

fn delphi_entry(bytes: &[u8], code: &[Range<usize>], base: usize) -> Search<usize> {
    let tables = hits(bytes, code, DELPHI_INIT).into_iter().filter(|&at| {
        absolute_rva(bytes, at + 1, base).is_some_and(|table| init_table(bytes, code, table, base))
    });

    sole(tables).and_then(|init| {
        let reach = init.saturating_sub(DELPHI_FRAME_REACH)..init;
        let before = bytes.get(reach.clone()).unwrap_or_default();
        sole(find_patterns(before, DELPHI_FRAME).map(|offset| reach.start + offset))
    })
}

fn init_table(bytes: &[u8], code: &[Range<usize>], table: usize, base: usize) -> bool {
    let Ok(count) = read_u32(bytes, table) else {
        return false;
    };
    let Some(units) = absolute_rva(bytes, table + 4, base) else {
        return false;
    };
    if !(1..=MAX_DELPHI_UNITS).contains(&count)
        || units + count as usize * DELPHI_UNIT > bytes.len()
    {
        return false;
    }

    let in_code = |rva: usize| code.iter().any(|range| range.contains(&rva));
    let (mut pointers, mut into_code) = (0usize, 0usize);
    for index in 0..(count as usize).min(DELPHI_UNITS_CHECKED) {
        for half in 0..2 {
            let Ok(pointer) = read_u32(bytes, units + index * DELPHI_UNIT + half * 4) else {
                return false;
            };
            if pointer == 0 {
                continue;
            }
            match (pointer as usize).checked_sub(base) {
                Some(rva) if rva < bytes.len() => {
                    pointers += 1;
                    into_code += usize::from(in_code(rva));
                }
                _ => return false,
            }
        }
    }
    into_code >= 2 && into_code * 2 >= pointers
}

fn absolute_rva(bytes: &[u8], at: usize, base: usize) -> Option<usize> {
    let rva = (read_u32(bytes, at).ok()? as usize).checked_sub(base)?;
    (rva < bytes.len()).then_some(rva)
}
