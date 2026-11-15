use std::ops::Range;

use super::branches::rel32_target;
use super::find_patterns;
use super::tables::unique;
use crate::pe::image::{read_u16, read_u32};
use crate::pe::{PeKind, PeModel};

const MSVC_ENTRY_X64: &str = "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ??"; // the msvc mainCRTStartup still native under vmp
const MSVC_ENTRY_X86: &str = "CC CC E8 ?? ?? ?? ?? E9 ?? ?? ?? ??"; // __security_init_cookie then a tail jump into __scrt_common_main_seh
const X86_ENTRY_SKIP: usize = 2; // the match starts at the int3 padding before the prologue
const MINGW_CONSOLE_X64: &str =
    "48 83 EC 28 48 8B 05 ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? 90 90 48 83 C4 28 C3"; // mingw stores __mingw_app_type 0
const MINGW_GUI_X64: &str =
    "48 83 EC 28 48 8B 05 ?? ?? ?? ?? C7 00 01 00 00 00 E8 ?? ?? ?? ?? 90 90 48 83 C4 28 C3"; // the same storing 1 for WinMainCRTStartup
const GO_RT0_X64: &str = "48 8B 3C 24 48 8D 74 24 08 E9"; // the go _rt0_amd64 handing argc/argv on to rt0_go
const GO_RT0_X86: &str = "83 EC 08 8B 44 24 08 8D 5C 24 0C 89 04 24 89 5C 24 04 E9";
const VB6_ENTRY: &str = "68 ?? ?? ?? ?? E8 ?? ?? ?? ??"; // push offset VBHeader then call ThunRTMain
const VB6_HEADER_MAGIC: &[u8; 4] = b"VB5!";
const DELPHI_INIT: &str = "B8 ?? ?? ?? ?? E8"; // mov eax offset InitTable then call @InitExe
const DELPHI_FRAME: &str = "55 8B EC"; // matched apart from the call where the locals between them vary
const DELPHI_FRAME_REACH: usize = 12;
const MAX_DELPHI_UNITS: u32 = 100_000;
const VC6_ENTRY: &str = concat!(
    "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ",
    "83 EC ?? 53 56 57 89 65 E8 33 DB 89 5D FC 6A ?? 5F 57 ?? ?? ?? ?? ?? ?? 59 ",
    "83 0D ?? ?? ?? ?? FF 83 0D ?? ?? ?? ?? FF",
);
const SUBSYSTEM_FROM_IMAGE_SIZE: usize = 12;
const SUBSYSTEM_GUI: u16 = 2;
const SUBSYSTEM_CONSOLE: u16 = 3;

pub(super) fn compiler_entry(
    bytes: &[u8],
    model: &PeModel,
    code: &[Range<usize>],
    base: usize,
) -> Option<usize> {
    let x64 = model.kind() == PeKind::Pe32Plus;
    let subsystem = read_u16(
        bytes,
        model.size_of_image_offset + SUBSYSTEM_FROM_IMAGE_SIZE,
    )
    .ok()?;

    let candidates = [
        msvc_entry(bytes, code, x64),
        mingw_entry(bytes, code, x64, subsystem),
        go_entry(bytes, code, x64),
        vb6_entry(bytes, code, x64, base),
        delphi_entry(bytes, code, x64, base),
        vc6_entry(bytes, code, x64),
    ];

    let mut found = candidates.into_iter().flatten();
    let first = found.next()?;
    found.all(|other| other == first).then_some(first) // recognisers that disagree are all distrusted rather than guessed between
}

fn hits(bytes: &[u8], code: &[Range<usize>], pattern: &str) -> Vec<usize> {
    code.iter()
        .flat_map(|range| {
            find_patterns(&bytes[range.clone()], pattern).map(move |offset| range.start + offset)
        })
        .collect()
}

fn msvc_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Option<usize> {
    let (pattern, skip) = if x64 {
        (MSVC_ENTRY_X64, 0)
    } else {
        (MSVC_ENTRY_X86, X86_ENTRY_SKIP)
    };
    unique(hits(bytes, code, pattern)).map(|at| at + skip)
}

fn mingw_entry(bytes: &[u8], code: &[Range<usize>], x64: bool, subsystem: u16) -> Option<usize> {
    let pattern = match subsystem {
        SUBSYSTEM_CONSOLE => MINGW_CONSOLE_X64,
        SUBSYSTEM_GUI => MINGW_GUI_X64,
        _ => return None,
    };
    if !x64 {
        return None;
    }
    unique(hits(bytes, code, pattern))
}

fn go_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Option<usize> {
    let body = unique(hits(bytes, code, if x64 { GO_RT0_X64 } else { GO_RT0_X86 }))?;
    unique(
        hits(bytes, code, "E9 ?? ?? ?? ??")
            .into_iter()
            .filter(|&at| rel32_target(bytes, at) == Some(body)),
    )
}

fn vb6_entry(bytes: &[u8], code: &[Range<usize>], x64: bool, base: usize) -> Option<usize> {
    if x64 {
        return None;
    }
    unique(hits(bytes, code, VB6_ENTRY).into_iter().filter(|&at| {
        absolute_rva(bytes, at + 1, base)
            .and_then(|header| bytes.get(header..header + VB6_HEADER_MAGIC.len()))
            .is_some_and(|magic| magic == VB6_HEADER_MAGIC)
    }))
}

fn delphi_entry(bytes: &[u8], code: &[Range<usize>], x64: bool, base: usize) -> Option<usize> {
    if x64 {
        return None;
    }
    let init = unique(hits(bytes, code, DELPHI_INIT).into_iter().filter(|&at| {
        absolute_rva(bytes, at + 1, base).is_some_and(|table| init_table(bytes, code, table, base))
    }))?;

    let reach = init.saturating_sub(DELPHI_FRAME_REACH)..init;
    unique(find_patterns(&bytes[reach.clone()], DELPHI_FRAME).map(|offset| reach.start + offset))
}

fn init_table(bytes: &[u8], code: &[Range<usize>], table: usize, base: usize) -> bool {
    let Ok(count) = read_u32(bytes, table) else {
        return false;
    };
    let Some(units) = absolute_rva(bytes, table + 4, base) else {
        return false;
    };
    if !(1..=MAX_DELPHI_UNITS).contains(&count) || units + count as usize * 8 > bytes.len() {
        return false;
    }

    let in_code = |rva: usize| code.iter().any(|range| range.contains(&rva));
    let (mut pointers, mut into_code) = (0usize, 0usize);
    for index in 0..(count as usize).min(16) {
        for half in 0..2 {
            let Ok(pointer) = read_u32(bytes, units + index * 8 + half * 4) else {
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
    into_code >= 2 && into_code * 2 >= pointers // a stray mov eax imm then call never points most of a table into code
}

fn vc6_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Option<usize> {
    if x64 {
        return None;
    }
    unique(hits(bytes, code, VC6_ENTRY))
}

fn absolute_rva(bytes: &[u8], at: usize, base: usize) -> Option<usize> {
    let rva = (read_u32(bytes, at).ok()? as usize).checked_sub(base)?;
    (rva < bytes.len()).then_some(rva)
}
