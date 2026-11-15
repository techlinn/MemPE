use std::collections::BTreeSet;
use std::ops::Range;

use super::Packed;
use crate::pe::PeKind;
use crate::pe::image::{read_pointer, write_u32};
use crate::pe::packers::PackerReport;
use crate::pe::packers::branches::{CALL_REL32, JUMP_REL32, REL32_LEN, rel32_target};
use crate::pe::packers::emu::Destination;
use crate::pe::packers::entry::compiler_entry;
use crate::pe::packers::tables::unique;

const MAX_ENTRY_CANDIDATES: usize = 64;
const MAX_STORED_POINTERS: usize = 16;
const FUNCTION_PADDING: [u8; 3] = [0xCC, 0x90, 0xC3];
const COOKIE_X86: [u8; 4] = 0xBB40_E64E_u32.to_le_bytes(); // msvc's default security cookie
const COOKIE_X64: [u8; 8] = 0x0000_2B99_2DDF_A232_u64.to_le_bytes();
const COOKIE_REACH: usize = 0x80; // __security_init_cookie compares with the default near its start
const STARTUP_FRAME_X64: [u8; 4] = [0x48, 0x83, 0xEC, 0x28]; // sub rsp, 28h around the cookie call
const STARTUP_UNFRAME_X64: [u8; 4] = [0x48, 0x83, 0xC4, 0x28];
const STARTUP_LANDINGS: usize = 2; // the call to __security_init_cookie, then the jump to __scrt_common_main_seh

pub(super) fn restore(
    restored: &mut [u8],
    packed: &Packed<'_>,
    report: &mut PackerReport,
) -> Option<usize> {
    let model = packed.model();
    let code = packed.code();
    let compiled = compiler_entry(restored, model, code, packed.origin.base);
    let obfuscated = match compiled {
        Some(_) => None,
        None => obfuscated_entry(packed, code),
    };
    let stored = || stored_entry(restored, packed, code);
    let entry = compiled.or(obfuscated).or_else(stored);

    let written = entry
        .and_then(|entry| u32::try_from(entry).ok())
        .is_some_and(|entry| write_u32(restored, model.entry_point_offset, entry).is_ok());
    let entry = entry.filter(|_| written);
    let rebuilt = obfuscated
        .filter(|_| written)
        .and_then(|at| msvc_startup(restored, packed, code, at));

    match (entry, obfuscated, rebuilt) {
        (None, _, _) => report.unrestored.push(
            "original entry point (no known runtime entry, no jump into themida, and no single address themida kept for it)",
        ),
        (Some(_), None, _) => report.restored.push("original entry point"),
        (Some(_), Some(_), Some(())) => {
            report.restored.push("original entry point");
            report.restored.push("the entry point's first instructions (msvc startup, rebuilt from where themida's virtual machine went)");
        }
        (Some(_), Some(_), None) => {
            report.restored.push("original entry point");
            report
                .lost
                .push("the entry point's first instructions (virtualized)");
        }
    }

    entry
}

fn obfuscated_entry(packed: &Packed<'_>, code: &[Range<usize>]) -> Option<usize> {
    let bytes = packed.image.bytes();
    let snapshot = packed.snapshot();
    let engine = &packed.layout.engine;
    let vm = packed.engine();
    let enters_vm = |at: &usize| {
        snapshot.destination(snapshot.base + *at as u64, &vm) == Some(Destination::VirtualMachine)
    }; // data inside a code section can look like a jump too

    let jumps = code.iter().flat_map(|range| range.clone()).filter(|at| {
        starts_function(bytes, code, *at)
            && bytes.get(*at) == Some(&JUMP_REL32)
            && rel32_target(bytes, *at).is_some_and(|target| engine.contains(&target))
    });

    unique(jumps.take(MAX_ENTRY_CANDIDATES).filter(enters_vm)) // several would be macro entries, which say nothing about the entry point
}

fn stored_entry(bytes: &[u8], packed: &Packed<'_>, code: &[Range<usize>]) -> Option<usize> {
    let kind = packed.kind();
    let variables = &packed.layout.variables;
    let engine = bytes.get(variables.start..variables.end.min(bytes.len()))?;
    let in_code = |rva: usize| code.iter().any(|range| range.contains(&rva));

    let mut pointed = BTreeSet::new();
    for window in engine.windows(kind.pointer_width()) {
        let value = read_pointer(window, 0, kind).ok()?;
        let Some(rva) = value
            .checked_sub(packed.origin.base)
            .filter(|rva| in_code(*rva))
        else {
            continue;
        };

        pointed.insert(rva);
        if pointed.len() > MAX_STORED_POINTERS {
            return None; // in a large 32-bit program chance alone points this often, and proves nothing
        }
    }

    let called: BTreeSet<usize> = code
        .iter()
        .flat_map(|range| range.clone())
        .filter(|at| matches!(bytes.get(*at), Some(&CALL_REL32 | &JUMP_REL32)))
        .filter_map(|at| rel32_target(bytes, at))
        .collect();

    unique(
        pointed
            .into_iter()
            .filter(|rva| starts_function(bytes, code, *rva) && !called.contains(rva)), // nothing in a program calls its own entry point
    )
}

fn msvc_startup(
    restored: &mut [u8],
    packed: &Packed<'_>,
    code: &[Range<usize>],
    entry: usize,
) -> Option<()> {
    let snapshot = packed.snapshot();
    let base = snapshot.base;
    let native: Vec<Range<u64>> = code
        .iter()
        .map(|range| base + range.start as u64..base + range.end as u64)
        .collect();
    let landings = snapshot.native_landings(base + entry as u64, &native, &|found| {
        found.len() == STARTUP_LANDINGS
    })?;
    let [cookie, main] = landings[..] else {
        return None;
    };
    let cookie = usize::try_from(cookie.address.checked_sub(base)?).ok()?;
    let main = usize::try_from(main.address.checked_sub(base)?).ok()?;

    let (constant, frame, unframe): (&[u8], &[u8], &[u8]) = match packed.kind() {
        PeKind::Pe32 => (&COOKIE_X86, &[], &[]),
        PeKind::Pe32Plus => (&COOKIE_X64, &STARTUP_FRAME_X64, &STARTUP_UNFRAME_X64),
    };
    let sets_cookie = restored
        .get(cookie..cookie + COOKIE_REACH)
        .is_some_and(|body| {
            body.windows(constant.len())
                .any(|window| window == constant)
        });
    if !sets_cookie {
        return None;
    }

    let call_at = entry + frame.len();
    let jump_at = call_at + REL32_LEN + unframe.len();
    let rel = |from: usize, to: usize| i32::try_from(to as i64 - (from + REL32_LEN) as i64).ok();
    let stub = [
        frame,
        &[CALL_REL32],
        &rel(call_at, cookie)?.to_le_bytes(),
        unframe,
        &[JUMP_REL32],
        &rel(jump_at, main)?.to_le_bytes(),
    ]
    .concat();

    restored
        .get_mut(entry..entry + stub.len())?
        .copy_from_slice(&stub);
    Some(())
}

fn starts_function(bytes: &[u8], code: &[Range<usize>], at: usize) -> bool {
    code.iter().any(|range| range.start == at)
        || at
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .is_some_and(|before| FUNCTION_PADDING.contains(before))
}
