mod aspack;
mod fsg;
mod merged_sections;
mod mew;
mod mpress;
mod pecompact;
mod themida;
mod upx;
mod vmprotect;

use std::ops::Range;

pub(crate) use vmprotect::resource_apis_hooked;

use crate::AppResult;
use crate::pe::bytes::read_u32;
use crate::pe::parse::{map_disk_image, parse_disk_image, parse_memory_image};
use crate::pe::{IMAGE_SCN_MEM_WRITE, PeImage, PeKind, PeModel, TLS_DIRECTORY};
use crate::unpack::x86::branches::rel32_target;
use crate::unpack::x86::opcodes::{JUMP_REL8, JUMP_REL32};
use crate::unpack::{Origin, Unpacked, x86};

const SPLIT_BY_HEADER: &str = "from the header's code fields and table positions";
const NAMED_BY_CONTENTS: &str = "from what each section holds";
const UNPROVEN_FLAGS: &str =
    "permissions not provable for every section, so those got read, write and execute";
const MAX_ENTRY_HOPS: usize = 8;

const LOWEST_MODULE: usize = 0x10000; // nothing maps below 64 KiB

fn resolved_import(value: usize, image: &Range<usize>) -> bool {
    value >= LOWEST_MODULE && !image.contains(&value)
}

/// One packer's module. Only `unpack` is required; the rest tell launch mode where the program's
/// code is and how the stub behaves, and default to "nothing special".
pub(crate) trait Packer: Sync {
    /// Restores an image this packer packed, or returns `None` when the image is not its.
    /// A recognised image that cannot be restored comes back with no image and a report saying why.
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked>;

    /// RVA ranges that will hold the program's own code, read from the image as Windows mapped it,
    /// before the stub ran. Launch mode takes execute rights from them to stop at the entry point.
    fn original_code(&self, _image: &PeImage<'_>, _base: usize) -> Option<Vec<Range<usize>>> {
        None
    }

    /// True when the stub asks the kernel about debuggers in ways a debugger cannot hide,
    /// so launch mode watches from an exception handler inside the process instead.
    fn checks_debugger_directly(&self, _image: &PeImage<'_>) -> bool {
        false
    }

    /// RVA of a stub routine that runs inside the program's code after unpacking, such as
    /// MPRESS's import fixer. Launch mode lets it run and stops where it jumps to the program.
    fn import_fixer(&self, _image: &PeImage<'_>) -> Option<usize> {
        None
    }

    /// Offset, within `code` read from the import fixer's first byte, of the `jmp rel32`
    /// that hands control to the program.
    fn import_fixer_exit(&self, _code: &[u8]) -> Option<usize> {
        None
    }
}

const PACKERS: [&dyn Packer; 8] = [
    &upx::Upx,
    &aspack::Aspack,
    &mpress::Mpress,
    &pecompact::Pecompact,
    &fsg::Fsg,
    &mew::Mew,
    &themida::Themida,
    &vmprotect::Vmprotect,
]; // exact signatures first, wrappers last

pub(crate) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let metered = x86::metered(|| first_unpacked(image, origin));
    let mut unpacked = metered.result?;

    let notes = &mut unpacked.findings.report.notes;
    if metered.ran_dry {
        notes.push(
            "the emulator ran out of steps, so parts that needed it may be missing".to_string(),
        );
    }
    if metered.skipped_system_calls > 0 {
        notes.push(format!(
            "{} system calls in followed packer code were skipped and taken as successful",
            metered.skipped_system_calls
        ));
    }
    if metered.skipped_api_calls > 0 {
        notes.push(format!(
            "{} API calls in followed packer code were skipped with a stand-in result",
            metered.skipped_api_calls
        ));
    }

    Some(unpacked)
}

fn first_unpacked(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let mut detected = None;

    for packer in PACKERS {
        match packer.unpack(image, origin) {
            Some(unpacked) if unpacked.image.is_some() => return Some(unpacked),
            Some(unpacked) => {
                detected.get_or_insert(unpacked);
            }
            None => {}
        }
    }

    detected
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum LayoutBasis {
    KnownPacker,
    StubSection,
    NoPacker,
}

pub(crate) struct ProgramLayout {
    pub(crate) kind: PeKind,
    pub(crate) entry: usize,
    pub(crate) code: Vec<Range<usize>>,
    pub(crate) basis: LayoutBasis,
    pub(crate) fixer: Option<usize>,
    pub(crate) tls_directory: Option<usize>,
}

impl ProgramLayout {
    pub(crate) fn entry_stub_in_code(&self) -> bool {
        self.basis == LayoutBasis::KnownPacker
            && self.code.iter().any(|range| range.contains(&self.entry)) // pecompact starts its stub inside the program's code section
    }
}

pub(crate) fn program_layout(bytes: &[u8], base: usize) -> AppResult<ProgramLayout> {
    let image = parse_memory_image(bytes)?;
    let model = image.model();
    let entry = read_u32(bytes, model.entry_point_offset)? as usize;
    let (code, basis) = program_code(&image, base, entry);
    let tls_directory = model
        .directory(bytes, TLS_DIRECTORY)
        .map(|directory| directory.rva().as_usize());

    Ok(ProgramLayout {
        kind: model.kind,
        entry,
        code,
        basis,
        fixer: PACKERS
            .iter()
            .find_map(|packer| packer.import_fixer(&image)),
        tls_directory,
    })
}

pub(crate) fn checks_debugger_directly(file: &[u8]) -> bool {
    let Some(mapped) = parse_disk_image(file)
        .ok()
        .and_then(|image| map_disk_image(file, image.model().image_size as usize))
    else {
        return false;
    };

    parse_memory_image(&mapped).is_ok_and(|image| {
        PACKERS
            .iter()
            .any(|packer| packer.checks_debugger_directly(&image))
    })
}

pub(crate) fn fixer_exit(code: &[u8]) -> Option<usize> {
    PACKERS
        .iter()
        .find_map(|packer| packer.import_fixer_exit(code))
}

fn program_code(
    image: &PeImage<'_>,
    base: usize,
    entry: usize,
) -> (Vec<Range<usize>>, LayoutBasis) {
    let packer = PACKERS
        .iter()
        .rev() // a wrapper's layout wins
        .find_map(|packer| packer.original_code(image, base));
    if let Some(code) = packer {
        return (code, LayoutBasis::KnownPacker);
    }

    let sections = &image.model().sections;
    let parts: Vec<_> = sections
        .iter()
        .map(|section| SectionPart {
            range: section.range(),
            executable: section.is_executable(),
            writable: section.characteristics() & IMAGE_SCN_MEM_WRITE != 0,
            on_disk: section.raw_size != 0,
        })
        .collect();

    match beside_stub(&parts, entry) {
        Some(code) => {
            let hops = entry_jumps(image.bytes(), entry); // the entry's own jumps lead on through the packer
            let program = code
                .into_iter()
                .filter(|range| !hops.iter().any(|hop| range.contains(hop)))
                .collect();
            (program, LayoutBasis::StubSection)
        }
        None => {
            let code = parts.into_iter().map(|part| part.range).collect();
            (code, LayoutBasis::NoPacker)
        }
    }
}

struct SectionPart {
    range: Range<usize>,
    executable: bool,
    writable: bool,
    on_disk: bool,
}

// where the entry goes by unconditional direct jumps before any other instruction runs
fn entry_jumps(bytes: &[u8], entry: usize) -> Vec<usize> {
    let mut hops = Vec::new();
    let mut at = entry;
    while hops.len() < MAX_ENTRY_HOPS {
        let next = match bytes.get(at) {
            Some(&JUMP_REL32) => rel32_target(bytes, at),
            Some(&JUMP_REL8) => bytes
                .get(at + 1)
                .and_then(|displacement| (at + 2).checked_add_signed(*displacement as i8 as isize)),
            _ => None,
        };
        let Some(next) = next.filter(|next| *next < bytes.len() && !hops.contains(next)) else {
            break;
        };
        hops.push(next);
        at = next;
    }
    hops
}

fn beside_stub(parts: &[SectionPart], entry: usize) -> Option<Vec<Range<usize>>> {
    let stub = parts
        .iter()
        .find(|part| part.range.contains(&entry))
        .filter(|part| part.writable)?; // old packers omit the execute flag
    let beside: Vec<_> = parts
        .iter()
        .filter(|part| part.range != stub.range)
        .collect();

    let first = parts.first()?;
    let unpacked_into = first.range != stub.range && !first.on_disk; // empty on disk: filled at run time
    (unpacked_into || beside.iter().any(|part| part.executable))
        .then(|| beside.iter().map(|part| part.range.clone()).collect())
}

pub(crate) fn sections_before(
    bytes: &[u8],
    model: &PeModel,
    end: usize,
    executable: bool,
) -> Vec<Range<usize>> {
    model
        .sections
        .iter()
        .filter(|section| section.is_executable() == executable)
        .map(|section| section.range().start..section.range().end.min(bytes.len()))
        .filter(|range| range.start < end && range.start < range.end)
        .collect()
}
