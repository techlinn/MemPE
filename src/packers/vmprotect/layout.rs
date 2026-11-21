use std::ops::Range;

use super::OWN_SECTIONS;
use crate::packers::sections_before;
use crate::pe::bytes::{entropy, read_u32};
use crate::pe::{
    DELAY_IMPORT_DIRECTORY, EXCEPTION_DIRECTORY, IMAGE_SCN_MEM_WRITE, IMPORT_DIRECTORY,
    LOAD_CONFIG_DIRECTORY, PeImage, PeModel, Rva, SectionModel, TLS_DIRECTORY,
};
use crate::unpack::x86::branches::{CALL_REL32, rel32_target};
use crate::unpack::x86::opcodes::PUSH_IMM32;

const SECTION_PREFIX: &[u8] = b".vmp";
const MIN_VM_SECTION: u32 = 0x1_0000;
const MAX_RUNTIME_DATA: u32 = 0x1000;
const PACKED_ENTROPY: f64 = 6.5; // payload entropy vs code
const ENTROPY_STEP: usize = 4;
const PUSH_IMM32_LEN: usize = 5;
const VM_SECTIONS: usize = 3;
const COMPANION_DIRECTORIES: [usize; 4] = [
    EXCEPTION_DIRECTORY,
    TLS_DIRECTORY,
    LOAD_CONFIG_DIRECTORY,
    DELAY_IMPORT_DIRECTORY,
];

pub(super) struct Layout {
    pub(super) code: Vec<Range<usize>>,
    pub(super) block: Range<usize>,
    pub(super) sections: Vec<Range<usize>>,
    pub(super) stubs: Option<Range<usize>>, // by position and size: unconfirmed
    pub(super) undersized: Option<Range<usize>>, // same position, under the size bar
    pub(super) vmp_marks: bool, // vmp's names, numbered names, section roles, or a push-and-call entry
    pub(super) runtime_data: bool,
}

impl Layout {
    pub(super) fn of(image: &PeImage<'_>) -> Option<Self> {
        let bytes = image.bytes();
        let model = image.model();

        let (entry, vm) = vm_section(bytes, model)?;
        let candidate = stub_candidate(model, entry);
        let stubs = candidate
            .filter(|section| section.span() >= MIN_VM_SECTION)
            .map(SectionModel::range);
        let payload = payload_start(bytes, model, &vm, stubs.as_ref());
        let block = payload..vm.end;

        let undersized = candidate
            .filter(|section| section.span() < MIN_VM_SECTION)
            .map(SectionModel::range)
            .filter(|section| section.start < payload);

        Some(Self {
            code: sections_before(bytes, model, payload, true),
            sections: model
                .sections
                .iter()
                .map(SectionModel::range)
                .filter(|section| block.contains(&section.start))
                .collect(),
            stubs,
            undersized,
            vmp_marks: named(model, entry)
                || numbered(model, entry)
                || vm_sections(model, entry)
                || entry_calls_vm(bytes, model, &block),
            runtime_data: runtime_data(model, entry),
            block,
        })
    }

    pub(super) fn payload(&self) -> usize {
        self.block.start
    }
}

fn vm_section(bytes: &[u8], model: &PeModel) -> Option<(usize, Range<usize>)> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()?;
    let (index, section) = model
        .sections
        .iter()
        .enumerate()
        .find(|(_, section)| section.contains_rva(Rva(entry)))?;

    let vm = section.range();
    let shaped = index > 0 && section.span() >= MIN_VM_SECTION && section.is_executable();
    let holds = |directory: usize| {
        model
            .directory(bytes, directory)
            .is_some_and(|data| vm.contains(&data.rva().as_usize()))
    };

    let companions = COMPANION_DIRECTORIES.into_iter().any(&holds); // vmp moves these beside the entry point

    (shaped && holds(IMPORT_DIRECTORY) && (companions || packed(bytes, &vm))).then_some((index, vm))
}

fn packed(bytes: &[u8], section: &Range<usize>) -> bool {
    bytes
        .get(section.start..section.end.min(bytes.len()))
        .is_some_and(|data| entropy(data.iter().step_by(ENTROPY_STEP)) >= PACKED_ENTROPY)
}

fn stub_candidate(model: &PeModel, entry: usize) -> Option<&SectionModel> {
    let sections = &model.sections;

    (1..entry)
        .rev()
        .map(|index| &sections[index])
        .find(|section| section.is_executable()) // vmp data between entry and stubs
}

fn payload_start(
    bytes: &[u8],
    model: &PeModel,
    vm: &Range<usize>,
    stubs: Option<&Range<usize>>,
) -> usize {
    if let Some(stubs) = stubs {
        return stubs.start.min(vm.start);
    }

    let first = model
        .sections
        .first()
        .map_or(0, |section| section.virtual_address().as_usize());

    let mut start = vm.start;
    for section in &model.sections {
        let range = section.range();
        let candidate = range.start != first && section.is_executable() && range.start < start;
        if candidate && packed(bytes, &range) {
            start = range.start;
        }
    }
    start
}

fn runtime_data(model: &PeModel, entry: usize) -> bool {
    entry.checked_sub(1).is_some_and(|before| {
        let data = &model.sections[before];
        !data.is_executable() && data.span() <= MAX_RUNTIME_DATA // vm state page before the vm
    })
}

fn named(model: &PeModel, entry: usize) -> bool {
    packer_named(model.sections[entry].name())
}

// vmp names its three sections from one setting plus 0, 1 and 2 (detect it easy's collision rule)
fn numbered(model: &PeModel, entry: usize) -> bool {
    let names: Option<Vec<&[u8]>> = (0..VM_SECTIONS)
        .map(|offset| {
            let index = (entry + offset + 1).checked_sub(VM_SECTIONS)?;
            let name = model.sections.get(index)?.name();
            let length = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len());
            name.get(..length)
        })
        .collect();
    let Some(names) = names else {
        return false;
    };

    fn prefix(name: &[u8]) -> Option<&[u8]> {
        name.split_last().map(|(_, prefix)| prefix)
    }
    names.iter().enumerate().all(|(index, name)| {
        name.last() == Some(&(b'0' + index as u8)) && prefix(name) == prefix(names[0])
    })
}

// vmp appends its vm code (empty on disk, read only), its vm state, then its loader with the entry
fn vm_sections(model: &PeModel, entry: usize) -> bool {
    let sections = &model.sections;
    let (Some(code), Some(state), Some(loader)) = (
        entry.checked_sub(2).and_then(|index| sections.get(index)),
        entry.checked_sub(1).and_then(|index| sections.get(index)),
        sections.get(entry),
    ) else {
        return false;
    };
    let writable = |section: &SectionModel| section.characteristics() & IMAGE_SCN_MEM_WRITE != 0;

    code.is_executable()
        && !writable(code)
        && code.raw_size == 0
        && code.span() >= MIN_VM_SECTION
        && !state.is_executable()
        && writable(state)
        && state.span() <= MAX_RUNTIME_DATA
        && !writable(loader)
}

fn packer_named(name: &[u8; 8]) -> bool {
    name.starts_with(SECTION_PREFIX) && !OWN_SECTIONS.contains(&name)
}

fn entry_calls_vm(bytes: &[u8], model: &PeModel, block: &Range<usize>) -> bool {
    let Ok(entry) = read_u32(bytes, model.entry_point_offset) else {
        return false;
    };
    let push = entry as usize;
    let call = push + PUSH_IMM32_LEN;

    bytes.get(push) == Some(&PUSH_IMM32)
        && bytes.get(call) == Some(&CALL_REL32)
        && rel32_target(bytes, call).is_some_and(|target| block.contains(&target))
}
