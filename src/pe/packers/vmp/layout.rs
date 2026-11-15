use std::ops::Range;

use crate::pe::image::read_u32;
use crate::pe::packers::branches::{CALL_REL32, rel32_target};
use crate::pe::{
    DELAY_IMPORT_DIRECTORY, EXCEPTION_DIRECTORY, IMPORT_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeImage,
    PeModel, Rva, SectionModel, TLS_DIRECTORY,
};

const SECTION_PREFIX: &[u8] = b".vmp";
const MIN_VM_SECTION: u32 = 0x1_0000; // the vm section dwarfs the original ones
const PACKED_ENTROPY: f64 = 6.5; // vmp payload sections are near random and the original code sits well below
const ENTROPY_STEP: usize = 4;
const PUSH_IMM32: u8 = 0x68;
const PUSH_IMM32_LEN: usize = 5;
const COMPANION_DIRECTORIES: [usize; 4] = [
    EXCEPTION_DIRECTORY,
    TLS_DIRECTORY,
    LOAD_CONFIG_DIRECTORY,
    DELAY_IMPORT_DIRECTORY,
];

pub(super) struct Layout {
    pub(super) code: Vec<Range<usize>>,
    pub(super) block: Range<usize>, // vmp's sections, up to the end of the one the packed entry point is in
    pub(super) sections: Vec<Range<usize>>,
    pub(super) stubs: Option<Range<usize>>,
    pub(super) signed: bool, // default section names, or an entry point that pushes a handler key and calls the vm
}

impl Layout {
    pub(super) fn of(image: &PeImage<'_>) -> Option<Self> {
        let bytes = image.bytes();
        let model = image.model();

        let vm = vm_section(bytes, model)?;
        let stubs = stub_section(model, &vm);
        let payload = payload_start(bytes, model, &vm, stubs.as_ref());
        let block = payload..vm.end;

        Some(Self {
            code: program_code(bytes, model, payload),
            sections: model
                .sections()
                .iter()
                .map(SectionModel::range)
                .filter(|section| block.contains(&section.start))
                .collect(),
            stubs,
            signed: named(model) || entry_calls_vm(bytes, model, &block),
            block,
        })
    }

    pub(super) fn payload(&self) -> usize {
        self.block.start
    }
}

fn vm_section(bytes: &[u8], model: &PeModel) -> Option<Range<usize>> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()?;
    let (index, section) = model
        .sections()
        .iter()
        .enumerate()
        .find(|(_, section)| section.contains_rva(Rva(entry)))?;

    let vm = section.range();
    let shaped = index > 0 && section.span() >= MIN_VM_SECTION && section.is_executable();
    let holds = |directory: usize| {
        model
            .directory(bytes, directory)
            .ok()
            .flatten()
            .is_some_and(|data| vm.contains(&data.rva().as_usize()))
    };

    let companions = COMPANION_DIRECTORIES.into_iter().any(&holds); // vmp moves these into the same appended section as the entry point
    let packed = || {
        bytes
            .get(vm.start..vm.end.min(bytes.len()))
            .is_some_and(|data| entropy(data) >= PACKED_ENTROPY)
    }; // a minimal x86 program has no companion directory to confirm it

    (shaped && holds(IMPORT_DIRECTORY) && (companions || packed())).then_some(vm)
}

fn stub_section(model: &PeModel, vm: &Range<usize>) -> Option<Range<usize>> {
    let sections = model.sections();
    let entry = sections
        .iter()
        .position(|section| section.virtual_address().as_usize() == vm.start)?;
    let section = (1..entry)
        .rev()
        .map(|index| &sections[index])
        .find(|section| section.is_executable())?; // vmp's data section sits between the entry point's section and the one holding the stubs

    (section.span() >= MIN_VM_SECTION).then(|| section.range())
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
        .sections()
        .first()
        .map_or(0, |section| section.virtual_address().as_usize());
    let packed = |section: &Range<usize>| {
        bytes
            .get(section.start..section.end.min(bytes.len()))
            .is_some_and(|data| entropy(data) >= PACKED_ENTROPY)
    };

    let mut start = vm.start;
    for section in model.sections() {
        let range = section.range();
        let candidate = range.start != first && section.is_executable() && range.start < start;
        if candidate && packed(&range) {
            start = range.start;
        }
    }
    start
}

fn program_code(bytes: &[u8], model: &PeModel, payload: usize) -> Vec<Range<usize>> {
    model
        .sections()
        .iter()
        .filter(|section| section.is_executable())
        .map(|section| section.range().start..section.range().end.min(bytes.len()))
        .filter(|range| range.start < payload && range.start < range.end)
        .collect()
}

fn named(model: &PeModel) -> bool {
    model
        .sections()
        .iter()
        .any(|section| section.name().starts_with(SECTION_PREFIX))
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

fn entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for byte in data.iter().step_by(ENTROPY_STEP) {
        counts[*byte as usize] += 1;
    }

    let total = counts.iter().sum::<u64>() as f64;
    -counts
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let share = *count as f64 / total;
            share * share.log2()
        })
        .sum::<f64>()
}
