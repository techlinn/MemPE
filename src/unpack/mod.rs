pub(crate) mod codecs;
pub(crate) mod initial_data;
pub(crate) mod packer_report;
pub(crate) mod tables;
pub(crate) mod wrapped_imports;
pub(crate) mod x86;

use std::cell::OnceCell;
use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::Path;

pub(crate) use initial_data::FreshCopy;
pub(crate) use packer_report::{PackerId, PackerReport, Part, State};

use crate::pe::bytes::read_pointer;
use crate::pe::exports::ExportIndex;
pub(crate) use crate::pe::import_list::{ImportedFunction, ModuleImports, NameHint, NameHints};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::process_memory::ProcessMemory;
use crate::pe::{IMAGE_SCN_MEM_WRITE, PeModel};

pub(crate) const PACKER_HEADER_BYTES: &str =
    "the packer's own bytes after the section table were cleared back to the linker's zero fill";
pub(crate) use initial_data::{InitialData, with_initial_data};
pub(crate) use x86::{find_pattern, find_patterns, hex, pattern_at};

const MAX_PACKED_FILE: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum HeaderSource {
    Memory,
    Disk,
}

pub(crate) struct Origin<'a> {
    pub(crate) base: usize,
    pub(crate) headers: HeaderSource,
    pub(crate) file: Option<&'a Path>,
    pub(crate) exports: &'a ExportIndex,
    pub(crate) memory: &'a ProcessMemory<'a>,
    pub(crate) disk: OnceCell<Option<Vec<u8>>>,
}

pub(crate) fn file_base(file: &[u8], model: &PeModel) -> Option<usize> {
    read_pointer(file, model.image_base_offset, model.kind).ok()
}

impl Origin<'_> {
    pub(crate) fn read_file(&self) -> Option<&[u8]> {
        let read = || {
            let file = File::open(self.file?).ok()?;
            let fits = file.metadata().ok()?.len() <= MAX_PACKED_FILE;
            fits.then_some(())?; // a cut file would parse as a different one

            let mut bytes = Vec::new();
            file.take(MAX_PACKED_FILE).read_to_end(&mut bytes).ok()?;
            Some(bytes)
        };
        self.disk.get_or_init(read).as_deref()
    }

    pub(crate) fn linked_base(&self) -> Option<usize> {
        let file = self.read_file()?;
        let disk = parse_disk_image(file).ok()?;
        file_base(file, disk.model())
    }

    // a packer may rewrite its section flags after the loader mapped them
    pub(crate) fn writable_sections(&self, memory: &PeModel) -> Vec<Range<usize>> {
        let writable = |model: &PeModel| -> Vec<Range<usize>> {
            model
                .sections
                .iter()
                .filter(|section| section.characteristics() & IMAGE_SCN_MEM_WRITE != 0)
                .map(|section| section.range())
                .collect()
        };

        let file = self
            .read_file()
            .and_then(|file| parse_disk_image(file).ok());
        let mapped = file
            .as_ref()
            .filter(|disk| disk.model().image_size == memory.image_size)
            .map(|disk| writable(disk.model()))
            .unwrap_or_default();

        let mut sections = writable(memory);
        sections.extend(mapped);
        sections
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Refusal(pub(crate) &'static str);

pub(crate) type Step<T> = Result<T, Refusal>;

pub(crate) fn need<T>(value: Option<T>, why: &'static str) -> Step<T> {
    value.ok_or(Refusal(why))
}

pub(crate) struct Unpacked {
    pub(crate) image: Option<Vec<u8>>,
    pub(crate) findings: PackerFindings,
    pub(crate) fresh: Option<FreshCopy>,
}

impl Unpacked {
    pub(crate) fn refused(packer: PackerId, version: Option<String>, refusal: Refusal) -> Self {
        Self::detected_only(packer, version, refusal.0)
    }

    pub(crate) fn restored(
        image: Vec<u8>,
        report: PackerReport,
        imports: Option<PackerImports>,
        fresh: Option<FreshCopy>,
    ) -> Step<Self> {
        need(
            parse_memory_image(&image).ok(),
            "the restored image does not parse",
        )?;

        Ok(Self {
            image: Some(image),
            findings: PackerFindings {
                report,
                imports: imports.unwrap_or(PackerImports::Unknown),
                packer_ranges: Vec::new(),
            },
            fresh,
        })
    }

    pub(crate) fn detected_only(
        packer: PackerId,
        version: Option<String>,
        reason: &'static str,
    ) -> Self {
        let mut report = PackerReport::new(packer, version);
        report.failed_with(Part::Image, reason);
        Self {
            image: None,
            findings: PackerFindings {
                report,
                imports: PackerImports::Unknown,
                packer_ranges: Vec::new(),
            },
            fresh: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct PackerFindings {
    pub(crate) report: PackerReport,
    pub(crate) imports: PackerImports,
    pub(crate) packer_ranges: Vec<Range<usize>>, // its own sections left in the image: no program import lives there
}

#[derive(Clone)]
pub(crate) enum PackerImports {
    Intact,
    Listed(Vec<ModuleImports>),
    FilledIat {
        rva: u32,
        size: u32,
        names: NameHints,
    },
    Unknown,
}

pub(crate) fn counted(count: usize, one: &str, many: &str) -> String {
    match count {
        1 => format!("1 {one}"),
        count => format!("{count} {many}"),
    }
}
