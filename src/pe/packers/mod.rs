mod aspack;
mod codecs;
mod fsg;
mod mpress;
mod pecompact;
mod tables;
mod upx;

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::pe::PeImage;
use tables::Restoration;

type Unpacker = fn(&PeImage<'_>, &Origin<'_>) -> Option<Unpacked>;

const MAX_PACKED_FILE: u64 = 512 * 1024 * 1024;

const UNPACKERS: [Unpacker; 5] = [
    upx::unpack,
    aspack::unpack,
    mpress::unpack,
    pecompact::unpack,
    fsg::unpack,
];

#[derive(Clone, Copy)]
pub(super) enum HeaderSource {
    Memory,
    Disk,
}

pub(super) struct Origin<'a> {
    pub(super) base: usize,
    pub(super) headers: HeaderSource,
    pub(super) file: Option<&'a Path>,
}

impl Origin<'_> {
    fn read_file(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(self.file?)
            .ok()?
            .take(MAX_PACKED_FILE)
            .read_to_end(&mut bytes)
            .ok()?;
        Some(bytes)
    }
}

pub(super) struct Unpacked {
    pub(super) image: Option<Vec<u8>>,
    pub(super) findings: PackerFindings,
    pub(super) fresh: Option<FreshImage>,
}

pub(super) struct FreshImage {
    pub(super) bytes: Vec<u8>,
    pub(super) changed: usize,
}

impl Unpacked {
    fn detected_only(name: &'static str, version: Option<String>, reason: &'static str) -> Self {
        let mut report = PackerReport::new(name, version);
        report.unrestored.push(reason);
        Self {
            image: None,
            findings: PackerFindings {
                report,
                imports: PackerImports::Intact,
            },
            fresh: None,
        }
    }
}

#[derive(Clone)]
pub(super) struct PackerFindings {
    pub(super) report: PackerReport,
    pub(super) imports: PackerImports,
}

#[derive(Clone)]
pub(super) enum PackerImports {
    Intact,
    Listed(Vec<ModuleImports>),
    FilledIat { rva: u32, size: u32 },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PackerReport {
    pub(crate) name: &'static str,
    pub(crate) version: Option<String>,
    pub(crate) restored: Vec<&'static str>,
    pub(crate) unrestored: Vec<&'static str>,
    pub(crate) lost: Vec<&'static str>,
}

impl PackerReport {
    fn new(name: &'static str, version: Option<String>) -> Self {
        Self {
            name,
            version,
            restored: Vec::new(),
            unrestored: Vec::new(),
            lost: Vec::new(),
        }
    }

    fn record(&mut self, part: &'static str, state: Restoration) {
        match state {
            Restoration::Restored => self.restored.push(part),
            Restoration::Failed => self.unrestored.push(part),
            Restoration::Lost => self.lost.push(part),
            Restoration::Absent => {}
        }
    }
}

impl Display for PackerReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(version) => write!(formatter, "{} {version}", self.name),
            None => formatter.write_str(self.name),
        }
    }
}

#[derive(Clone)]
pub(super) struct ModuleImports {
    pub(super) module: String,
    pub(super) first_thunk: u32,
    pub(super) functions: Vec<ImportedFunction>,
}

#[derive(Clone)]
pub(super) enum ImportedFunction {
    Name(String),
    Ordinal(u16),
    OrdinalFromAddress,
    NameFromAddress,
    NameFromAddressAmong(Arc<HashSet<String>>), // names left in memory pick between aliases and tell names from ordinals
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    UNPACKERS.iter().find_map(|unpack| unpack(image, origin))
}

pub(super) fn find_pattern(haystack: &[u8], pattern: &str) -> Option<usize> {
    find_patterns(haystack, pattern).next()
}

pub(super) fn find_patterns<'a>(
    haystack: &'a [u8],
    pattern: &str,
) -> impl Iterator<Item = usize> + 'a {
    let expected = pattern
        .split_whitespace()
        .map(|token| match token {
            "??" => Some(None),
            hex => u8::from_str_radix(hex, 16).ok().map(Some),
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    let usable = !expected.is_empty();
    haystack
        .windows(expected.len().max(1))
        .enumerate()
        .filter(move |(_, window)| {
            usable
                && window
                    .iter()
                    .zip(&expected)
                    .all(|(byte, wanted)| wanted.is_none_or(|wanted| wanted == *byte))
        })
        .map(|(at, _)| at)
}
