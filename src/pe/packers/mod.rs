mod tables;
mod upx;

use std::fmt::{Display, Formatter};

use crate::pe::PeImage;

type Unpacker = fn(&PeImage<'_>, HeaderSource) -> Option<Unpacked>;

const UNPACKERS: [Unpacker; 1] = [upx::unpack];

#[derive(Clone, Copy)]
pub(super) enum HeaderSource {
    Memory,
    Disk,
}

pub(super) struct Unpacked {
    pub(super) image: Option<Vec<u8>>,
    pub(super) findings: PackerFindings,
}

pub(super) struct PackerFindings {
    pub(super) report: PackerReport,
    pub(super) imports: PackerImports,
}

pub(super) enum PackerImports {
    Intact,
    Listed(Vec<ModuleImports>),
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

impl Display for PackerReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(version) => write!(formatter, "{} {version}", self.name),
            None => formatter.write_str(self.name),
        }
    }
}

pub(super) struct ModuleImports {
    pub(super) module: String,
    pub(super) first_thunk: u32,
    pub(super) functions: Vec<ImportedFunction>,
}

pub(super) enum ImportedFunction {
    Name(String),
    Ordinal(u16),
    OrdinalFromAddress,
}

pub(super) fn unpack(image: &PeImage<'_>, headers: HeaderSource) -> Option<Unpacked> {
    UNPACKERS.iter().find_map(|unpack| unpack(image, headers))
}

pub(super) fn find_pattern(haystack: &[u8], pattern: &str) -> Option<usize> {
    let expected = pattern
        .split_whitespace()
        .map(|token| match token {
            "??" => Some(None),
            hex => u8::from_str_radix(hex, 16).ok().map(Some),
        })
        .collect::<Option<Vec<_>>>()?;
    if expected.is_empty() {
        return None;
    }
    haystack.windows(expected.len()).position(|window| {
        window
            .iter()
            .zip(&expected)
            .all(|(byte, wanted)| wanted.is_none_or(|wanted| wanted == *byte))
    })
}
