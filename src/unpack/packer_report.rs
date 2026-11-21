use std::fmt::{Display, Formatter};

use super::tables::Restoration;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PackerId {
    Upx,
    AsPack,
    Mpress,
    PeCompact,
    Fsg,
    Mew,
    Themida,
    WinLicense,
    VmProtect,
}

impl Display for PackerId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Upx => "UPX",
            Self::AsPack => "ASPack",
            Self::Mpress => "MPRESS",
            Self::PeCompact => "PECompact",
            Self::Fsg => "FSG",
            Self::Mew => "MEW",
            Self::Themida => "Themida",
            Self::WinLicense => "WinLicense",
            Self::VmProtect => "VMProtect",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Part {
    Image,
    Headers,
    EntryPoint,
    EntryCode,
    Imports,
    Relocations,
    Resources,
    ResourceLayout,
    ResourceData,
    IconGroups,
    Exports,
    ExportForwarders,
    Tls,
    TlsPointers,
    Exceptions,
    LoadConfig,
    DelayImports,
    DebugDirectory,
    DebugEntries,
    GuardFlags,
    BuildTimestamp,
    SectionTable,
    SectionSplit,
    SectionNames,
    SectionFlags,
    Code,
    CodeAndData,
    Unwind,
    Overlay,
    MutatedCode,
    VirtualizedCode,
    EncryptedStrings,
    EngineCalls,
    VmCalls,
    PackerSections,
}

impl Part {
    fn label(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Headers => "headers",
            Self::EntryPoint => "original entry point",
            Self::EntryCode => "the entry point's first instructions",
            Self::Imports => "imports",
            Self::Relocations => "relocations",
            Self::Resources => "resources",
            Self::ResourceLayout => "resource layout",
            Self::ResourceData => "resource data the packer blanked",
            Self::IconGroups => "icon groups the packer overwrote",
            Self::Exports => "exports",
            Self::ExportForwarders => "export forwarders",
            Self::Tls => "TLS directory",
            Self::TlsPointers => "the TLS directory's own pointers",
            Self::Exceptions => "exception directory",
            Self::LoadConfig => "load config",
            Self::DelayImports => "delay imports",
            Self::DebugDirectory => "debug directory",
            Self::DebugEntries => "debug entries the packer erased",
            Self::GuardFlags => "control flow guard flags the packer cleared",
            Self::BuildTimestamp => "build timestamp",
            Self::SectionTable => "section table",
            Self::SectionSplit => "code and data sections",
            Self::SectionNames => "section names",
            Self::SectionFlags => "section flags",
            Self::Code => "code",
            Self::CodeAndData => "code and data",
            Self::Unwind => "unwind info",
            Self::Overlay => "overlay",
            Self::MutatedCode => "mutated code",
            Self::VirtualizedCode => "virtualized code",
            Self::EncryptedStrings => "encrypted strings",
            Self::EngineCalls => "calls into the packer's engine",
            Self::VmCalls => "calls into the packer's code",
            Self::PackerSections => "the packer's sections",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum State {
    Restored,
    Inferred, // worked out from evidence, not read back from the packer
    Failed,
    Lost,
}

impl State {
    fn rewrote(self) -> bool {
        matches!(self, Self::Restored | Self::Inferred)
    }
}

#[derive(Clone)]
pub(crate) struct Finding {
    part: Part,
    state: State,
    partly: bool,
    detail: Option<&'static str>,
}

impl Display for Finding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = self.part.label();
        match (self.partly, label.starts_with("the ")) {
            (true, true) => write!(formatter, "some of {label}")?,
            (true, false) => write!(formatter, "some {label}")?,
            (false, _) => formatter.write_str(label)?,
        }
        match self.detail {
            Some(detail) => write!(formatter, " ({detail})"),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PackerReport {
    pub(crate) packer: PackerId,
    pub(crate) version: Option<String>,
    findings: Vec<Finding>,
    pub(crate) notes: Vec<String>,
}

impl PackerReport {
    pub(crate) fn new(packer: PackerId, version: Option<String>) -> Self {
        Self {
            packer,
            version,
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub(crate) fn restored(&mut self, part: Part) {
        self.add(part, State::Restored, false, None);
    }

    pub(crate) fn restored_with(&mut self, part: Part, detail: &'static str) {
        self.add(part, State::Restored, false, Some(detail));
    }

    pub(crate) fn inferred(&mut self, part: Part, detail: &'static str) {
        self.add(part, State::Inferred, false, Some(detail));
    }

    pub(crate) fn failed(&mut self, part: Part) {
        self.add(part, State::Failed, false, None);
    }

    pub(crate) fn failed_with(&mut self, part: Part, detail: &'static str) {
        self.add(part, State::Failed, false, Some(detail));
    }

    pub(crate) fn partly_failed(&mut self, part: Part, detail: &'static str) {
        self.add(part, State::Failed, true, Some(detail));
    }

    pub(crate) fn lost(&mut self, part: Part) {
        self.add(part, State::Lost, false, None);
    }

    pub(crate) fn lost_with(&mut self, part: Part, detail: &'static str) {
        self.add(part, State::Lost, false, Some(detail));
    }

    pub(crate) fn record(&mut self, part: Part, state: Restoration) {
        match state {
            Restoration::Restored => self.restored(part),
            Restoration::Inferred(detail) => self.inferred(part, detail),
            Restoration::Failed => self.failed(part),
            Restoration::Lost => self.lost(part),
            Restoration::Absent => {}
        }
    }

    pub(crate) fn entry_state(&self) -> Option<State> {
        self.findings
            .iter()
            .find(|finding| finding.part == Part::EntryPoint && finding.state.rewrote())
            .map(|finding| finding.state)
    }

    pub(crate) fn restored_anything(&self) -> bool {
        self.findings.iter().any(|finding| finding.state.rewrote())
    }

    pub(crate) fn has(&self, state: State) -> bool {
        self.findings.iter().any(|finding| finding.state == state)
    }

    pub(crate) fn listed(&self, state: State) -> Vec<String> {
        self.findings
            .iter()
            .filter(|finding| finding.state == state)
            .map(ToString::to_string)
            .collect()
    }

    pub(crate) fn withdraw(&mut self, part: Part) {
        self.findings
            .retain(|finding| finding.part != part || !finding.state.rewrote());
    }

    pub(crate) fn refuse_image(&mut self, detail: &'static str) {
        self.findings.clear();
        self.notes.clear();
        self.failed_with(Part::Image, detail);
    }

    fn add(&mut self, part: Part, state: State, partly: bool, detail: Option<&'static str>) {
        self.findings.push(Finding {
            part,
            state,
            partly,
            detail,
        });
    }
}

impl Display for PackerReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(version) => write!(formatter, "{} {version}", self.packer),
            None => write!(formatter, "{}", self.packer),
        }
    }
}
