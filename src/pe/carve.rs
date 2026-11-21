use crate::pe::bytes::read_u32;
use crate::pe::parse::parse_disk_image;
use crate::pe::{DOS_HEADER_SIZE, DOS_MAGIC};
use crate::pe::{PeImage, PeKind, SECURITY_DIRECTORY};

const SUBSYSTEM_NATIVE: u16 = 1;
const MIN_EMBEDDED_SIZE: usize = 0x100;
const MAX_EMBEDDED_SIZE: usize = 256 * 1024 * 1024;
const MAX_EMBEDDED_PER_IMAGE: usize = 256;
const MAX_CARVE_ATTEMPTS: usize = 8_192;

pub(crate) struct EmbeddedPe {
    pub(crate) offset: usize,
    pub(crate) length: usize,
    pub(crate) kind: PeKind,
    pub(crate) extension: &'static str,
}

pub(crate) struct CarveResult {
    pub(crate) found: Vec<EmbeddedPe>,
    pub(crate) unscanned: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum CarveSource {
    Image,
    Buffer,
}

enum Candidate {
    File(EmbeddedPe),
    Mapped(usize),
    Nothing,
}

pub(crate) fn carve_embedded(memory: &[u8], source: CarveSource) -> CarveResult {
    let Some(last_candidate) = memory.len().checked_sub(DOS_HEADER_SIZE) else {
        return CarveResult {
            found: Vec::new(),
            unscanned: 0,
        };
    };

    let magic = DOS_MAGIC.to_le_bytes();
    let mut found = Vec::new();
    let mut attempts = 0usize;
    let mut jumped = 0usize;
    let mut offset = match source {
        CarveSource::Image => 1, // skip own header
        CarveSource::Buffer => 0,
    };

    while offset <= last_candidate
        && found.len() < MAX_EMBEDDED_PER_IMAGE
        && attempts < MAX_CARVE_ATTEMPTS
    {
        if memory.get(offset..offset.saturating_add(magic.len())) != Some(&magic[..]) {
            offset = offset.saturating_add(1);
            continue;
        }

        attempts = attempts.saturating_add(1);

        // nothing inside a jump is looked at; a carved file's inside is written out with it, a mapped
        // image's is not
        let step = match candidate_at(memory, offset) {
            Candidate::File(embedded) => {
                let length = embedded.length;
                found.push(embedded);
                length
            }
            Candidate::Mapped(length) => {
                jumped = jumped.saturating_add(length);
                length
            }
            Candidate::Nothing => {
                offset = offset.saturating_add(1);
                continue;
            }
        };

        offset = offset.saturating_add(step);
    }

    let tail = last_candidate.saturating_add(1).saturating_sub(offset);

    CarveResult {
        found,
        unscanned: tail.saturating_add(jumped),
    }
}

fn candidate_at(memory: &[u8], offset: usize) -> Candidate {
    let Some(slice) = memory.get(offset..) else {
        return Candidate::Nothing;
    };
    let Ok(image) = parse_disk_image(slice) else {
        return Candidate::Nothing;
    };

    if mapped_layout(&image) {
        let mapped = (image.model().image_size as usize).min(slice.len());
        return Candidate::Mapped(mapped.max(1));
    }

    let Some(length) = embedded_length(&image) else {
        return Candidate::Nothing;
    };

    if !(MIN_EMBEDDED_SIZE..=MAX_EMBEDDED_SIZE).contains(&length) || length > slice.len() {
        return Candidate::Nothing;
    }

    Candidate::File(EmbeddedPe {
        offset,
        length,
        kind: image.model().kind,
        extension: classify(&image),
    })
}

// first raw bytes missing at the raw pointer, present at the rva
fn mapped_layout(image: &PeImage<'_>) -> bool {
    let bytes = image.bytes();
    let first = image
        .model()
        .sections
        .iter()
        .filter(|section| section.raw_size != 0)
        .min_by_key(|section| section.raw_pointer);
    let Some(first) = first else {
        return false;
    };

    let in_file = first.raw_pointer as usize;
    let in_memory = first.virtual_address().as_usize();
    let length =
        (first.raw_size.min(first.mapped_size()) as usize).min(in_file.abs_diff(in_memory));
    let holds_data = |start: usize| {
        bytes
            .get(start..start.saturating_add(length))
            .is_some_and(|data| data.iter().any(|byte| *byte != 0))
    };

    length != 0 && !holds_data(in_file) && holds_data(in_memory)
}

fn embedded_length(image: &PeImage<'_>) -> Option<usize> {
    let bytes = image.bytes();
    let model = image.model();
    let mut end = read_u32(bytes, model.size_of_headers_offset).ok()? as usize;

    for section in &model.sections {
        end = end.max(section.raw_pointer as usize + section.raw_size as usize);
    }

    Some(end.max(certificate_end(image)?))
}

fn certificate_end(image: &PeImage<'_>) -> Option<usize> {
    let Some(certificate) = image.directory(SECURITY_DIRECTORY) else {
        return Some(0);
    };

    certificate
        .rva()
        .as_usize()
        .checked_add(certificate.size() as usize)
}

fn classify(image: &PeImage<'_>) -> &'static str {
    let model = image.model();

    if model.subsystem == SUBSYSTEM_NATIVE {
        "sys"
    } else if model.is_dll {
        "dll"
    } else {
        "exe"
    }
}
