use crate::pe::image::read_u32;
use crate::pe::parse::parse_disk_image;
use crate::pe::{PeImage, PeKind, SECURITY_DIRECTORY};

const DOS_MAGIC: [u8; 2] = *b"MZ";
const DOS_HEADER_SIZE: usize = 64;
const RAW_SIZE_OFFSET: usize = 16;
const RAW_POINTER_OFFSET: usize = 20;
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

pub(crate) fn carve_embedded(memory: &[u8], source: CarveSource) -> CarveResult {
    let Some(last_candidate) = memory.len().checked_sub(DOS_HEADER_SIZE) else {
        return CarveResult {
            found: Vec::new(),
            unscanned: 0,
        };
    };

    let mut found = Vec::new();
    let mut attempts = 0usize;
    let mut offset = match source {
        CarveSource::Image => 1, // offset 0 is the images own header
        CarveSource::Buffer => 0,
    };

    while offset <= last_candidate
        && found.len() < MAX_EMBEDDED_PER_IMAGE
        && attempts < MAX_CARVE_ATTEMPTS
    {
        if memory.get(offset..offset.saturating_add(DOS_MAGIC.len())) != Some(&DOS_MAGIC[..]) {
            offset = offset.saturating_add(1);
            continue;
        }

        attempts = attempts.saturating_add(1);

        match try_carve(memory, offset) {
            Some(embedded) => {
                offset = offset.saturating_add(embedded.length);
                found.push(embedded);
            }
            None => offset = offset.saturating_add(1),
        }
    }

    let unscanned = last_candidate.saturating_add(1).saturating_sub(offset);
    CarveResult { found, unscanned }
}

fn try_carve(memory: &[u8], offset: usize) -> Option<EmbeddedPe> {
    let slice = memory.get(offset..)?;
    let image = parse_disk_image(slice).ok()?;
    let length = embedded_length(&image)?;

    if !(MIN_EMBEDDED_SIZE..=MAX_EMBEDDED_SIZE).contains(&length) || length > slice.len() {
        return None;
    }

    Some(EmbeddedPe {
        offset,
        length,
        kind: image.model().kind,
        extension: classify(&image),
    })
}

fn embedded_length(image: &PeImage<'_>) -> Option<usize> {
    let bytes = image.bytes();
    let model = image.model();
    let mut end = usize::try_from(read_u32(bytes, model.size_of_headers_offset).ok()?).ok()?;

    for section in model.sections() {
        let header = section.header_offset;
        let raw_size =
            usize::try_from(read_u32(bytes, header.checked_add(RAW_SIZE_OFFSET)?).ok()?).ok()?;
        let raw_offset =
            usize::try_from(read_u32(bytes, header.checked_add(RAW_POINTER_OFFSET)?).ok()?).ok()?;
        end = end.max(raw_offset.checked_add(raw_size)?);
    }

    Some(end.max(certificate_end(image)?))
}

fn certificate_end(image: &PeImage<'_>) -> Option<usize> {
    let Ok(Some(certificate)) = image.directory(SECURITY_DIRECTORY) else {
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
