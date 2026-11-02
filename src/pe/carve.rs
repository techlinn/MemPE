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

#[cfg(test)]
mod tests {
    use super::{CarveSource, carve_embedded};

    fn host_with_embedded() -> Vec<u8> {
        let mut host = vec![0u8; 0x4000];
        write_min_pe(&mut host, 0);
        write_min_pe(&mut host, 0x2000);
        host
    }

    fn write_min_pe(bytes: &mut [u8], at: usize) {
        let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put16(bytes, at, 0x5a4d);
        put32(bytes, at + 0x3c, 0x80);
        put32(bytes, at + 0x80, 0x0000_4550);
        put16(bytes, at + 0x84, 0x8664);
        put16(bytes, at + 0x86, 1);
        put16(bytes, at + 0x94, 0xf0);
        put16(bytes, at + 0x96, 0x22);
        let optional = at + 0x98;
        put16(bytes, optional, 0x20b);
        put32(bytes, optional + 32, 0x1000);
        put32(bytes, optional + 36, 0x200);
        put32(bytes, optional + 56, 0x2000);
        put32(bytes, optional + 60, 0x200);
        put32(bytes, optional + 108, 16);
        let section = optional + 0xf0;
        bytes[section..section + 5].copy_from_slice(b".text");
        put32(bytes, section + 8, 0x1000);
        put32(bytes, section + 12, 0x1000);
        put32(bytes, section + 16, 0x200);
        put32(bytes, section + 20, 0x200);
        put32(bytes, section + 36, 0x6000_0020);
    }

    #[test]
    fn carves_only_the_inner_pe_not_the_host() {
        let host = host_with_embedded();

        let found = carve_embedded(&host, CarveSource::Image).found;

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, 0x2000);
        assert_eq!(found[0].extension, "exe");
    }

    #[test]
    fn ignores_a_bare_mz_without_a_pe_header() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0x100] = 0x4d;
        bytes[0x101] = 0x5a;

        assert!(carve_embedded(&bytes, CarveSource::Image).found.is_empty());
    }

    #[test]
    fn ignores_an_embedded_pe_with_a_conflicting_machine() {
        let mut host = vec![0u8; 0x4000];
        write_min_pe(&mut host, 0x2000);
        host[0x2000 + 0x84..0x2000 + 0x86].copy_from_slice(&0x1234u16.to_le_bytes());

        assert!(carve_embedded(&host, CarveSource::Image).found.is_empty());
    }

    #[test]
    fn ignores_an_embedded_pe_whose_section_exceeds_the_image() {
        let mut host = vec![0u8; 0x4000];
        write_min_pe(&mut host, 0x2000);
        let section_size = 0x2000 + 0x98 + 0xf0 + 8;
        host[section_size..section_size + 4].copy_from_slice(&0x9000u32.to_le_bytes());

        assert!(carve_embedded(&host, CarveSource::Image).found.is_empty());
    }

    #[test]
    fn reports_nothing_unscanned_after_a_complete_pass() {
        assert_eq!(
            carve_embedded(&host_with_embedded(), CarveSource::Image).unscanned,
            0
        );
    }

    #[test]
    fn finds_a_pe_at_the_very_start_of_a_buffer() {
        let mut buffer = vec![0u8; 0x4000];
        write_min_pe(&mut buffer, 0);

        let from_buffer = carve_embedded(&buffer, CarveSource::Buffer).found;
        let from_image = carve_embedded(&buffer, CarveSource::Image).found;

        assert_eq!(from_buffer.len(), 1);
        assert_eq!(from_buffer[0].offset, 0);
        assert!(from_image.is_empty());
    }

    #[test]
    fn scans_nothing_in_a_buffer_shorter_than_a_dos_header() {
        let mut buffer = vec![0u8; 0x20];
        buffer[..2].copy_from_slice(b"MZ");

        let result = carve_embedded(&buffer, CarveSource::Buffer);

        assert!(result.found.is_empty());
        assert_eq!(result.unscanned, 0);
    }

    #[test]
    fn reports_the_bytes_left_when_the_attempt_limit_stops_it() {
        let bytes = b"MZ".repeat(super::MAX_CARVE_ATTEMPTS + 0x1000);

        let result = carve_embedded(&bytes, CarveSource::Image);

        assert!(result.found.is_empty());
        assert_eq!(
            result.unscanned,
            bytes.len() - super::DOS_HEADER_SIZE - 2 * super::MAX_CARVE_ATTEMPTS
        );
        assert!(result.unscanned < bytes.len());
    }

    #[test]
    fn ignores_dense_pseudo_random_noise() {
        let mut bytes = vec![0u8; 0x8000];
        let mut state = 0x1234_5678_9abc_def0u64;
        for byte in bytes.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }

        assert!(carve_embedded(&bytes, CarveSource::Image).found.is_empty());
    }
}
