use super::pogo::{DEBUG_TYPE_POGO, pogo_data};
use super::{FIRST_SECTION_RVA, SCAN_STEP};
use crate::pe::image::{read_u32, write_u32};
use crate::pe::{DEBUG_DIRECTORY, PeModel};

pub(crate) const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_TIMESTAMP_OFFSET: usize = 4;
pub(crate) const DEBUG_TYPE_OFFSET: usize = 12;
pub(crate) const DEBUG_SIZE_OFFSET: usize = 16;
pub(crate) const DEBUG_ADDRESS_OFFSET: usize = 20;
pub(crate) const DEBUG_TYPE_CODEVIEW: u32 = 2;
const MAX_DEBUG_TYPE: u32 = 20; // the highest image_debug_type windows defines
const CODEVIEW_RSDS_HEADER: usize = 24; // signature, guid and age
const CODEVIEW_NB10_HEADER: usize = 16; // signature, offset, timestamp and age
const PDB_EXTENSION: &[u8] = b".pdb";
const MAX_PDB_PATH: usize = 1_024;

pub(crate) fn debug_timestamp(bytes: &[u8], model: &PeModel) -> Option<u32> {
    let directory = model.directory(bytes, DEBUG_DIRECTORY).ok()??;
    let start = directory.rva().as_usize();
    (0..directory.size() as usize / DEBUG_ENTRY_SIZE)
        .filter_map(|index| {
            read_u32(
                bytes,
                start + index * DEBUG_ENTRY_SIZE + DEBUG_TIMESTAMP_OFFSET,
            )
            .ok()
        })
        .find(|timestamp| *timestamp != 0)
}

pub(super) fn find_debug_directory(bytes: &[u8], end: usize) -> Option<(usize, usize)> {
    let record = bytes.get(..end).and_then(find_codeview_record);
    let field = |at: usize, offset: usize| {
        let entry = bytes.get(at..at.checked_add(DEBUG_ENTRY_SIZE)?)?;
        read_u32(entry, offset).ok()
    };
    let anchored = |at: usize| {
        let data = field(at, DEBUG_ADDRESS_OFFSET).map(|rva| rva as usize);
        let points_at_record = record
            .as_ref()
            .is_some_and(|record| data == Some(record.rva));
        field(at, 0) == Some(0)
            && data.is_some_and(|data| data < end)
            && match field(at, DEBUG_TYPE_OFFSET) {
                Some(DEBUG_TYPE_CODEVIEW) => points_at_record,
                Some(DEBUG_TYPE_POGO) => data.is_some_and(|data| pogo_data(bytes, data, end)),
                _ => false,
            }
    };

    let anchors = (FIRST_SECTION_RVA..end)
        .step_by(SCAN_STEP)
        .filter(|at| anchored(*at))
        .take(MAX_DEBUG_TYPE as usize + 1)
        .collect::<Vec<_>>();
    let codeview = *anchors.first()?;

    let timestamp = field(codeview, DEBUG_TIMESTAMP_OFFSET)?;
    let belongs = |at: usize| {
        field(at, 0) == Some(0)
            && field(at, DEBUG_TIMESTAMP_OFFSET) == Some(timestamp)
            && field(at, DEBUG_TYPE_OFFSET).is_some_and(|kind| (1..=MAX_DEBUG_TYPE).contains(&kind))
    };

    let mut start = codeview;
    while let Some(before) = start
        .checked_sub(DEBUG_ENTRY_SIZE)
        .filter(|at| belongs(*at))
    {
        start = before;
    }

    let mut stop = codeview.checked_add(DEBUG_ENTRY_SIZE)?;
    while belongs(stop) {
        stop = stop.checked_add(DEBUG_ENTRY_SIZE)?;
    }

    anchors
        .iter()
        .all(|anchor| (start..stop).contains(anchor))
        .then_some((start, stop - start))
}

pub(crate) struct CodeViewRecord {
    pub(crate) rva: usize,
    pub(crate) size: usize,
}

pub(crate) fn find_codeview_record(bytes: &[u8]) -> Option<CodeViewRecord> {
    let mut found = None;
    for (signature, header) in [
        (b"RSDS", CODEVIEW_RSDS_HEADER),
        (b"NB10", CODEVIEW_NB10_HEADER),
    ] {
        for start in bytes
            .windows(signature.len())
            .enumerate()
            .filter(|(_, window)| window == signature)
            .map(|(start, _)| start)
        {
            let Some(size) = codeview_size(bytes, start, header) else {
                continue;
            };

            if found.is_some() {
                return None;
            }

            found = Some(CodeViewRecord { rva: start, size });
        }
    }

    found
}

fn codeview_size(bytes: &[u8], start: usize, header: usize) -> Option<usize> {
    let path_start = start.checked_add(header)?;
    let path = bytes.get(path_start..path_start.checked_add(MAX_PDB_PATH)?.min(bytes.len()))?;
    let length = path.iter().position(|byte| *byte == 0)?;
    let text = path.get(..length)?;

    let printable = text
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ');
    let pdb = text
        .len()
        .checked_sub(PDB_EXTENSION.len())
        .and_then(|start| text.get(start..))
        .is_some_and(|extension| extension.eq_ignore_ascii_case(PDB_EXTENSION));
    (printable && pdb).then(|| header.saturating_add(length).saturating_add(1))
}

pub(crate) fn codeview_entry(
    record: &CodeViewRecord,
    timestamp: u32,
) -> Option<[u8; DEBUG_ENTRY_SIZE]> {
    let mut entry = [0u8; DEBUG_ENTRY_SIZE];
    write_u32(&mut entry, DEBUG_TIMESTAMP_OFFSET, timestamp).ok()?;
    write_u32(&mut entry, DEBUG_TYPE_OFFSET, DEBUG_TYPE_CODEVIEW).ok()?;
    write_u32(
        &mut entry,
        DEBUG_SIZE_OFFSET,
        u32::try_from(record.size).ok()?,
    )
    .ok()?;
    write_u32(
        &mut entry,
        DEBUG_ADDRESS_OFFSET,
        u32::try_from(record.rva).ok()?,
    )
    .ok()?;

    Some(entry)
}
