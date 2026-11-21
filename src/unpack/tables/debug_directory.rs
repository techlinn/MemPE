use std::ops::Range;

use super::pogo_sections::{DEBUG_TYPE_POGO, pogo_data};
use super::{SCAN_STEP, Search};
use crate::pe::bytes::{read_u32, write_u32};
use crate::pe::{
    DEBUG_ADDRESS_OFFSET, DEBUG_DIRECTORY, DEBUG_ENTRY_SIZE, DEBUG_SIZE_OFFSET, DEBUG_TYPE_OFFSET,
    MAX_DEBUG_ENTRIES, PeModel,
};

const DEBUG_TIMESTAMP_OFFSET: usize = 4;
pub(crate) const DEBUG_TYPE_CODEVIEW: u32 = 2;
const MAX_DEBUG_TYPE: u32 = 20;
const CODEVIEW_RSDS_HEADER: usize = 24; // signature, guid and age
const CODEVIEW_NB10_HEADER: usize = 16; // signature, offset, timestamp and age
const PDB_EXTENSION: &[u8] = b".pdb";
const MAX_PDB_PATH: usize = 1_024;
const MAX_CODEVIEW_RECORDS: usize = 16;

fn debug_entry_count(directory_size: u32) -> usize {
    (directory_size as usize / DEBUG_ENTRY_SIZE).min(MAX_DEBUG_ENTRIES)
}

pub(crate) fn debug_entries(bytes: &[u8], model: &PeModel) -> impl Iterator<Item = usize> {
    let (start, count) = model
        .directory(bytes, DEBUG_DIRECTORY)
        .map_or((0, 0), |directory| {
            (
                directory.rva().as_usize(),
                debug_entry_count(directory.size()),
            )
        });

    (0..count).filter_map(move |index| start.checked_add(index.checked_mul(DEBUG_ENTRY_SIZE)?))
}

pub(crate) fn debug_timestamp(bytes: &[u8], model: &PeModel) -> Option<u32> {
    debug_entries(bytes, model)
        .filter_map(|entry| read_u32(bytes, entry.checked_add(DEBUG_TIMESTAMP_OFFSET)?).ok())
        .find(|timestamp| *timestamp != 0)
}

pub(super) fn find_debug_directory(bytes: &[u8], image: &Range<usize>) -> Search<(usize, usize)> {
    let end = image.end;
    let records = bytes.get(..end).map(codeview_records).unwrap_or_default();
    let field = |at: usize, offset: usize| {
        let entry = bytes.get(at..at.checked_add(DEBUG_ENTRY_SIZE)?)?;
        read_u32(entry, offset).ok()
    };
    let anchored = |at: usize| {
        let data = field(at, DEBUG_ADDRESS_OFFSET).map(|rva| rva as usize);
        let points_at_record = records.iter().any(|record| data == Some(record.rva));
        field(at, 0) == Some(0)
            && data.is_some_and(|data| data < end)
            && match field(at, DEBUG_TYPE_OFFSET) {
                Some(DEBUG_TYPE_CODEVIEW) => points_at_record,
                Some(DEBUG_TYPE_POGO) => data.is_some_and(|data| pogo_data(bytes, data, image)),
                _ => false,
            }
    };

    let anchors = image
        .clone()
        .step_by(SCAN_STEP)
        .filter(|at| anchored(*at))
        .take(MAX_DEBUG_ENTRIES + 1)
        .collect::<Vec<_>>();
    let Some(&anchor) = anchors.first() else {
        return Search::None;
    };
    let Some(timestamp) = field(anchor, DEBUG_TIMESTAMP_OFFSET) else {
        return Search::None;
    };

    let data_fits = |at: usize| {
        let address = field(at, DEBUG_ADDRESS_OFFSET).map(|rva| rva as usize);
        let size = field(at, DEBUG_SIZE_OFFSET).map(|size| size as usize);
        address.zip(size).is_some_and(|(address, size)| {
            address == 0 // not mapped
                || image.contains(&address)
                    && address.checked_add(size).is_some_and(|stop| stop <= end)
        })
    };
    let belongs = |at: usize| {
        anchors.contains(&at)
            || timestamp != 0 // zero is no link between neighbours
                && field(at, 0) == Some(0)
                && field(at, DEBUG_TIMESTAMP_OFFSET) == Some(timestamp)
                && field(at, DEBUG_TYPE_OFFSET)
                    .is_some_and(|kind| (1..=MAX_DEBUG_TYPE).contains(&kind))
                && data_fits(at)
    };

    let mut start = anchor;
    while let Some(before) = start
        .checked_sub(DEBUG_ENTRY_SIZE)
        .filter(|at| belongs(*at))
    {
        start = before;
    }

    let mut stop = anchor.saturating_add(DEBUG_ENTRY_SIZE);
    while belongs(stop) {
        stop = stop.saturating_add(DEBUG_ENTRY_SIZE);
    }

    match anchors.iter().all(|anchor| (start..stop).contains(anchor)) {
        true => Search::One((start, stop - start)),
        false => Search::Several,
    }
}

pub(crate) struct CodeViewRecord {
    pub(crate) rva: usize,
    pub(crate) size: usize,
}

pub(crate) fn find_codeview_record(bytes: &[u8]) -> Option<CodeViewRecord> {
    let mut records = codeview_records(bytes);
    (records.len() == 1).then(|| records.remove(0))
}

fn codeview_records(bytes: &[u8]) -> Vec<CodeViewRecord> {
    let mut found = Vec::new();
    for (signature, header) in [
        (b"RSDS", CODEVIEW_RSDS_HEADER),
        (b"NB10", CODEVIEW_NB10_HEADER),
    ] {
        let starts = bytes
            .windows(signature.len())
            .enumerate()
            .filter(|(_, window)| window == signature)
            .map(|(start, _)| start);

        for start in starts {
            if found.len() == MAX_CODEVIEW_RECORDS {
                return found;
            }
            if let Some(size) = codeview_size(bytes, start, header) {
                found.push(CodeViewRecord { rva: start, size });
            }
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
