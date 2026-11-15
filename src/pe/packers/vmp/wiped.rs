use std::ops::Range;

use super::layout::Layout;
use crate::pe::image::{read_pointer, read_u32, write_pointer, write_u32};
use crate::pe::packers::PackerReport;
use crate::pe::packers::tables::{
    READ_ONLY_SECTION, SCAN_STEP, load_config_length, place_table, set_directory, unique,
};
use crate::pe::{EXCEPTION_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeKind, PeModel};

const MIN_VARIETY: f64 = 0.75; // of the distinct values that many random bytes are expected to hold
const STRAY_ZEROS: usize = 2;
const ZERO_SPACING: usize = 32; // vmp's fill holds a zero every hundred bytes or so, a program's data far more often
const GUARD: usize = 8;
const GUARD_FLAGS_PE32: usize = 0x58; // the one field vmp leaves in the load config it wipes
const GUARD_FLAGS_PE32_PLUS: usize = 0x90;
const GUARD_FLAGS_LEN: usize = 4;
const GUARD_CHECK_PE32: usize = 0x48;
const GUARD_CHECK_PE32_PLUS: usize = 0x70;
const SAFE_HANDLERS: usize = 0x40; // PE32 only: the table's address, then its count
const HANDLER_SIZE: usize = 4;
const MAX_SAFE_HANDLERS: usize = 0x1_0000;

pub(super) struct Wiped<'a> {
    pub(super) model: &'a PeModel,
    pub(super) layout: &'a Layout,
    pub(super) base: usize,
    pub(super) moved_tables: &'a [u8; 8],
}

impl Wiped<'_> {
    pub(super) fn restore(&self, restored: &mut Vec<u8>, report: &mut PackerReport) {
        if self.restore_load_config(restored).is_some() {
            report.restored.push("load config");
        }
        if self.restore_exceptions(restored).is_some() {
            report.restored.push("exception directory");
        }
    }

    fn restore_load_config(&self, restored: &mut Vec<u8>) -> Option<()> {
        let (copy, declared) = self.moved(restored, LOAD_CONFIG_DIRECTORY)?;
        let length = load_config_length(restored, copy, declared);
        let mut config = restored.get(copy..copy.checked_add(length)?)?.to_vec();
        let place = self.wiped_load_config(restored, &config)?;

        let _ = self.return_guard_check(restored, &mut config);
        if self.model.kind() == PeKind::Pe32 {
            self.keep_safe_handlers(restored, &mut config)?;
        }

        restored
            .get_mut(place..place + length)?
            .copy_from_slice(&config);
        set_directory(restored, self.model, LOAD_CONFIG_DIRECTORY, place, declared)
    }

    fn wiped_load_config(&self, restored: &[u8], config: &[u8]) -> Option<usize> {
        let flags = match self.model.kind() {
            PeKind::Pe32 => GUARD_FLAGS_PE32,
            PeKind::Pe32Plus => GUARD_FLAGS_PE32_PLUS,
        };
        let kept = flags..flags + GUARD_FLAGS_LEN;
        let anchor = config.get(kept.clone())?;

        let fits = |at: &usize| {
            restored
                .get(*at..at.saturating_add(config.len()))
                .is_some_and(|hole| {
                    hole[kept.clone()] == *anchor
                        && wiped(&hole[..kept.start])
                        && wiped(&hole[kept.end..])
                })
        };
        unique(
            self.data(restored)
                .into_iter()
                .flat_map(|section| section.step_by(SCAN_STEP))
                .filter(fits),
        )
    }

    fn return_guard_check(&self, restored: &[u8], config: &mut [u8]) -> Option<()> {
        let kind = self.model.kind();
        let field = match kind {
            PeKind::Pe32 => GUARD_CHECK_PE32,
            PeKind::Pe32Plus => GUARD_CHECK_PE32_PLUS,
        };
        let image = |address: usize| address.checked_sub(self.base);
        let pointed = |at: usize| image(read_pointer(restored, at, kind).ok()?);

        let own = image(read_pointer(config, field, kind).ok()?)
            .filter(|own| self.layout.block.contains(own))?;
        let original = pointed(own)?; // vmp aims the field into its code, at a spot holding where the program's pointer is

        let in_data = self
            .data(restored)
            .iter()
            .any(|section| section.contains(&original));
        let checks_code = pointed(original)
            .is_some_and(|check| self.layout.code.iter().any(|code| code.contains(&check)));
        let sound = in_data && checks_code && original.is_multiple_of(kind.pointer_width());

        sound.then_some(())?;
        write_pointer(config, field, kind, (self.base + original) as u64).ok()
    }

    fn keep_safe_handlers(&self, restored: &mut Vec<u8>, config: &mut [u8]) -> Option<()> {
        let table = read_u32(config, SAFE_HANDLERS).ok()? as usize;
        let count = read_u32(config, SAFE_HANDLERS + HANDLER_SIZE).ok()? as usize;
        let Some(table) = table
            .checked_sub(self.base)
            .filter(|table| self.layout.block.contains(table))
        else {
            return Some(());
        };

        let in_program = |handler: &u32| {
            self.layout
                .code
                .iter()
                .any(|code| code.contains(&(*handler as usize)))
        };
        let kept: Vec<u8> = (0..count.min(MAX_SAFE_HANDLERS))
            .map_while(|index| read_u32(restored, table + index * HANDLER_SIZE).ok())
            .filter(in_program) // vmp lists the program's handlers first and its own after them
            .flat_map(u32::to_le_bytes)
            .collect();

        let address = match kept.is_empty() {
            true => 0,
            false => {
                let program = 0..self.layout.payload();
                let at = place_table(
                    restored,
                    self.model,
                    &program,
                    &kept,
                    self.moved_tables,
                    READ_ONLY_SECTION,
                )?;
                u32::try_from(self.base + at).ok()?
            }
        };
        let count = u32::try_from(kept.len() / HANDLER_SIZE).ok()?;
        write_u32(config, SAFE_HANDLERS, address).ok()?;
        write_u32(config, SAFE_HANDLERS + HANDLER_SIZE, count).ok()
    }

    fn restore_exceptions(&self, restored: &mut [u8]) -> Option<()> {
        let (copy, size) = self.moved(restored, EXCEPTION_DIRECTORY)?;
        let table = restored.get(copy..copy.checked_add(size)?)?.to_vec();

        let emptied = |section: &Range<usize>| {
            let end = section.start + size;
            let after = end..end.saturating_add(GUARD).min(section.end);
            end <= section.end && wiped(&restored[section.start..end]) && plain(&restored[after])
        }; // the linker gives the table a section of its own, which vmp wipes whole
        let place = unique(
            self.data(restored)
                .into_iter()
                .filter(emptied)
                .map(|section| section.start),
        )?;

        restored[place..place + size].copy_from_slice(&table);
        set_directory(restored, self.model, EXCEPTION_DIRECTORY, place, size)
    }

    fn moved(&self, restored: &[u8], directory: usize) -> Option<(usize, usize)> {
        let data = self.model.directory(restored, directory).ok()??;
        let rva = data.rva().as_usize();
        (self.layout.block.contains(&rva) && data.size() > 0).then_some((rva, data.size() as usize))
    }

    fn data(&self, restored: &[u8]) -> Vec<Range<usize>> {
        self.model
            .sections()
            .iter()
            .filter(|section| !section.is_executable())
            .map(|section| section.range().start..section.range().end.min(restored.len()))
            .filter(|range| range.start < self.layout.payload() && range.start < range.end)
            .collect()
    }
}

fn wiped(bytes: &[u8]) -> bool {
    let mut seen = [false; 256];
    for byte in bytes {
        seen[*byte as usize] = true;
    }

    let distinct = seen.iter().filter(|seen| **seen).count() as f64;
    let expected = 256.0 * (1.0 - (255.0_f64 / 256.0).powf(bytes.len() as f64));
    let zeros = bytes.iter().filter(|byte| **byte == 0).count();

    distinct >= MIN_VARIETY * expected && zeros <= STRAY_ZEROS + bytes.len() / ZERO_SPACING
}

fn plain(bytes: &[u8]) -> bool {
    let filler = bytes.iter().filter(|byte| matches!(byte, 0 | 0xFF)).count();
    bytes.len() < GUARD || filler >= STRAY_ZEROS
}
