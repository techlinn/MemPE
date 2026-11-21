use std::ops::Range;

use super::MOVED_TABLES_SECTION;
use super::layout::Layout;
use crate::packers::sections_before;
use crate::pe::bytes::{read_pointer, read_u32, write_pointer, write_u32};
use crate::pe::{
    EXCEPTION_DIRECTORY, GUARD_CHECK_PE32, GUARD_CHECK_PE32_PLUS, GUARD_FLAGS_PE32,
    GUARD_FLAGS_PE32_PLUS, LOAD_CONFIG_DIRECTORY, LOAD_CONFIG_HANDLERS_PE32, MAX_SAFESEH_HANDLERS,
    PeKind, PeModel, SAFESEH_HANDLER_SIZE,
};
use crate::unpack::tables::{
    SCAN_STEP, SectionKind, load_config_length, place_table, safe_handlers, unique,
};
use crate::unpack::{PackerReport, Part};

const MIN_VARIETY: f64 = 0.75; // share of distinct values random bytes hold
const STRAY_ZEROS: usize = 2;
const ZERO_SPACING: usize = 32; // zero density: fill vs data
const TAIL: usize = 8;
const TAIL_PADDING: usize = 2; // 00 or ff bytes that end the wipe
const GUARD_FLAGS_LEN: usize = 4;
const LEFT: &str = "left where the packer moved it";
const FOUND_BY_WIPE: &str = "put back over the one run of wiped bytes that fits it";

pub(super) struct WipedTables<'a> {
    pub(super) model: &'a PeModel,
    pub(super) layout: &'a Layout,
    pub(super) base: usize,
}

struct LoadConfig {
    guard_in_block: bool,
    dropped_handlers: usize,
}

impl WipedTables<'_> {
    pub(super) fn restore(&self, restored: &mut Vec<u8>, report: &mut PackerReport) {
        if self.moved(restored, LOAD_CONFIG_DIRECTORY).is_some() {
            match self.restore_load_config(restored) {
                Some(config) => describe_load_config(&config, report),
                None => report.failed_with(Part::LoadConfig, LEFT),
            }
        }

        if self.moved(restored, EXCEPTION_DIRECTORY).is_some() {
            match self.restore_exceptions(restored) {
                Some(()) => report.inferred(Part::Exceptions, FOUND_BY_WIPE),
                None => report.failed_with(Part::Exceptions, LEFT),
            }
        }
    }

    fn restore_load_config(&self, restored: &mut Vec<u8>) -> Option<LoadConfig> {
        let mut attempt = restored.clone(); // a refusal half way leaves no edits
        let config = self.place_load_config(&mut attempt)?;

        *restored = attempt;
        Some(config)
    }

    fn place_load_config(&self, restored: &mut Vec<u8>) -> Option<LoadConfig> {
        let (copy, declared) = self.moved(restored, LOAD_CONFIG_DIRECTORY)?;
        let length = load_config_length(restored, copy, declared);
        let mut config = restored.get(copy..copy.checked_add(length)?)?.to_vec();
        let place = self.wiped_load_config(restored, &config)?;

        let guard_in_block = self.return_guard_check(restored, &mut config);
        let dropped_handlers = match self.model.kind {
            PeKind::Pe32 => self.keep_safe_handlers(restored, &mut config)?,
            PeKind::Pe32Plus => 0,
        };

        restored
            .get_mut(place..place.checked_add(length)?)?
            .copy_from_slice(&config);
        self.model
            .set_directory(restored, LOAD_CONFIG_DIRECTORY, place, declared)?;

        Some(LoadConfig {
            guard_in_block,
            dropped_handlers,
        })
    }

    fn wiped_load_config(&self, restored: &[u8], config: &[u8]) -> Option<usize> {
        let flags = match self.model.kind {
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

    // true: the check pointer still leads into the packer's block
    fn return_guard_check(&self, restored: &[u8], config: &mut [u8]) -> bool {
        let kind = self.model.kind;
        let field = match kind {
            PeKind::Pe32 => GUARD_CHECK_PE32,
            PeKind::Pe32Plus => GUARD_CHECK_PE32_PLUS,
        };
        let image = |address: usize| address.checked_sub(self.base);
        let pointed = |at: usize| image(read_pointer(restored, at, kind).ok()?);

        let own = read_pointer(config, field, kind)
            .ok()
            .and_then(image)
            .filter(|own| self.layout.block.contains(own));
        let Some(own) = own else {
            return false;
        };

        let original = pointed(own).filter(|original| {
            let in_data = self
                .data(restored)
                .iter()
                .any(|section| section.contains(original));
            let checks_code = pointed(*original)
                .is_some_and(|check| self.layout.code.iter().any(|code| code.contains(&check)));

            in_data && checks_code && original.is_multiple_of(kind.pointer_width())
        }); // field points at the saved pointer

        original
            .and_then(|original| {
                write_pointer(config, field, kind, (self.base + original) as u64).ok()
            })
            .is_none()
    }

    fn keep_safe_handlers(&self, restored: &mut Vec<u8>, config: &mut [u8]) -> Option<usize> {
        let count_field = LOAD_CONFIG_HANDLERS_PE32 + SAFESEH_HANDLER_SIZE;
        let table = read_u32(config, LOAD_CONFIG_HANDLERS_PE32).ok()? as usize;
        let count = read_u32(config, count_field).ok()?;
        let Some(table) = table
            .checked_sub(self.base)
            .filter(|table| self.layout.block.contains(table))
        else {
            return Some(0);
        };
        (count <= MAX_SAFESEH_HANDLERS).then_some(())?;

        let listed = safe_handlers(restored, table, count)?;
        let kept = program_handlers(&listed, &self.layout.code);
        let dropped = listed.len() - kept.len() / SAFESEH_HANDLER_SIZE;

        let address = match kept.is_empty() {
            true => 0,
            false => {
                let program = 0..self.layout.payload();
                let at = place_table(
                    restored,
                    self.model,
                    &program,
                    &kept,
                    MOVED_TABLES_SECTION,
                    SectionKind::ReadOnly,
                )?;
                u32::try_from(self.base + at).ok()?
            }
        };
        let count = u32::try_from(kept.len() / SAFESEH_HANDLER_SIZE).ok()?;
        write_u32(config, LOAD_CONFIG_HANDLERS_PE32, address).ok()?;
        write_u32(config, count_field, count).ok()?;
        Some(dropped)
    }

    fn restore_exceptions(&self, restored: &mut [u8]) -> Option<()> {
        let (copy, size) = self.moved(restored, EXCEPTION_DIRECTORY)?;
        let table = restored.get(copy..copy.checked_add(size)?)?.to_vec();

        let emptied = |section: &Range<usize>| {
            let end = section.start + size;
            let after = end..end.saturating_add(TAIL).min(section.end);
            end <= section.end
                && wiped(&restored[section.start..end])
                && padding_follows(&restored[after])
        };
        let place = unique(
            self.data(restored)
                .into_iter()
                .filter(emptied)
                .map(|section| section.start),
        )?;

        restored[place..place + size].copy_from_slice(&table);
        self.model
            .set_directory(restored, EXCEPTION_DIRECTORY, place, size)
    }

    fn moved(&self, restored: &[u8], directory: usize) -> Option<(usize, usize)> {
        let data = self.model.directory(restored, directory)?;
        let rva = data.rva().as_usize();
        (self.layout.block.contains(&rva) && data.size() > 0).then_some((rva, data.size() as usize))
    }

    fn data(&self, restored: &[u8]) -> Vec<Range<usize>> {
        sections_before(restored, self.model, self.layout.payload(), false)
    }
}

fn describe_load_config(config: &LoadConfig, report: &mut PackerReport) {
    report.inferred(Part::LoadConfig, FOUND_BY_WIPE);

    if config.guard_in_block {
        report.partly_failed(
            Part::LoadConfig,
            "its guard check pointer still leads into the packer's block",
        );
    }
    if config.dropped_handlers > 0 {
        report.notes.push(format!(
            "{} safe exception handlers outside the program's code dropped from the load config",
            config.dropped_handlers
        ));
    }
}

fn program_handlers(listed: &[u32], code: &[Range<usize>]) -> Vec<u8> {
    listed
        .iter()
        .filter(|handler| {
            code.iter()
                .any(|range| range.contains(&(**handler as usize)))
        })
        .flat_map(|handler| handler.to_le_bytes())
        .collect()
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

fn padding_follows(bytes: &[u8]) -> bool {
    let filler = bytes.iter().filter(|byte| matches!(byte, 0 | 0xFF)).count();
    bytes.len() < TAIL || filler >= TAIL_PADDING
}
