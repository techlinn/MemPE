mod directories;
mod exception;
mod headers;
mod import_section;
mod observe;
mod sections;
mod source;

use crate::pe::exports::ExportIndex;
use crate::pe::imports::{ImportPlan, build_plan};
use crate::pe::parse::parse_memory_image;
use crate::pe::{
    EntryPointRva, IAT_DIRECTORY, IMPORT_DIRECTORY, PeImage, PeKind, PeModel, RegionEvidence,
    SectionModel,
};
use crate::{AppError, AppResult};
use directories::{
    ClearedDirectories, clear_bad_directories, clear_directory, clear_dynamic_base,
    repair_debug_directory,
};
use exception::{UnwindRanges, entry_unwind_covered, repair_exception_directory, unwind_layout};
use headers::{finalize_output, write_core_header_fields};
use import_section::{ImportSection, append_import_section};
use observe::{
    absent_sections, count_tls_callbacks, count_write_execute_sections, entry_section_name,
    invalid_pdata_sections, never_decrypted_sections,
};
use sections::{build_output_buffer, write_sections};
use source::resolve_source_bytes;

const SECTION_HEADER_SIZE: usize = 40;
const MAX_OUTPUT_SIZE: usize = 1024 * 1024 * 1024;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const PAGE_SIZE: usize = 4 * 1024;

pub(crate) struct RebuiltImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) kind: PeKind,
    pub(crate) is_dll: bool,
    pub(crate) section_count: usize,
    pub(crate) salvaged_headers: bool,
    pub(crate) disk_headers_used: bool,
    pub(crate) cleared_directories: usize,
    pub(crate) invalid_unwind_entries: usize,
    pub(crate) imports_rebuilt: usize,
    pub(crate) unemitted_imports: usize,
    pub(crate) unresolved_delay: usize,
    pub(crate) ambiguous_imports: usize,
    pub(crate) aliased_names: usize,
    pub(crate) declared_iat_slots: usize,
    pub(crate) invalid_pdata_sections: usize,
    pub(crate) managed: bool,
    pub(crate) renamed_sections: usize,
    pub(crate) tls_callbacks: usize,
    pub(crate) entry_point: u32,
    pub(crate) entry_section: Option<String>,
    pub(crate) repaired_debug_entries: usize,
    pub(crate) fixed_image_base: bool,
    pub(crate) notable_cleared_directories: Vec<String>,
    pub(crate) executable_flag_added: bool,
    pub(crate) entry_unwind_covered: Option<bool>,
    pub(crate) write_execute_sections: usize,
    pub(crate) never_decrypted_sections: usize,
    pub(crate) absent_sections: usize,
}

struct SectionLayout<'a> {
    model: &'a SectionModel,
    source_length: usize,
    raw_offset: usize,
    raw_size: usize,
}

pub(crate) fn rebuild(
    memory: &[u8],
    regions: &[RegionEvidence],
    observed_base: usize,
    disk_headers: Option<&[u8]>,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
    page_flags: &[u8],
) -> AppResult<RebuiltImage> {
    let (source, disk_headers_used) = resolve_source_bytes(memory, regions, disk_headers)?;
    let image = parse_memory_image(&source)
        .map_err(|error| AppError::new(format!("rebuilt PE headers are invalid: {error}")))?;
    let memory = image.bytes();
    let model = image.model();
    let (mut output, layouts, header_size) = build_output_buffer(model, memory)?;

    write_core_header_fields(&mut output, model, observed_base, header_size)?;
    let renamed_sections = write_sections(&mut output, memory, &layouts)?;

    let mut repairs = apply_repairs(&mut output, model, &layouts, header_size)?;
    let ImportOutcome {
        plan: import_plan,
        written,
        unemitted,
    } = resolve_imports(
        &mut output,
        model,
        &image,
        observed_base,
        exports,
        &mut repairs,
    )?;
    let (final_entry_point, executable_flag_added) =
        finalize_output(&mut output, model, entry_point)?;

    Ok(RebuiltImage {
        kind: model.kind,
        is_dll: model.is_dll,
        section_count: model.sections.len().saturating_add(usize::from(written)),
        salvaged_headers: model.salvaged,
        disk_headers_used,
        cleared_directories: repairs.cleared.total,
        notable_cleared_directories: repairs.cleared.notable_names(),
        invalid_unwind_entries: repairs.invalid_unwind_entries,
        imports_rebuilt: if written { import_plan.recovered } else { 0 },
        unemitted_imports: unemitted,
        unresolved_delay: import_plan.unresolved_delay,
        ambiguous_imports: import_plan.ambiguous,
        aliased_names: import_plan.aliased_names,
        declared_iat_slots: declared_iat_slots(&image, model),
        invalid_pdata_sections: invalid_pdata_sections(&output, model, &layouts, header_size),
        managed: unwind_layout(&output, model).is_managed(),
        renamed_sections,
        tls_callbacks: count_tls_callbacks(&image, observed_base),
        entry_point: final_entry_point,
        entry_section: entry_section_name(&layouts, final_entry_point),
        repaired_debug_entries: repairs.repaired_debug_entries,
        fixed_image_base: repairs.fixed_image_base,
        executable_flag_added,
        entry_unwind_covered: entry_unwind_covered(&repairs.unwind_ranges, final_entry_point),
        write_execute_sections: count_write_execute_sections(&layouts, regions),
        never_decrypted_sections: never_decrypted_sections(memory, &layouts, page_flags),
        absent_sections: absent_sections(memory, &layouts),
        bytes: output,
    })
}

struct RepairStats {
    cleared: ClearedDirectories,
    unwind_ranges: Option<UnwindRanges>,
    invalid_unwind_entries: usize,
    repaired_debug_entries: usize,
    fixed_image_base: bool,
}

fn apply_repairs(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<RepairStats> {
    let cleared = clear_bad_directories(output, model, layouts, header_size)?;
    let exception = repair_exception_directory(output, model, layouts, header_size)?;
    let repaired_debug_entries = repair_debug_directory(output, model, layouts, header_size)?;
    let fixed_image_base = clear_dynamic_base(output, model)?;
    Ok(RepairStats {
        cleared,
        unwind_ranges: exception.ranges,
        invalid_unwind_entries: exception.invalid,
        repaired_debug_entries,
        fixed_image_base,
    })
}

struct ImportOutcome {
    plan: ImportPlan,
    written: bool,
    unemitted: usize,
}

fn resolve_imports(
    output: &mut Vec<u8>,
    model: &PeModel,
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    repairs: &mut RepairStats,
) -> AppResult<ImportOutcome> {
    let plan = build_plan(image, observed_base, exports);
    let section = match plan.groups.is_empty() {
        true => ImportSection::NothingToWrite,
        false => append_import_section(output, model, &plan)?,
    };
    let (written, unemitted, iat_cleared) = match section {
        ImportSection::Written { iat_cleared } => (true, 0, iat_cleared),
        ImportSection::NothingToWrite => (false, 0, false),
        ImportSection::NoImportDirectory | ImportSection::NoRoomInHeaders => {
            (false, plan.recovered, false)
        }
    };
    if iat_cleared {
        repairs.cleared.record(IAT_DIRECTORY);
    }
    if !written && plan.existing.is_empty() {
        let extra = clear_directory(output, model, IMPORT_DIRECTORY)?;
        if extra > 0 {
            repairs.cleared.record(IMPORT_DIRECTORY);
        }
    }

    Ok(ImportOutcome {
        plan,
        written,
        unemitted,
    })
}

fn declared_iat_slots(image: &PeImage<'_>, model: &PeModel) -> usize {
    let Ok(Some(directory)) = image.directory(IAT_DIRECTORY) else {
        return 0;
    };
    directory.size() as usize / model.kind.pointer_width()
}

fn rva_to_file(rva: u32, layouts: &[SectionLayout<'_>], header_size: usize) -> Option<usize> {
    let rva = rva as usize;
    if rva < header_size {
        return Some(rva);
    }
    layouts.iter().find_map(|layout| {
        if layout.raw_size == 0 {
            return None;
        }
        let start = layout.model.virtual_address.get() as usize;
        let delta = rva.checked_sub(start)?;
        (delta < layout.source_length).then(|| layout.raw_offset.saturating_add(delta))
    })
}

fn align_up(value: usize, alignment: usize) -> AppResult<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(AppError::new("PE alignment is invalid"));
    }
    value
        .checked_add(alignment - 1)
        .map(|result| result & !(alignment - 1))
        .ok_or_else(|| AppError::new("PE alignment overflowed"))
}

fn align_up_u64(value: u64, alignment: u64) -> AppResult<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(AppError::new("PE alignment is invalid"));
    }
    value
        .checked_add(alignment - 1)
        .map(|result| result & !(alignment - 1))
        .ok_or_else(|| AppError::new("PE alignment overflowed"))
}

#[cfg(test)]
mod tests {
    use pelite::PeFile;

    use super::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, rebuild};
    use crate::pe::exports::ExportIndex;
    use crate::pe::{
        EntryPointRva, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeKind,
        RegionEvidence,
    };

    #[test]
    fn names_a_notable_directory_it_had_to_clear() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let debug = 0x98 + 112 + 6 * 8;
        put_u32(&mut memory, debug, 0x5000);
        put_u32(&mut memory, debug + 4, 0x28);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(
            rebuilt.notable_cleared_directories,
            vec!["Debug".to_owned()]
        );
        assert_eq!(get_u32(&rebuilt.bytes, debug), 0);
        Ok(())
    }

    #[test]
    fn refuses_disk_headers_that_claim_more_image_than_was_captured() {
        let mut disk = fixture_pe64();
        put_u32(&mut disk, 0x98 + 56, 0x9000);
        let mut memory = disk.clone();
        put_u32(&mut memory, 0x80, 0);

        let result = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            Some(&disk),
            &ExportIndex::default(),
            None,
            &[],
        );

        assert_eq!(
            result.err().map(|error| error.to_string()),
            Some("disk SizeOfImage exceeds the captured image".to_owned())
        );
    }

    #[test]
    fn rebuilds_a_memory_layout_pe32_plus() -> Result<(), Box<dyn std::error::Error>> {
        let memory = fixture_pe64();
        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert!(!rebuilt.is_dll);
        assert_eq!(rebuilt.section_count, 1);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        assert_eq!(&rebuilt.bytes[0x200..0x204], &[0x90, 0x90, 0xC3, 0]);
        Ok(())
    }

    #[test]
    fn rebuilds_a_memory_layout_pe32_dll() -> Result<(), Box<dyn std::error::Error>> {
        let memory = fixture_pe32();
        let rebuilt = rebuild(
            &memory,
            &[],
            0x0040_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert!(rebuilt.is_dll);
        assert_eq!(rebuilt.kind, PeKind::Pe32);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        assert_eq!(&rebuilt.bytes[0x200..0x204], &[0x55, 0x8B, 0xEC, 0xC3]);
        Ok(())
    }

    #[test]
    fn restores_damaged_headers_from_disk_structure() -> Result<(), Box<dyn std::error::Error>> {
        let mut disk = fixture_pe64();
        put_u32(&mut disk, 0x98 + 60, 0x000F_0000);
        let mut memory = disk.clone();
        memory[..0x200].fill(0);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            Some(&disk),
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert!(rebuilt.disk_headers_used);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        assert_eq!(&rebuilt.bytes[0x200..0x204], &[0x90, 0x90, 0xC3, 0]);
        Ok(())
    }

    #[test]
    fn preserves_valid_memory_entry_point_during_disk_merge()
    -> Result<(), Box<dyn std::error::Error>> {
        let disk = fixture_pe64();
        let mut memory = disk.clone();
        put_u32(&mut memory, 0x80, 0);
        put_u32(&mut memory, 0x98 + 16, 0x1001);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            Some(&disk),
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert!(rebuilt.disk_headers_used);
        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 16), 0x1001);
        Ok(())
    }

    #[test]
    fn rejects_disk_headers_that_conflict_with_memory_architecture() {
        let disk = fixture_pe64();
        let mut memory = disk.clone();
        put_u32(&mut memory, 0x80, 0);
        put_u16(&mut memory, 0x84, 0x014C);

        let result = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            Some(&disk),
            &ExportIndex::default(),
            None,
            &[],
        );

        assert!(result.is_err());
    }

    #[test]
    fn applies_only_valid_manual_entry_points() -> Result<(), Box<dyn std::error::Error>> {
        let memory = fixture_pe64();
        let valid = EntryPointRva::new(0x1002).ok_or("valid entry point is missing")?;
        let invalid = EntryPointRva::new(0x180).ok_or("invalid test entry point is missing")?;

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            Some(valid),
            &[],
        )?;
        let invalid_result = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            Some(invalid),
            &[],
        );

        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 16), 0x1002);
        assert!(invalid_result.is_err());
        Ok(())
    }

    #[test]
    fn recalculates_derived_optional_header_fields() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let section = 0x98 + 0xF0;
        put_u32(&mut memory, 0x98 + 4, 1);
        put_u32(&mut memory, 0x98 + 8, 2);
        put_u32(&mut memory, 0x98 + 12, 3);
        put_u32(&mut memory, 0x98 + 20, 4);
        put_u32(&mut memory, section + 36, 0xE000_00E0);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 4), 0x1000);
        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 8), 0x1000);
        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 12), 0x1000);
        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 20), 0x1000);
        Ok(())
    }

    #[test]
    fn removes_invalid_x64_unwind_entries() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let optional = 0x98;
        put_u32(&mut memory, optional + 112 + 3 * 8, 0x1100);
        put_u32(&mut memory, optional + 112 + 3 * 8 + 4, 12);
        put_u32(&mut memory, 0x1100, 0x1000);
        put_u32(&mut memory, 0x1104, 0x1010);
        put_u32(&mut memory, 0x1108, 0x1200);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(rebuilt.invalid_unwind_entries, 1);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        Ok(())
    }

    #[test]
    fn keeps_managed_unwind_entries_the_native_check_would_reject()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let optional = 0x98;
        put_u32(&mut memory, optional + 112 + 3 * 8, 0x1100);
        put_u32(&mut memory, optional + 112 + 3 * 8 + 4, 12);
        put_u32(&mut memory, 0x1100, 0x1000);
        put_u32(&mut memory, 0x1104, 0x1010);
        put_u32(&mut memory, 0x1108, 0x1200);
        put_u32(&mut memory, optional + 112 + 14 * 8, 0x1000);
        put_u32(&mut memory, optional + 112 + 14 * 8 + 4, 0x48);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(rebuilt.invalid_unwind_entries, 0);
        assert_eq!(get_u32(&rebuilt.bytes, optional + 112 + 3 * 8 + 4), 12);
        Ok(())
    }

    #[test]
    fn marks_an_image_with_a_com_descriptor_as_managed() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let optional = 0x98;
        let native = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;
        put_u32(&mut memory, optional + 112 + 14 * 8, 0x1000);
        put_u32(&mut memory, optional + 112 + 14 * 8 + 4, 0x48);
        let managed = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert!(!native.managed);
        assert!(managed.managed);
        Ok(())
    }

    #[test]
    fn recovers_section_access_from_committed_memory() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let section = 0x98 + 0xF0;
        put_u32(&mut memory, section + 36, IMAGE_SCN_CNT_INITIALIZED_DATA);
        let regions = [RegionEvidence {
            offset: 0x1000,
            size: 0x1000,
            readable: true,
            writable: false,
            executable: true,
        }];

        let rebuilt = rebuild(
            &memory,
            &regions,
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;
        let characteristics = get_u32(&rebuilt.bytes, section + 36);

        assert_ne!(characteristics & IMAGE_SCN_MEM_EXECUTE, 0);
        assert_ne!(characteristics & IMAGE_SCN_MEM_READ, 0);
        assert_ne!(characteristics & IMAGE_SCN_CNT_CODE, 0);
        assert_eq!(characteristics & IMAGE_SCN_MEM_WRITE, 0);
        Ok(())
    }

    #[test]
    fn repoints_debug_entries_at_the_rebuilt_layout() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let optional = 0x98;
        put_u32(&mut memory, optional + 112 + 6 * 8, 0x1100);
        put_u32(&mut memory, optional + 112 + 6 * 8 + 4, 28);
        put_u32(&mut memory, 0x1100 + 20, 0x1200);
        put_u32(&mut memory, 0x1100 + 24, 0xDEAD);

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(rebuilt.repaired_debug_entries, 1);
        assert_eq!(get_u32(&rebuilt.bytes, 0x300 + 24), 0x400);
        assert_ne!(get_u32(&rebuilt.bytes, 0x98 + 112 + 6 * 8), 0);
        Ok(())
    }

    #[test]
    fn recovers_runtime_data_up_to_the_declared_image_but_no_further()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let section = 0x98 + 0xF0;
        put_u32(&mut memory, section + 8, 0x100);
        memory.resize(0x3000, 0);
        memory[0x1900] = 0xC3;
        memory[0x2500] = 0xC3;
        let regions = [RegionEvidence {
            offset: 0x1000,
            size: 0x2000,
            readable: true,
            writable: false,
            executable: true,
        }];

        let rebuilt = rebuild(
            &memory,
            &regions,
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(get_u32(&rebuilt.bytes, section + 8), 0x901);
        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 56), 0x2000);
        assert_eq!(rebuilt.bytes[0xB00], 0xC3);
        assert!(rebuilt.bytes.len() < 0x1700);
        Ok(())
    }

    fn fixture_pe64() -> Vec<u8> {
        let mut image = vec![0u8; 0x2000];
        put_u16(&mut image, 0, 0x5A4D);
        put_u32(&mut image, 0x3c, 0x80);
        put_u32(&mut image, 0x80, 0x0000_4550);
        put_u16(&mut image, 0x84, 0x8664);
        put_u16(&mut image, 0x86, 1);
        put_u16(&mut image, 0x94, 0xF0);
        put_u16(&mut image, 0x96, 0x22);
        let optional = 0x98;
        put_u16(&mut image, optional, 0x20B);
        put_u32(&mut image, optional + 16, 0x1000);
        put_u64(&mut image, optional + 24, 0x0001_4000_0000);
        put_u32(&mut image, optional + 32, 0x1000);
        put_u32(&mut image, optional + 36, 0x200);
        put_u32(&mut image, optional + 56, 0x2000);
        put_u32(&mut image, optional + 60, 0x200);
        put_u32(&mut image, optional + 108, 16);
        let section = optional + 0xF0;
        image[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut image, section + 8, 0x1000);
        put_u32(&mut image, section + 12, 0x1000);
        put_u32(&mut image, section + 16, 0x200);
        put_u32(&mut image, section + 36, 0x6000_0020);
        image[0x1000..0x1004].copy_from_slice(&[0x90, 0x90, 0xC3, 0]);
        image
    }

    fn fixture_pe32() -> Vec<u8> {
        let mut image = vec![0u8; 0x2000];
        put_u16(&mut image, 0, 0x5A4D);
        put_u32(&mut image, 0x3c, 0x80);
        put_u32(&mut image, 0x80, 0x0000_4550);
        put_u16(&mut image, 0x84, 0x014C);
        put_u16(&mut image, 0x86, 1);
        put_u16(&mut image, 0x94, 0xE0);
        put_u16(&mut image, 0x96, 0x2102);
        let optional = 0x98;
        put_u16(&mut image, optional, 0x10B);
        put_u32(&mut image, optional + 16, 0x1000);
        put_u32(&mut image, optional + 28, 0x0040_0000);
        put_u32(&mut image, optional + 32, 0x1000);
        put_u32(&mut image, optional + 36, 0x200);
        put_u32(&mut image, optional + 56, 0x2000);
        put_u32(&mut image, optional + 60, 0x200);
        put_u32(&mut image, optional + 92, 16);
        let section = optional + 0xE0;
        image[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut image, section + 8, 0x1000);
        put_u32(&mut image, section + 12, 0x1000);
        put_u32(&mut image, section + 16, 0x200);
        put_u32(&mut image, section + 36, 0x6000_0020);
        image[0x1000..0x1004].copy_from_slice(&[0x55, 0x8B, 0xEC, 0xC3]);
        image
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn checksum_ignores_whatever_sat_in_the_field_before() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut image = fixture_pe64();
        let index = ExportIndex::build([]);
        let first = rebuild(&image, &[], 0x0000_7FF6_0000_0000, None, &index, None, &[])?;

        put_u32(&mut image, 0x98 + 64, 0xDEAD_BEEF);
        let second = rebuild(&image, &[], 0x0000_7FF6_0000_0000, None, &index, None, &[])?;

        assert_eq!(first.bytes, second.bytes);
        Ok(())
    }

    #[test]
    fn gives_an_all_zero_section_no_raw_data() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let section = 0x98 + 0xF0;
        for byte in memory.iter_mut().skip(0x1000) {
            *byte = 0;
        }

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(get_u32(&rebuilt.bytes, section + 16), 0);
        assert_eq!(get_u32(&rebuilt.bytes, section + 20), 0);
        assert_eq!(get_u32(&rebuilt.bytes, section + 12), 0x1000);
        Ok(())
    }

    #[test]
    fn reports_a_pdata_section_holding_no_runtime_functions()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let section = 0x98 + 0xF0;
        memory[section..section + 8].copy_from_slice(b".pdata  ");
        for byte in memory.iter_mut().take(0x1100).skip(0x1000) {
            *byte = 0xEE;
        }

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(rebuilt.invalid_pdata_sections, 1);
        Ok(())
    }

    #[test]
    fn leaves_a_section_alone_when_it_is_not_named_pdata() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut memory = fixture_pe64();
        for byte in memory.iter_mut().take(0x1100).skip(0x1000) {
            *byte = 0xEE;
        }

        let rebuilt = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            None,
            &[],
        )?;

        assert_eq!(rebuilt.invalid_pdata_sections, 0);
        Ok(())
    }
}
