use pelite::PeFile;

use crate::pe::exports::ExportIndex;
use crate::pe::image::{read_u16, read_u32, write_u16, write_u32, write_u64};
use crate::pe::imports::{ImportPlan, build_plan};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{EntryPointRva, PeKind, PeModel, RegionEvidence, Rva, SectionModel};
use crate::{AppError, AppResult};

const DOS_LFANEW_OFFSET: usize = 0x3c;
const SECTION_HEADER_SIZE: usize = 40;
const MAX_OUTPUT_SIZE: usize = 1024 * 1024 * 1024;
const SECURITY_DIRECTORY: usize = 4;
const DEBUG_DIRECTORY: usize = 6;
const EXCEPTION_DIRECTORY: usize = 3;
const IMPORT_DIRECTORY: usize = 1;
const IAT_DIRECTORY: usize = 12;
const MAX_DISK_HEADERS: usize = 1024 * 1024;
const RUNTIME_FUNCTION_SIZE: usize = 12;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const MEMPE_IMPORT_CHARACTERISTICS: u32 = 0xC000_0040;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
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
    pub(crate) ambiguous_imports: usize,
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
) -> AppResult<RebuiltImage> {
    let repaired;
    let (initial_image, disk_headers_used) = match parse_memory_image(memory) {
        Ok(image) => (image, false),
        Err(memory_error) => {
            let Some(disk_headers) = disk_headers else {
                return Err(memory_error);
            };
            repaired = merge_header_evidence(memory, disk_headers)?;
            let image = parse_memory_image(&repaired).map_err(|disk_error| {
                AppError::new(format!(
                    "memory headers are invalid ({memory_error}); disk header repair failed ({disk_error})"
                ))
            })?;
            (image, true)
        }
    };
    let recovered = recover_section_headers(initial_image.bytes(), initial_image.model(), regions)?;
    let image = match &recovered {
        Some(bytes) => parse_memory_image(bytes).map_err(|error| {
            AppError::new(format!(
                "memory-region header recovery produced an invalid PE: {error}"
            ))
        })?,
        None => initial_image,
    };
    let memory = image.bytes();
    let model = image.model();
    let section_table_end = model
        .sections
        .last()
        .map(|section| section.header_offset.saturating_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("PE has no section headers"))?;
    let header_size = align_up(section_table_end, model.file_alignment as usize)?;
    let layouts = layout_sections(model, memory.len(), header_size)?;
    let output_size = layouts
        .iter()
        .map(|layout| layout.raw_offset.saturating_add(layout.raw_size))
        .max()
        .unwrap_or(header_size)
        .max(header_size);
    if output_size > MAX_OUTPUT_SIZE {
        return Err(AppError::new(
            "rebuilt PE exceeds the 1 GiB output safety limit",
        ));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| AppError::new("not enough memory for the rebuilt PE"))?;
    output.resize(output_size, 0);
    let copied_headers = header_size.min(memory.len());
    output[..copied_headers].copy_from_slice(&memory[..copied_headers]);

    write_u16(&mut output, 0, 0x5A4D)?;
    write_u32(
        &mut output,
        DOS_LFANEW_OFFSET,
        u32::try_from(model.nt_offset)
            .map_err(|_| AppError::new("NT header offset does not fit a PE field"))?,
    )?;
    write_image_base(&mut output, model, observed_base)?;
    let image_size = rebuilt_image_size(model)?;
    write_u32(&mut output, model.size_of_image_offset, image_size)?;
    write_u32(
        &mut output,
        model.size_of_headers_offset,
        u32::try_from(header_size)
            .map_err(|_| AppError::new("rebuilt header size does not fit a PE field"))?,
    )?;
    write_u32(
        &mut output,
        model.number_of_directories_offset,
        u32::try_from(model.directory_count)
            .map_err(|_| AppError::new("directory count does not fit a PE field"))?,
    )?;

    for layout in &layouts {
        write_u32(
            &mut output,
            layout.model.header_offset.saturating_add(16),
            u32::try_from(layout.raw_size)
                .map_err(|_| AppError::new("section raw size does not fit a PE field"))?,
        )?;
        write_u32(
            &mut output,
            layout.model.header_offset.saturating_add(20),
            u32::try_from(layout.raw_offset)
                .map_err(|_| AppError::new("section file offset does not fit a PE field"))?,
        )?;
        let source_offset = layout.model.virtual_address.get() as usize;
        let source_end = source_offset
            .checked_add(layout.source_length)
            .ok_or_else(|| AppError::new("section source range overflowed"))?;
        let destination_end = layout
            .raw_offset
            .checked_add(layout.source_length)
            .ok_or_else(|| AppError::new("section output range overflowed"))?;
        let source = memory
            .get(source_offset..source_end)
            .ok_or_else(|| AppError::new("section source range is outside captured memory"))?;
        let destination = output
            .get_mut(layout.raw_offset..destination_end)
            .ok_or_else(|| AppError::new("section output range is outside rebuilt PE"))?;
        destination.copy_from_slice(source);
    }

    let mut cleared_directories = clear_bad_directories(&mut output, model, &layouts, header_size)?;
    let invalid_unwind_entries =
        repair_exception_directory(&mut output, model, &layouts, header_size)?;
    let import_plan = build_plan(&image, observed_base, exports);
    if !import_plan.groups.is_empty() {
        append_import_section(&mut output, model, &import_plan)?;
    } else if !import_plan.existing_valid {
        cleared_directories = clear_directory(&mut output, model, IMPORT_DIRECTORY)?
            .saturating_add(cleared_directories);
    }
    apply_entry_point(&mut output, model, entry_point)?;
    write_derived_header_fields(&mut output, model)?;
    PeFile::from_bytes(&output).map_err(|error| {
        AppError::new(format!("rebuilt PE failed independent reparse: {error}"))
    })?;

    Ok(RebuiltImage {
        bytes: output,
        kind: model.kind,
        is_dll: model.is_dll,
        section_count: model
            .sections
            .len()
            .saturating_add(usize::from(!import_plan.groups.is_empty())),
        salvaged_headers: model.salvaged,
        disk_headers_used,
        cleared_directories,
        invalid_unwind_entries,
        imports_rebuilt: import_plan.recovered,
        ambiguous_imports: import_plan.ambiguous,
    })
}

fn recover_section_headers(
    memory: &[u8],
    model: &PeModel,
    regions: &[RegionEvidence],
) -> AppResult<Option<Vec<u8>>> {
    if regions.is_empty() {
        return Ok(None);
    }
    let mut sections = model.sections.iter().collect::<Vec<_>>();
    sections.sort_unstable_by_key(|section| section.virtual_address);
    let mut recovered = None;
    let mut image_end = model.image_size as usize;
    for (index, section) in sections.iter().enumerate() {
        let start = section.virtual_address.get() as usize;
        let limit = sections
            .get(index + 1)
            .map(|next| next.virtual_address.get() as usize)
            .unwrap_or(memory.len())
            .min(memory.len());
        if start >= limit {
            continue;
        }
        let declared = section.virtual_size.max(section.raw_size) as usize;
        let expanded = expanded_section_length(memory, regions, start, limit, declared);
        let section_end = start.saturating_add(expanded).min(limit);
        let characteristics =
            recovered_characteristics(section.characteristics, regions, start, section_end);
        if expanded > declared {
            let virtual_size = u32::try_from(expanded)
                .map_err(|_| AppError::new("recovered section size exceeds u32"))?;
            let output = recovered.get_or_insert_with(|| memory.to_vec());
            write_u32(
                output,
                section.header_offset.saturating_add(8),
                virtual_size,
            )?;
            image_end = image_end.max(start.saturating_add(expanded));
        }
        if characteristics != section.characteristics {
            let output = recovered.get_or_insert_with(|| memory.to_vec());
            write_u32(
                output,
                section.header_offset.saturating_add(36),
                characteristics,
            )?;
        }
    }
    if image_end > model.image_size as usize {
        let image_size = align_up(image_end, model.section_alignment as usize)?;
        let image_size = u32::try_from(image_size)
            .map_err(|_| AppError::new("recovered image size exceeds u32"))?;
        let output = recovered.get_or_insert_with(|| memory.to_vec());
        write_u32(output, model.size_of_image_offset, image_size)?;
    }
    Ok(recovered)
}

fn expanded_section_length(
    memory: &[u8],
    regions: &[RegionEvidence],
    start: usize,
    limit: usize,
    declared: usize,
) -> usize {
    let scan_start = start.saturating_add(declared).min(limit);
    let mut last_byte = scan_start;
    for region in regions.iter().filter(|region| region.readable) {
        let region_end = region.offset.saturating_add(region.size);
        let range_start = scan_start.max(region.offset);
        let range_end = limit.min(region_end).min(memory.len());
        if range_start >= range_end {
            continue;
        }
        let Some(bytes) = memory.get(range_start..range_end) else {
            continue;
        };
        if let Some(index) = bytes.iter().rposition(|byte| *byte != 0) {
            last_byte = last_byte.max(range_start.saturating_add(index).saturating_add(1));
        }
    }
    last_byte.saturating_sub(start).max(declared)
}

fn recovered_characteristics(
    characteristics: u32,
    regions: &[RegionEvidence],
    start: usize,
    end: usize,
) -> u32 {
    let coverage = ProtectionCoverage::measure(regions, start, end);
    let mut recovered = characteristics;
    if coverage.executable > 0 {
        recovered |= IMAGE_SCN_MEM_EXECUTE;
    }
    if coverage.readable > 0 {
        recovered |= IMAGE_SCN_MEM_READ;
    }
    if coverage.write_is_substantial(end.saturating_sub(start)) {
        recovered |= IMAGE_SCN_MEM_WRITE;
    }
    recovered
}

#[derive(Default)]
struct ProtectionCoverage {
    committed: usize,
    readable: usize,
    writable: usize,
    executable: usize,
}

impl ProtectionCoverage {
    fn measure(regions: &[RegionEvidence], start: usize, end: usize) -> Self {
        let mut coverage = Self::default();
        for region in regions {
            let region_end = region.offset.saturating_add(region.size);
            let overlap_start = start.max(region.offset);
            let overlap_end = end.min(region_end);
            let bytes = overlap_end.saturating_sub(overlap_start);
            if bytes == 0 {
                continue;
            }
            coverage.committed = coverage.committed.saturating_add(bytes);
            if region.readable {
                coverage.readable = coverage.readable.saturating_add(bytes);
            }
            if region.writable {
                coverage.writable = coverage.writable.saturating_add(bytes);
            }
            if region.executable {
                coverage.executable = coverage.executable.saturating_add(bytes);
            }
        }
        coverage
    }

    fn write_is_substantial(&self, section_size: usize) -> bool {
        if self.committed == 0 || self.writable == 0 {
            return false;
        }
        let unanimous = self.writable >= section_size && self.committed >= section_size;
        let substantial = self.writable >= PAGE_SIZE.saturating_mul(2)
            && self.writable.saturating_mul(2) >= section_size;
        unanimous || substantial
    }
}

fn layout_sections<'a>(
    model: &'a PeModel,
    memory_size: usize,
    header_size: usize,
) -> AppResult<Vec<SectionLayout<'a>>> {
    let mut sections = model.sections.iter().collect::<Vec<_>>();
    sections.sort_unstable_by_key(|section| section.virtual_address);
    let mut layouts = Vec::with_capacity(sections.len());
    let mut raw_offset = header_size;
    for (index, section) in sections.iter().enumerate() {
        let source_offset = section.virtual_address.get() as usize;
        let declared_length = section.virtual_size.max(section.raw_size) as usize;
        let next_rva = sections
            .get(index + 1)
            .map(|next| next.virtual_address.get() as usize)
            .unwrap_or(memory_size);
        let until_next = next_rva.saturating_sub(source_offset);
        let available = memory_size.saturating_sub(source_offset);
        let source_length = declared_length.min(until_next).min(available);
        let raw_size = if source_length == 0 {
            0
        } else {
            align_up(source_length, model.file_alignment as usize)?
        };
        layouts.push(SectionLayout {
            model: section,
            source_length,
            raw_offset: if raw_size == 0 { 0 } else { raw_offset },
            raw_size,
        });
        raw_offset = raw_offset
            .checked_add(raw_size)
            .ok_or_else(|| AppError::new("rebuilt section layout overflowed"))?;
    }
    Ok(layouts)
}

fn rebuilt_image_size(model: &PeModel) -> AppResult<u32> {
    let maximum_end = model
        .sections
        .iter()
        .map(|section| {
            u64::from(section.virtual_address.get())
                + u64::from(section.virtual_size.max(section.raw_size))
        })
        .max()
        .unwrap_or(0);
    let aligned = align_up_u64(maximum_end, u64::from(model.section_alignment))?;
    u32::try_from(aligned).map_err(|_| AppError::new("rebuilt image size exceeds u32"))
}

fn write_image_base(output: &mut [u8], model: &PeModel, observed_base: usize) -> AppResult<()> {
    match model.kind {
        PeKind::Pe32 => write_u32(
            output,
            model.image_base_offset,
            u32::try_from(observed_base)
                .map_err(|_| AppError::new("observed PE32 image base exceeds 32 bits"))?,
        ),
        PeKind::Pe32Plus => write_u64(output, model.image_base_offset, observed_base as u64),
    }
}

fn clear_bad_directories(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<usize> {
    let mut cleared = 0usize;
    for index in 0..model.directory_count {
        let entry_offset = model
            .directory_offset(index)?
            .ok_or_else(|| AppError::new("data-directory slot is missing"))?;
        let rva = read_u32(output, entry_offset)?;
        let size = read_u32(output, entry_offset.saturating_add(4))?;
        if rva == 0 && size == 0 {
            continue;
        }
        let valid = index != SECURITY_DIRECTORY
            && index != DEBUG_DIRECTORY
            && directory_is_mapped(rva, size, layouts, header_size);
        if !valid {
            write_u32(output, entry_offset, 0)?;
            write_u32(output, entry_offset.saturating_add(4), 0)?;
            cleared = cleared.saturating_add(1);
        }
    }
    Ok(cleared)
}

fn merge_header_evidence(memory: &[u8], disk: &[u8]) -> AppResult<Vec<u8>> {
    let disk_image = parse_disk_image(disk)?;
    let model = disk_image.model();
    let memory_entry_point = validate_header_evidence(memory, model)?;
    let header_size = disk_header_size(disk, model)?;
    if header_size > memory.len() {
        return Err(AppError::new(
            "disk PE headers are larger than the captured image",
        ));
    }
    let mut repaired = memory.to_vec();
    let source = disk
        .get(..header_size)
        .ok_or_else(|| AppError::new("disk PE headers are truncated"))?;
    let destination = repaired
        .get_mut(..header_size)
        .ok_or_else(|| AppError::new("captured PE header range is missing"))?;
    destination.copy_from_slice(source);
    if let Some(entry_point) = memory_entry_point {
        write_u32(&mut repaired, model.entry_point_offset, entry_point)?;
    }
    Ok(repaired)
}

fn validate_header_evidence(memory: &[u8], model: &PeModel) -> AppResult<Option<u32>> {
    if model.image_size as usize > memory.len() {
        return Err(AppError::new("disk SizeOfImage exceeds the captured image"));
    }
    let memory_machine = read_u16(memory, model.nt_offset.saturating_add(4)).unwrap_or(0);
    let disk_machine = match model.kind {
        PeKind::Pe32 => 0x014C,
        PeKind::Pe32Plus => 0x8664,
    };
    if matches!(memory_machine, 0x014C | 0x8664) && memory_machine != disk_machine {
        return Err(AppError::new(
            "disk headers conflict with the captured image architecture",
        ));
    }
    let memory_magic = read_u16(memory, model.entry_point_offset.saturating_sub(16)).unwrap_or(0);
    let disk_magic = match model.kind {
        PeKind::Pe32 => 0x010B,
        PeKind::Pe32Plus => 0x020B,
    };
    if matches!(memory_magic, 0x010B | 0x020B) && memory_magic != disk_magic {
        return Err(AppError::new(
            "disk headers conflict with the captured optional-header format",
        ));
    }
    let matching_structure = memory_machine == disk_machine || memory_magic == disk_magic;
    let entry_point = read_u32(memory, model.entry_point_offset)
        .ok()
        .filter(|rva| matching_structure && model.executable_rva(Rva(*rva)));
    Ok(entry_point)
}

fn disk_header_size(disk: &[u8], model: &PeModel) -> AppResult<usize> {
    let section_table_end = model
        .sections
        .last()
        .and_then(|section| section.header_offset.checked_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("disk PE has no complete section table"))?;
    let size = align_up(section_table_end, model.file_alignment as usize)?;
    if size > MAX_DISK_HEADERS || size > disk.len() {
        return Err(AppError::new(
            "disk PE header size is outside the 1 MiB safety limit",
        ));
    }
    Ok(size)
}

fn apply_entry_point(
    output: &mut [u8],
    model: &PeModel,
    entry_point: Option<EntryPointRva>,
) -> AppResult<()> {
    let Some(entry_point) = entry_point else {
        return Ok(());
    };
    let rva = Rva(entry_point.get());
    if !model.executable_rva(rva) {
        return Err(AppError::new(format!(
            "manual entry point RVA 0x{:X} is not inside an executable section",
            entry_point.get()
        )));
    }
    write_u32(output, model.entry_point_offset, entry_point.get())
}

fn write_derived_header_fields(output: &mut [u8], model: &PeModel) -> AppResult<()> {
    let section_count = usize::from(read_u16(output, model.nt_offset.saturating_add(6))?);
    let maximum_section_count = model.sections.len().saturating_add(1);
    if section_count < model.sections.len() || section_count > maximum_section_count {
        return Err(AppError::new("rebuilt PE has an invalid section count"));
    }
    let first_section = model
        .sections
        .first()
        .map(|section| section.header_offset)
        .ok_or_else(|| AppError::new("rebuilt PE has no section table"))?;
    let mut sizes = DerivedSizes::default();
    for index in 0..section_count {
        let offset = first_section
            .checked_add(index.saturating_mul(SECTION_HEADER_SIZE))
            .ok_or_else(|| AppError::new("rebuilt section header offset overflowed"))?;
        sizes.add_section(output, offset, model.file_alignment)?;
    }
    write_u32(output, model.size_of_code_offset, sizes.code)?;
    write_u32(
        output,
        model.size_of_initialized_data_offset,
        sizes.initialized_data,
    )?;
    write_u32(
        output,
        model.size_of_uninitialized_data_offset,
        sizes.uninitialized_data,
    )?;
    write_u32(output, model.base_of_code_offset, sizes.base_of_code)
}

#[derive(Default)]
struct DerivedSizes {
    code: u32,
    initialized_data: u32,
    uninitialized_data: u32,
    base_of_code: u32,
}

impl DerivedSizes {
    fn add_section(&mut self, output: &[u8], offset: usize, file_alignment: u32) -> AppResult<()> {
        let virtual_size = read_u32(output, offset.saturating_add(8))?;
        let virtual_address = read_u32(output, offset.saturating_add(12))?;
        let raw_size = read_u32(output, offset.saturating_add(16))?;
        let characteristics = read_u32(output, offset.saturating_add(36))?;
        if characteristics & IMAGE_SCN_CNT_CODE != 0 {
            self.code = add_size(self.code, raw_size, "code size")?;
            if self.base_of_code == 0 || virtual_address < self.base_of_code {
                self.base_of_code = virtual_address;
            }
        }
        if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            self.initialized_data =
                add_size(self.initialized_data, raw_size, "initialized-data size")?;
        }
        if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            let aligned = align_up_u64(u64::from(virtual_size), u64::from(file_alignment))?;
            let aligned = u32::try_from(aligned)
                .map_err(|_| AppError::new("uninitialized-data size exceeds u32"))?;
            self.uninitialized_data =
                add_size(self.uninitialized_data, aligned, "uninitialized-data size")?;
        }
        Ok(())
    }
}

fn add_size(left: u32, right: u32, name: &str) -> AppResult<u32> {
    left.checked_add(right)
        .ok_or_else(|| AppError::new(format!("{name} overflowed")))
}

fn repair_exception_directory(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<usize> {
    if model.kind != PeKind::Pe32Plus || EXCEPTION_DIRECTORY >= model.directory_count {
        return Ok(0);
    }
    let entry_offset = model
        .directory_offset(EXCEPTION_DIRECTORY)?
        .ok_or_else(|| AppError::new("exception-directory slot is missing"))?;
    let rva = read_u32(output, entry_offset)?;
    let size = read_u32(output, entry_offset.saturating_add(4))? as usize;
    if rva == 0 || size == 0 {
        return Ok(0);
    }
    let Some(file_offset) = rva_to_file(rva, layouts, header_size) else {
        return Ok(0);
    };
    let count = size / RUNTIME_FUNCTION_SIZE;
    let mut valid = Vec::<[u8; RUNTIME_FUNCTION_SIZE]>::with_capacity(count);
    let mut invalid = usize::from(!size.is_multiple_of(RUNTIME_FUNCTION_SIZE));
    for index in 0..count {
        let offset = file_offset
            .checked_add(index.saturating_mul(RUNTIME_FUNCTION_SIZE))
            .ok_or_else(|| AppError::new("runtime-function offset overflowed"))?;
        let Some(entry) = output.get(offset..offset.saturating_add(RUNTIME_FUNCTION_SIZE)) else {
            invalid = invalid.saturating_add(count.saturating_sub(index));
            break;
        };
        if runtime_function_is_valid(output, entry, model, layouts, header_size) {
            let mut copy = [0u8; RUNTIME_FUNCTION_SIZE];
            copy.copy_from_slice(entry);
            valid.push(copy);
        } else {
            invalid = invalid.saturating_add(1);
        }
    }
    if invalid == 0 {
        return Ok(0);
    }
    let range_end = file_offset
        .checked_add(size)
        .ok_or_else(|| AppError::new("exception-directory range overflowed"))?;
    let destination = output
        .get_mut(file_offset..range_end)
        .ok_or_else(|| AppError::new("exception directory lies outside the rebuilt PE"))?;
    destination.fill(0);
    for (index, entry) in valid.iter().enumerate() {
        let start = index.saturating_mul(RUNTIME_FUNCTION_SIZE);
        let end = start.saturating_add(RUNTIME_FUNCTION_SIZE);
        if let Some(slot) = destination.get_mut(start..end) {
            slot.copy_from_slice(entry);
        }
    }
    if valid.is_empty() {
        write_u32(output, entry_offset, 0)?;
        write_u32(output, entry_offset.saturating_add(4), 0)?;
    } else {
        let new_size = valid
            .len()
            .checked_mul(RUNTIME_FUNCTION_SIZE)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| AppError::new("exception-directory size overflowed"))?;
        write_u32(output, entry_offset.saturating_add(4), new_size)?;
    }
    Ok(invalid)
}

fn runtime_function_is_valid(
    output: &[u8],
    entry: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> bool {
    let Ok(begin) = read_u32(entry, 0) else {
        return false;
    };
    let Ok(end) = read_u32(entry, 4) else {
        return false;
    };
    let Ok(unwind) = read_u32(entry, 8) else {
        return false;
    };
    if begin >= end || !model.executable_rva(Rva(begin)) || !model.executable_rva(Rva(end - 1)) {
        return false;
    }
    let Some(unwind_offset) = rva_to_file(unwind, layouts, header_size) else {
        return false;
    };
    let Some(first) = output.get(unwind_offset).copied() else {
        return false;
    };
    matches!(first & 0x07, 1 | 2)
}

fn append_import_section(
    output: &mut Vec<u8>,
    model: &PeModel,
    plan: &ImportPlan,
) -> AppResult<()> {
    if IMPORT_DIRECTORY >= model.directory_count {
        return Err(AppError::new(
            "PE optional header has no import-directory slot",
        ));
    }
    let section_header = model
        .sections
        .iter()
        .map(|section| section.header_offset)
        .max()
        .and_then(|offset| offset.checked_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("new section-header offset overflowed"))?;
    let header_limit = usize::try_from(read_u32(output, model.size_of_headers_offset)?)
        .map_err(|_| AppError::new("PE header size does not fit memory"))?;
    if section_header.saturating_add(SECTION_HEADER_SIZE) > header_limit {
        return Err(AppError::new(
            "PE headers have no room for the recovered import section",
        ));
    }
    let virtual_address = align_up_u64(
        u64::from(read_u32(output, model.size_of_image_offset)?),
        u64::from(model.section_alignment),
    )?;
    let virtual_address = u32::try_from(virtual_address)
        .map_err(|_| AppError::new("import section RVA exceeds u32"))?;
    let payload = build_import_payload(plan, model.kind, virtual_address)?;
    let raw_offset = align_up(output.len(), model.file_alignment as usize)?;
    let raw_size = align_up(payload.len(), model.file_alignment as usize)?;
    let final_size = raw_offset
        .checked_add(raw_size)
        .ok_or_else(|| AppError::new("import section output size overflowed"))?;
    if final_size > MAX_OUTPUT_SIZE {
        return Err(AppError::new(
            "recovered imports exceed the 1 GiB output safety limit",
        ));
    }
    output.resize(final_size, 0);
    let payload_end = raw_offset
        .checked_add(payload.len())
        .ok_or_else(|| AppError::new("import payload range overflowed"))?;
    output
        .get_mut(raw_offset..payload_end)
        .ok_or_else(|| AppError::new("import payload lies outside the rebuilt PE"))?
        .copy_from_slice(&payload);

    let name = output
        .get_mut(section_header..section_header.saturating_add(8))
        .ok_or_else(|| AppError::new("new section name lies outside the PE headers"))?;
    name.copy_from_slice(b".mempe\0\0");
    write_u32(
        output,
        section_header.saturating_add(8),
        u32::try_from(payload.len())
            .map_err(|_| AppError::new("import payload size exceeds u32"))?,
    )?;
    write_u32(output, section_header.saturating_add(12), virtual_address)?;
    write_u32(
        output,
        section_header.saturating_add(16),
        u32::try_from(raw_size).map_err(|_| AppError::new("import raw size exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(20),
        u32::try_from(raw_offset).map_err(|_| AppError::new("import file offset exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(36),
        MEMPE_IMPORT_CHARACTERISTICS,
    )?;
    let section_count_offset = model.nt_offset.saturating_add(6);
    let section_count = read_u16(output, section_count_offset)?
        .checked_add(1)
        .ok_or_else(|| AppError::new("section count overflowed"))?;
    write_u16(output, section_count_offset, section_count)?;
    let image_end = u64::from(virtual_address)
        .checked_add(payload.len() as u64)
        .ok_or_else(|| AppError::new("import virtual range overflowed"))?;
    let image_size = align_up_u64(image_end, u64::from(model.section_alignment))?;
    write_u32(
        output,
        model.size_of_image_offset,
        u32::try_from(image_size).map_err(|_| AppError::new("image size exceeds u32"))?,
    )?;
    let descriptor_size = plan
        .groups
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(IMPORT_DESCRIPTOR_SIZE))
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| AppError::new("import descriptor size overflowed"))?;
    write_directory(
        output,
        model,
        IMPORT_DIRECTORY,
        virtual_address,
        descriptor_size,
    )?;
    clear_directory(output, model, IAT_DIRECTORY)?;
    Ok(())
}

fn build_import_payload(plan: &ImportPlan, kind: PeKind, section_rva: u32) -> AppResult<Vec<u8>> {
    let width = if kind == PeKind::Pe32 { 4 } else { 8 };
    let descriptor_bytes = plan
        .groups
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(IMPORT_DESCRIPTOR_SIZE))
        .ok_or_else(|| AppError::new("import descriptor size overflowed"))?;
    let mut payload = vec![0u8; descriptor_bytes];
    for (group_index, group) in plan.groups.iter().enumerate() {
        align_vec(&mut payload, width);
        let lookup_offset = payload.len();
        let lookup_size = group
            .entries
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(width))
            .ok_or_else(|| AppError::new("import lookup-table size overflowed"))?;
        payload.resize(payload.len().saturating_add(lookup_size), 0);
        for (entry_index, entry) in group.entries.iter().enumerate() {
            let thunk = if let Some(name) = &entry.name {
                align_vec(&mut payload, 2);
                let name_offset = payload.len();
                payload.extend_from_slice(&[0, 0]);
                append_ascii(&mut payload, name)?;
                u64::from(section_rva)
                    .checked_add(name_offset as u64)
                    .ok_or_else(|| AppError::new("import name RVA overflowed"))?
            } else {
                let flag = if kind == PeKind::Pe32 {
                    0x8000_0000u64
                } else {
                    0x8000_0000_0000_0000u64
                };
                flag | u64::from(entry.ordinal & 0xffff)
            };
            let thunk_offset = lookup_offset
                .checked_add(entry_index.saturating_mul(width))
                .ok_or_else(|| AppError::new("import thunk offset overflowed"))?;
            write_thunk(&mut payload, thunk_offset, kind, thunk)?;
        }
        let module_offset = payload.len();
        append_ascii(&mut payload, &group.module)?;
        let descriptor = group_index.saturating_mul(IMPORT_DESCRIPTOR_SIZE);
        write_u32(
            &mut payload,
            descriptor,
            section_rva
                .checked_add(
                    u32::try_from(lookup_offset)
                        .map_err(|_| AppError::new("import lookup-table offset exceeds u32"))?,
                )
                .ok_or_else(|| AppError::new("import lookup-table RVA overflowed"))?,
        )?;
        write_u32(
            &mut payload,
            descriptor.saturating_add(12),
            section_rva
                .checked_add(
                    u32::try_from(module_offset)
                        .map_err(|_| AppError::new("import module offset exceeds u32"))?,
                )
                .ok_or_else(|| AppError::new("import module RVA overflowed"))?,
        )?;
        write_u32(
            &mut payload,
            descriptor.saturating_add(16),
            group.first_thunk,
        )?;
    }
    Ok(payload)
}

fn append_ascii(bytes: &mut Vec<u8>, value: &str) -> AppResult<()> {
    if value.is_empty() || !value.is_ascii() || value.as_bytes().contains(&0) {
        return Err(AppError::new("import name is not valid ASCII"));
    }
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    Ok(())
}

fn align_vec(bytes: &mut Vec<u8>, alignment: usize) {
    let padding = (alignment - bytes.len() % alignment) % alignment;
    bytes.resize(bytes.len().saturating_add(padding), 0);
}

fn write_thunk(bytes: &mut [u8], offset: usize, kind: PeKind, value: u64) -> AppResult<()> {
    match kind {
        PeKind::Pe32 => write_u32(
            bytes,
            offset,
            u32::try_from(value).map_err(|_| AppError::new("PE32 import thunk exceeds u32"))?,
        ),
        PeKind::Pe32Plus => write_u64(bytes, offset, value),
    }
}

fn write_directory(
    output: &mut [u8],
    model: &PeModel,
    index: usize,
    rva: u32,
    size: u32,
) -> AppResult<()> {
    let offset = model
        .directory_offset(index)?
        .ok_or_else(|| AppError::new("PE has no requested data-directory slot"))?;
    write_u32(output, offset, rva)?;
    write_u32(output, offset.saturating_add(4), size)
}

fn clear_directory(output: &mut [u8], model: &PeModel, index: usize) -> AppResult<usize> {
    let Some(offset) = model.directory_offset(index)? else {
        return Ok(0);
    };
    let was_set =
        read_u32(output, offset)? != 0 || read_u32(output, offset.saturating_add(4))? != 0;
    write_u32(output, offset, 0)?;
    write_u32(output, offset.saturating_add(4), 0)?;
    Ok(usize::from(was_set))
}

fn rva_to_file(rva: u32, layouts: &[SectionLayout<'_>], header_size: usize) -> Option<usize> {
    let rva = rva as usize;
    if rva < header_size {
        return Some(rva);
    }
    layouts.iter().find_map(|layout| {
        let start = layout.model.virtual_address.get() as usize;
        let delta = rva.checked_sub(start)?;
        (delta < layout.source_length).then(|| layout.raw_offset.saturating_add(delta))
    })
}

fn directory_is_mapped(
    rva: u32,
    size: u32,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> bool {
    if size == 0 {
        return false;
    }
    let start = rva as usize;
    let Some(end) = start.checked_add(size as usize) else {
        return false;
    };
    if end <= header_size {
        return true;
    }
    layouts.iter().any(|layout| {
        let section_start = layout.model.virtual_address.get() as usize;
        let section_end = section_start.saturating_add(layout.source_length);
        start >= section_start && end <= section_end
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

    use super::{
        IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
        rebuild, recovered_characteristics,
    };
    use crate::pe::{EntryPointRva, ExportIndex, PeKind, RegionEvidence};

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
        )?;
        let invalid_result = rebuild(
            &memory,
            &[],
            0x0000_7FF6_0000_0000,
            None,
            &ExportIndex::default(),
            Some(invalid),
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
        )?;

        assert_eq!(rebuilt.invalid_unwind_entries, 1);
        assert!(PeFile::from_bytes(&rebuilt.bytes).is_ok());
        Ok(())
    }

    #[test]
    fn recovers_section_access_from_committed_memory() -> Result<(), Box<dyn std::error::Error>> {
        let mut memory = fixture_pe64();
        let section = 0x98 + 0xF0;
        put_u32(&mut memory, section + 36, IMAGE_SCN_CNT_CODE);
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
        )?;
        let characteristics = get_u32(&rebuilt.bytes, section + 36);

        assert_ne!(characteristics & IMAGE_SCN_MEM_EXECUTE, 0);
        assert_ne!(characteristics & IMAGE_SCN_MEM_READ, 0);
        assert_eq!(characteristics & IMAGE_SCN_MEM_WRITE, 0);
        Ok(())
    }

    #[test]
    fn requires_substantial_write_coverage() {
        let mut regions = [
            RegionEvidence {
                offset: 0x1000,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: false,
            },
            RegionEvidence {
                offset: 0x2000,
                size: 0x3000,
                readable: true,
                writable: false,
                executable: false,
            },
        ];

        let sparse = recovered_characteristics(0, &regions, 0x1000, 0x5000);
        let retained = recovered_characteristics(IMAGE_SCN_MEM_WRITE, &regions, 0x1000, 0x5000);
        regions[0].size = 0x2000;
        regions[1].offset = 0x3000;
        regions[1].size = 0x2000;
        let substantial = recovered_characteristics(0, &regions, 0x1000, 0x5000);

        assert_eq!(sparse & IMAGE_SCN_MEM_WRITE, 0);
        assert_ne!(retained & IMAGE_SCN_MEM_WRITE, 0);
        assert_ne!(substantial & IMAGE_SCN_MEM_WRITE, 0);
    }

    #[test]
    fn recovers_runtime_data_beyond_declared_image_size() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut memory = fixture_pe64();
        memory.resize(0x3000, 0);
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
        )?;
        let section = 0x98 + 0xF0;

        assert_eq!(get_u32(&rebuilt.bytes, section + 8), 0x1501);
        assert_eq!(get_u32(&rebuilt.bytes, 0x98 + 56), 0x3000);
        assert_eq!(rebuilt.bytes[0x1700], 0xC3);
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
}
