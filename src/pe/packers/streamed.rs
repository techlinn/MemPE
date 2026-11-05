use std::ops::Range;

use super::tables::{
    CODE_SECTION, DATA_SECTION, DEBUG_ADDRESS_OFFSET, DEBUG_ENTRY_SIZE, DEBUG_SIZE_OFFSET,
    LinkerBounds, RESOURCE_DATA_SIZE_OFFSET, ResourceLayout, Restoration, SectionHints,
    SectionPiece, THUNK_SIZE, apply_listed_imports, clear_directory, debug_timestamp,
    find_relocation_table, fresh_image, iat_span, lay_out_resources, linker_bounds,
    lowest_moved_leaf, map_disk_image, name_sections, pogo_parts, pogo_sections,
    pogo_tls_directory, recover_directories, relocations_intact, repair_icon_groups,
    replace_first_section, resource_layout, restore_moved_resources, restore_tls, security_cookie,
    set_directory, split_merged_section, walk_resources,
};
use super::{ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked};
use crate::pe::image::{read_u16, read_u32, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DEBUG_DIRECTORY, DELAY_IMPORT_DIRECTORY,
    DYNAMIC_BASE, IMAGE_SCN_MEM_WRITE, LOAD_CONFIG_DIRECTORY, PeImage, PeModel, RESOURCE_DIRECTORY,
};

const TIMESTAMP_OFFSET: usize = 8;
pub(super) const EBX: u8 = 3;
pub(super) const ESI: u8 = 6;
pub(super) const EDI: u8 = 7;

pub(super) struct Load {
    pub(super) at: usize,
    pub(super) register: u8,
    pub(super) value: usize,
}

pub(super) struct ListedImports {
    pub(super) modules: Vec<ModuleImports>,
    pub(super) end_markers: Vec<usize>,
    pub(super) written: Range<usize>, // import data the stub rewrites while it reads it
    pub(super) names_end: usize,
}

pub(super) struct StreamedImage {
    pub(super) name: &'static str,
    pub(super) version: &'static str,
    pub(super) entry: usize,
    pub(super) image: Range<usize>,
    pub(super) image_end: usize,
    pub(super) original: Vec<u8>,
    pub(super) beneath_imports: Option<(usize, Vec<u8>)>,
    pub(super) imports: Option<ListedImports>,
    pub(super) section_starts: Option<Vec<usize>>,
    pub(super) keeps_code_fields: bool,
}

struct Located {
    bounds: Option<LinkerBounds>,
    resources: Option<usize>,
    relocations: Option<Range<usize>>,
}

struct Evidence<'a> {
    memory: &'a [u8],
    original: &'a [u8],
    finished: bool,
    stub_writes: [Range<usize>; 2],
    constants_start: Option<usize>,
    names_end: usize,
}

impl Evidence<'_> {
    fn untouched(&self, range: Range<usize>) -> bool {
        !self.finished
            || range.into_iter().all(|at| {
                self.stub_writes.iter().any(|written| written.contains(&at))
                    || self.memory.get(at) == self.original.get(at)
            })
    }
}

pub(super) fn restore(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    streamed: StreamedImage,
) -> Option<Unpacked> {
    let StreamedImage {
        name,
        version,
        entry,
        image: image_range,
        image_end,
        original,
        beneath_imports,
        imports: listed,
        section_starts,
        keeps_code_fields,
    } = streamed;
    let original = original.as_slice();
    let model = image.model();
    let end = image_range.end;
    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(name, Some(version.to_owned()));

    let layout = resource_layout(
        image.bytes(),
        model,
        listed
            .iter()
            .flat_map(|listed| &listed.modules)
            .map(|module| module.module.as_str()),
    );

    let finished = listed
        .as_ref()
        .is_some_and(|listed| stub_finished(image.bytes(), original, &listed.modules));
    if !finished {
        restored
            .get_mut(image_range.clone())?
            .copy_from_slice(original.get(image_range.clone())?);
        report.restored.push("code and data from the packed data");
    }

    let iat = listed.as_ref().and_then(|listed| {
        iat_span(
            listed
                .modules
                .iter()
                .map(|module| (module.first_thunk as usize, module.functions.len())),
            THUNK_SIZE,
        )
        .map(|(start, size)| start..start + size)
    });
    let evidence = Evidence {
        memory: image.bytes(),
        original,
        finished,
        stub_writes: [
            iat.clone().unwrap_or_default(),
            listed
                .as_ref()
                .map(|listed| listed.written.clone())
                .unwrap_or_default(),
        ],
        constants_start: iat.as_ref().map(|iat| iat.start),
        names_end: listed.as_ref().map_or(0, |listed| listed.names_end),
    };

    write_u32(
        &mut restored,
        model.entry_point_offset,
        u32::try_from(entry).ok()?,
    )
    .ok()?;
    report.restored.push("entry point");

    let imports = listed.and_then(
        |ListedImports {
             modules,
             end_markers,
             ..
         }| {
            for slot in end_markers {
                write_u32(&mut restored, slot, 0).ok()?;
            }
            apply_listed_imports(&mut restored, model, modules)
        },
    );
    match imports {
        Some(_) => report.restored.push("imports"),
        None => report.unrestored.push("imports"),
    }

    if let Some((at, beneath)) = &beneath_imports {
        restored
            .get_mut(*at..at.checked_add(beneath.len())?)?
            .copy_from_slice(beneath); // the import list is decoded over bytes of the original
    }

    let page = model.section_alignment as usize;
    let kept_relocations = find_relocation_table(original, &image_range, origin.base, page); // kept data whose directory the packer cleared

    let pogo = pogo_parts(&restored, model, end);
    let linked_resources = pogo.as_deref().and_then(|parts| {
        parts
            .iter()
            .filter(|part| part.name.starts_with(b".rsrc"))
            .map(|part| part.rva)
            .min()
    });

    let moved = lowest_moved_leaf(&restored, model, end);
    let kept_in_packer = match moved {
        Some(_) => None,
        None => resources_at_image_end(
            &mut restored,
            model,
            image_end,
            layout,
            original,
            kept_relocations.as_ref(),
            linked_resources,
        ),
    };
    let resources = moved.or(kept_in_packer);

    let linker_pieces = pogo
        .as_deref()
        .and_then(|parts| pogo_sections(parts, model, end, Some(entry)));
    let from_linker = linker_pieces.is_some();
    let bounds = keeps_code_fields
        .then(|| linker_bounds(&restored, model, entry))
        .flatten();
    let pieces = linker_pieces.or_else(|| {
        let located = Located {
            bounds,
            resources,
            relocations: kept_relocations.clone(),
        };
        Some(stream_sections(
            section_starts?,
            page,
            entry,
            &evidence,
            located,
            end,
        ))
    });

    let ranges: Vec<Range<usize>> = match &pieces {
        Some(pieces) => pieces.iter().map(|piece| piece.start..piece.end).collect(),
        None => resources.into_iter().map(|leaf| leaf..image_end).collect(), // fsg 2.0 packs the leaves from where .rsrc began
    };
    let resources_restored = match kept_in_packer {
        Some(_) => Restoration::Restored,
        None => restore_moved_resources(&mut restored, model, &ranges, end, layout, Some(original)),
    };
    report.record("resources", resources_restored);

    if has_blank_leaf(&restored, model) {
        report.lost.push("resource data the packer blanked"); // fsg 2.0 zeroes delphi's DVCLAL and PACKAGEINFO
    }

    let icons = repair_icon_groups(&mut restored, model);
    report.record("icon groups the packer overwrote", icons); // fsg 1.x writes the next leaf into a group's tail

    let tls = restore_tls(
        &mut restored,
        model,
        origin.base,
        end,
        pogo.as_deref().and_then(pogo_tls_directory),
    );
    report.record("original TLS directory", tls);

    recover_directories(&mut restored, model, origin.base, end, &mut report);

    if let Some(timestamp) = debug_timestamp(&restored, model) {
        let at = model.nt_offset.checked_add(TIMESTAMP_OFFSET)?;
        if read_u32(&restored, at).ok() != Some(timestamp) {
            write_u32(&mut restored, at, timestamp).ok()?;
            report.restored.push("build timestamp");
        }
    }

    let relocations = check_relocations(&mut restored, model, end, kept_relocations);
    report.record("relocations", relocations);

    let sections = match pieces {
        Some(pieces) => replace_first_section(&mut restored, model, &pieces),
        None => split_merged(
            &mut restored,
            model,
            origin.base,
            entry,
            &evidence,
            resources,
            image_end,
        ),
    };
    match (sections.is_some(), from_linker) {
        (true, true) => report.restored.push("section table"),
        (true, false) => {
            report.restored.push("code and data sections");
            report.lost.push("section table");
        }
        (false, _) => report.lost.push("section table"),
    }

    clear_directory(&mut restored, model, BOUND_IMPORT_DIRECTORY);
    parse_memory_image(&restored).ok()?;

    let fresh = finished
        .then(|| {
            fresh_image(
                image.bytes(),
                &restored,
                original,
                origin.base,
                origin.base,
                end,
                &[],
            )
        })
        .flatten();

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings {
            report,
            imports: imports.unwrap_or(PackerImports::Unknown),
        },
        fresh,
    })
}

pub(super) fn register_load(bytes: &[u8], at: usize) -> Option<Load> {
    let code = bytes.get(at..)?;
    let immediate = |offset: usize| read_u32(code, offset).ok().map(|value| value as usize);

    let (register, value) = match *code.first()? {
        opcode @ 0xB8..=0xBF => (opcode - 0xB8, immediate(1)?),
        0x68 => match *code.get(5)? {
            pop @ 0x58..=0x5F => (pop - 0x58, immediate(1)?),
            _ => return None,
        },
        0x8D => {
            let modrm = *code.get(1)?;
            (modrm & 0xC7 == 0x05).then_some(((modrm >> 3) & 7, immediate(2)?))?
        }
        0xC7 => {
            let modrm = *code.get(1)?;
            (modrm & 0xF8 == 0xC0).then_some((modrm & 7, immediate(2)?))?
        }
        _ => return None,
    };

    Some(Load {
        at,
        register,
        value,
    })
}

pub(super) fn mapped_file(file: &[u8], image: &PeImage<'_>) -> Option<Vec<u8>> {
    let disk = parse_disk_image(file).ok()?;
    let model = disk.model();
    let memory = image.model();

    let same_image = model.image_size == memory.image_size
        && read_u32(file, model.entry_point_offset).ok()
            == read_u32(image.bytes(), memory.entry_point_offset).ok();
    same_image.then_some(())?;
    map_disk_image(file, model.image_size as usize)
}

fn resources_at_image_end(
    restored: &mut [u8],
    model: &PeModel,
    image_end: usize,
    layout: ResourceLayout,
    pristine: &[u8],
    relocations: Option<&Range<usize>>,
    linked_start: Option<usize>,
) -> Option<usize> {
    let page = model.section_alignment as usize;
    let last_relocations =
        relocations.filter(|table| table.end.next_multiple_of(page) >= image_end);
    let tree_end = match last_relocations {
        Some(table) => table.start, // .rsrc sat right below the .reloc that ends the image
        None => {
            let relocatable = model.is_dll
                || read_u16(restored, model.dll_characteristics_offset)
                    .is_ok_and(|flags| flags & DYNAMIC_BASE != 0);
            (!relocatable).then_some(())?; // its .reloc would follow .rsrc
            image_end
        }
    };

    let root = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()??
        .rva()
        .as_usize();
    (root >= image_end).then_some(())?;

    let first = model.sections().first()?.virtual_address().as_usize();
    let linked_start = linked_start.filter(|start| {
        (first..tree_end).contains(start)
            && restored
                .get(*start..tree_end)
                .is_some_and(|area| area.iter().all(|byte| *byte == 0))
    });
    if let Some(start) = linked_start
        && lay_out_resources(
            restored,
            model,
            root,
            start..tree_end,
            layout,
            Some(pristine),
        )
        .is_some()
    {
        return Some(start); // the linker recorded where .rsrc began
    }

    let mut start = tree_end;

    while start > first {
        start = start.checked_sub(page)?;
        restored
            .get(start..start.checked_add(page)?)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(())?;
        if lay_out_resources(
            restored,
            model,
            root,
            start..tree_end,
            layout,
            Some(pristine),
        )
        .is_some()
        {
            return Some(start);
        }
    }

    None
}

fn has_blank_leaf(restored: &[u8], model: &PeModel) -> bool {
    let Some(root) = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()
        .flatten()
        .map(|directory| directory.rva().as_usize())
    else {
        return false;
    };

    walk_resources(restored, root).is_some_and(|tree| {
        tree.data_entries.iter().any(|entry| {
            let leaf = |offset: usize| {
                read_u32(restored, root.checked_add(*entry)?.checked_add(offset)?)
                    .ok()
                    .map(|value| value as usize)
            };

            let data = leaf(0)
                .zip(leaf(RESOURCE_DATA_SIZE_OFFSET))
                .and_then(|(rva, size)| restored.get(rva..rva.checked_add(size)?));
            data.is_some_and(|data| !data.is_empty() && data.iter().all(|byte| *byte == 0))
        })
    })
}

fn stream_sections(
    starts: Vec<usize>,
    page: usize,
    entry: usize,
    evidence: &Evidence<'_>,
    located: Located,
    end: usize,
) -> Vec<SectionPiece> {
    let Located {
        bounds,
        resources,
        relocations,
    } = located;
    let relocation_bounds =
        relocations.map(|table| [table.start, table.end.next_multiple_of(page)]);
    let starts: Vec<usize> = starts
        .into_iter()
        .chain(
            bounds
                .into_iter()
                .flat_map(|bounds| [Some(bounds.code_end), bounds.data])
                .flatten(),
        )
        .chain(resources.filter(|start| start.is_multiple_of(page))) // .rsrc opens where the tree went back
        .chain(relocation_bounds.into_iter().flatten())
        .filter(|start| *start < end)
        .collect(); // one stream covers sections whose raw data ran on without a gap

    let constants = evidence.constants_start.filter(|iat| {
        let piece_start = starts.iter().copied().filter(|start| start <= iat).max();
        let piece_end = starts
            .iter()
            .copied()
            .filter(|start| start > iat)
            .min()
            .unwrap_or(end);
        piece_start.is_some_and(|piece_start| evidence.untouched(piece_start..piece_end))
    });

    let entry_piece_end = starts
        .iter()
        .copied()
        .filter(|start| *start > entry)
        .min()
        .unwrap_or(end);
    let hints = SectionHints {
        code: Some(entry),
        code_end: Some(bounds.map_or(entry_piece_end, |bounds| bounds.code_end)), // linkers put code first
        constants,
        relocations: relocation_bounds.map(|[start, _]| start),
        resources,
    };

    let unsplit = !evidence.finished && bounds.is_none(); // with no runtime writes and no linker fields nothing marks where data starts
    let mut pieces = Vec::new();
    for piece in name_sections(starts, end, &hints) {
        let written = (piece.characteristics == CODE_SECTION)
            .then(|| first_written_page(evidence, &piece, page))
            .flatten(); // a program never writes its code, so where it wrote is merged data
        match written {
            Some(data) => {
                pieces.push(SectionPiece { end: data, ..piece });
                pieces.push(SectionPiece {
                    name: *b".data\0\0\0",
                    start: data,
                    end: piece.end,
                    characteristics: DATA_SECTION,
                });
            }
            None if unsplit && piece.characteristics == CODE_SECTION => pieces.push(SectionPiece {
                characteristics: CODE_SECTION | IMAGE_SCN_MEM_WRITE,
                ..piece
            }),
            None => pieces.push(piece),
        }
    }

    pieces
}

fn first_written_page(evidence: &Evidence<'_>, piece: &SectionPiece, page: usize) -> Option<usize> {
    (piece.start..piece.end)
        .step_by(page)
        .skip(1)
        .find(|start| !evidence.untouched(*start..start.saturating_add(page).min(piece.end)))
}

fn split_merged(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    entry: usize,
    evidence: &Evidence<'_>,
    resources: Option<usize>,
    image_end: usize,
) -> Option<()> {
    let page = model.section_alignment as usize;
    let constants_end = read_only_end(restored, model).max(evidence.names_end);
    let constants_page = constants_end.checked_next_multiple_of(page);
    let data = match security_cookie(restored, model, base) {
        Some(cookie) => constants_page.map(|constants| constants.min(cookie / page * page)), // msvc puts it on the first page of .data
        None => constants_page,
    };

    let split = evidence
        .constants_start
        .zip(data)
        .filter(|(constants, data)| constants < data && evidence.untouched(*constants..*data));

    let hints = SectionHints {
        code: Some(entry),
        code_end: None,
        constants: split.map(|(constants, _)| constants),
        relocations: None,
        resources,
    };

    split_merged_section(
        restored,
        model,
        &hints,
        split.map(|(_, data)| data),
        Some(image_end),
    )
}

fn read_only_end(restored: &[u8], model: &PeModel) -> usize {
    let directory_end = |index: usize| {
        let directory = model.directory(restored, index).ok().flatten()?;
        directory
            .rva()
            .as_usize()
            .checked_add(directory.size() as usize)
    };

    let debug_data_end = model
        .directory(restored, DEBUG_DIRECTORY)
        .ok()
        .flatten()
        .map_or(0, |directory| {
            let start = directory.rva().as_usize();
            (0..directory.size() as usize / DEBUG_ENTRY_SIZE)
                .filter_map(|index| {
                    let entry = start.checked_add(index.checked_mul(DEBUG_ENTRY_SIZE)?)?;
                    let size = read_u32(restored, entry.checked_add(DEBUG_SIZE_OFFSET)?).ok()?;
                    let rva = read_u32(restored, entry.checked_add(DEBUG_ADDRESS_OFFSET)?).ok()?;
                    (rva as usize).checked_add(size as usize)
                })
                .max()
                .unwrap_or(0)
        });

    [
        LOAD_CONFIG_DIRECTORY,
        DEBUG_DIRECTORY,
        DELAY_IMPORT_DIRECTORY,
    ]
    .into_iter()
    .filter_map(directory_end)
    .chain([debug_data_end])
    .max()
    .unwrap_or(0)
}

fn stub_finished(memory: &[u8], original: &[u8], modules: &[ModuleImports]) -> bool {
    modules
        .iter()
        .rev()
        .find(|module| !module.functions.is_empty())
        .is_some_and(|module| {
            let slot = module.first_thunk as usize;
            let filled = read_u32(memory, slot).ok();
            filled.is_some_and(|value| value != 0) && filled != read_u32(original, slot).ok()
        }) // the stub fills the last module's iat right before it jumps
}

fn check_relocations(
    restored: &mut [u8],
    model: &PeModel,
    end: usize,
    kept: Option<Range<usize>>,
) -> Restoration {
    let directory = model
        .directory(restored, BASERELOC_DIRECTORY)
        .ok()
        .flatten();

    let intact = directory.is_some_and(|directory| {
        let start = directory.rva().as_usize();
        start < end && relocations_intact(restored, start, directory.size() as usize)
    });
    if intact {
        return Restoration::Absent;
    }

    let reattached = kept.is_some_and(|table| {
        set_directory(
            restored,
            model,
            BASERELOC_DIRECTORY,
            table.start,
            table.len(),
        )
        .is_some()
    });
    if reattached {
        return Restoration::Restored;
    }

    clear_directory(restored, model, BASERELOC_DIRECTORY);

    let dynamic = read_u16(restored, model.dll_characteristics_offset)
        .is_ok_and(|flags| flags & DYNAMIC_BASE != 0);
    match dynamic {
        true => Restoration::Lost,
        false => Restoration::Absent,
    }
}
