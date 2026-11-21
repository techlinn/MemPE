use std::ops::Range;

use super::{Restoration, SCAN_STEP, place, unique};
use crate::pe::bytes::{read_pointer, read_u32};
use crate::pe::{
    PeKind, PeModel, TLS_CALLBACKS_FIELD, TLS_DIRECTORY, TLS_DIRECTORY_PE32,
    TLS_DIRECTORY_PE32_PLUS, TLS_END_FIELD, TLS_INDEX_FIELD, TLS_POINTER_FIELDS, TLS_START_FIELD,
    first_section_rva,
};

const MAX_TLS_CALLBACKS: usize = 4_096;
const BY_TEMPLATE: &str = "found by its template";
const BY_SHAPE: &str =
    "found by its template size and fields, the copy's pointers being the packer's own";
const LINKER_PLACE: &str = "put back where the linker's layout has it";
const BORLAND_PLACE: &str = "put back where borland's linker has it";

fn directory_length(kind: PeKind) -> usize {
    match kind {
        PeKind::Pe32 => TLS_DIRECTORY_PE32,
        PeKind::Pe32Plus => TLS_DIRECTORY_PE32_PLUS,
    }
}

pub(crate) fn restore_tls(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
    linker_place: Option<usize>,
) -> Restoration {
    let Some(copy) = model.directory(restored, TLS_DIRECTORY) else {
        return Restoration::Absent;
    };

    let copy = copy.rva().as_usize();
    let kind = model.kind;
    let length = directory_length(kind);
    let image = first_section_rva(&model.sections).unwrap_or(end)..end;
    let refill = |restored: &mut [u8], place: usize| -> Option<usize> {
        (copy >= end && place < end).then_some(())?;
        let content = restored.get(copy..copy.checked_add(length)?)?.to_vec();
        self::place(restored, place, &content)?;
        Some(place)
    };

    let original = find_original_tls(restored, copy, kind, &image)
        .map(|rva| (rva, None))
        .or_else(|| {
            let rva = find_tls_by_template(restored, copy, kind, base, &image)?;
            Some((rva, Some(BY_TEMPLATE)))
        })
        .or_else(|| {
            let rva = find_tls_by_shape(restored, copy, kind, base, &image)?;
            Some((rva, Some(BY_SHAPE)))
        })
        .or_else(|| {
            let rva = refill(restored, linker_place?)?;
            Some((rva, Some(LINKER_PLACE)))
        })
        .or_else(|| {
            let place = callbacks_in_directory(restored, copy, kind, base)?;
            let section_start = place.is_multiple_of(model.section_alignment as usize); // ilink32 gives the directory its own .rdata
            section_start.then_some(())?;
            Some((refill(restored, place)?, Some(BORLAND_PLACE)))
        });

    let set = original.and_then(|(rva, how)| {
        model.set_directory(restored, TLS_DIRECTORY, rva, length)?;
        Some(how)
    });
    match set {
        Some(None) => Restoration::Restored,
        Some(Some(how)) => Restoration::Inferred(how),
        None if copy < end => Restoration::Absent, // fsg keeps its copy inside the program
        None if tls_template(restored, copy, kind, base, end).is_some() => Restoration::Lost,
        None => {
            model.clear_directory(restored, TLS_DIRECTORY);
            Restoration::Failed
        }
    }
}

pub(crate) fn tls_callbacks(bytes: &[u8], model: &PeModel, base: usize) -> Vec<usize> {
    let Some(directory) = model.directory(bytes, TLS_DIRECTORY) else {
        return Vec::new();
    };

    let kind = model.kind;
    let width = kind.pointer_width();
    let field = directory
        .rva()
        .as_usize()
        .saturating_add(width * TLS_CALLBACKS_FIELD);
    let Some(list) = read_pointer(bytes, field, kind)
        .ok()
        .filter(|list| *list != 0)
        .and_then(|list| list.checked_sub(base))
    else {
        return Vec::new();
    };

    (0..MAX_TLS_CALLBACKS)
        .map_while(|slot| {
            read_pointer(bytes, list.saturating_add(slot * width), kind)
                .ok()
                .filter(|callback| *callback != 0)
        })
        .filter_map(|callback| callback.checked_sub(base))
        .collect()
}

fn find_original_tls(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    image: &Range<usize>,
) -> Option<usize> {
    let width = kind.pointer_width();
    let callbacks = width.checked_mul(TLS_CALLBACKS_FIELD)?;
    let length = directory_length(kind);
    let wanted = bytes.get(copy..copy.checked_add(length)?)?;
    let (before, after) = (wanted.get(..callbacks)?, wanted.get(callbacks + width..)?);

    unique(image.clone().step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && bytes.get(*at..at.saturating_add(callbacks)) == Some(before)
            && bytes.get(at.saturating_add(callbacks + width)..at.saturating_add(length))
                == Some(after)
    }))
}

fn callbacks_in_directory(bytes: &[u8], copy: usize, kind: PeKind, base: usize) -> Option<usize> {
    let width = kind.pointer_width();
    let zero_fill = width.checked_mul(TLS_POINTER_FIELDS)?;
    let callbacks =
        read_pointer(bytes, copy.checked_add(width * TLS_CALLBACKS_FIELD)?, kind).ok()?;
    (read_u32(bytes, copy.checked_add(zero_fill)?).ok()? == 0).then_some(())?;

    callbacks.checked_sub(base)?.checked_sub(zero_fill) // borland: callbacks at zero fill
}

fn find_tls_by_template(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    base: usize,
    image: &Range<usize>,
) -> Option<usize> {
    let template = |at: usize, limit: usize| tls_template(bytes, at, kind, base, limit);
    let (start, stop) = template(copy, bytes.len())?;
    let wanted = bytes.get(start..stop)?;
    wanted.iter().any(|byte| *byte != 0).then_some(())?; // zeros match any zeros

    unique(image.clone().step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && template(*at, image.end).is_some_and(|(other_start, other_stop)| {
                other_start != start && bytes.get(other_start..other_stop) == Some(wanted)
            })
    }))
}

// a packer that moves the template keeps its size, zero fill and characteristics
fn find_tls_by_shape(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    base: usize,
    image: &Range<usize>,
) -> Option<usize> {
    let width = kind.pointer_width();
    let pointer =
        |at: usize, field: usize| read_pointer(bytes, at.checked_add(field * width)?, kind).ok();
    let tail = |at: usize| {
        bytes.get(
            at.checked_add(TLS_POINTER_FIELDS * width)?..at.checked_add(directory_length(kind))?,
        )
    };
    let rva = |address: usize| address.checked_sub(base).filter(|rva| image.contains(rva));

    let size = pointer(copy, TLS_END_FIELD)?
        .checked_sub(pointer(copy, TLS_START_FIELD)?)
        .filter(|size| *size > 0)?;
    let fields = tail(copy)?;

    unique(image.clone().step_by(SCAN_STEP).filter(|at| {
        let template = pointer(*at, TLS_START_FIELD).and_then(rva);
        let end = pointer(*at, TLS_END_FIELD).and_then(|end| end.checked_sub(base));
        let index = pointer(*at, TLS_INDEX_FIELD).and_then(rva);
        let callbacks = pointer(*at, TLS_CALLBACKS_FIELD);

        *at != copy
            && template.zip(end).is_some_and(|(start, end)| {
                end.checked_sub(start) == Some(size) && end <= image.end
            })
            && index.is_some()
            && callbacks.is_some_and(|list| list == 0 || rva(list).is_some())
            && tail(*at) == Some(fields)
    }))
}

fn tls_template(
    bytes: &[u8],
    at: usize,
    kind: PeKind,
    base: usize,
    limit: usize,
) -> Option<(usize, usize)> {
    let width = kind.pointer_width();
    let field = |index: usize| {
        let address = read_pointer(bytes, at.checked_add(index * width)?, kind).ok()?;
        address.checked_sub(base).filter(|rva| *rva < limit)
    };

    let start = field(TLS_START_FIELD)?;
    let stop = field(TLS_END_FIELD)?;
    field(TLS_INDEX_FIELD)?;

    (stop > start).then_some((start, stop))
}
