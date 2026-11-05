use super::{
    FIRST_SECTION_RVA, Restoration, SCAN_STEP, clear_directory, place, set_directory, unique,
};
use crate::pe::image::{read_pointer, read_u32};
use crate::pe::{PeKind, PeModel, TLS_DIRECTORY};

const TLS_DIRECTORY_PE32: usize = 24;
const TLS_DIRECTORY_PE32_PLUS: usize = 40;

pub(crate) fn restore_tls(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
    linker_place: Option<usize>,
) -> Restoration {
    let Ok(Some(copy)) = model.directory(restored, TLS_DIRECTORY) else {
        return Restoration::Absent;
    };

    let copy = copy.rva().as_usize();
    let length = match model.kind() {
        PeKind::Pe32 => TLS_DIRECTORY_PE32,
        PeKind::Pe32Plus => TLS_DIRECTORY_PE32_PLUS,
    };
    let refill = |restored: &mut [u8], place: usize| -> Option<usize> {
        (copy >= end && place < end).then_some(())?;
        let content = restored.get(copy..copy.checked_add(length)?)?.to_vec();
        self::place(restored, place, &content)?;
        Some(place)
    };

    let original = find_original_tls(restored, copy, model.kind(), end)
        .or_else(|| find_tls_by_template(restored, copy, model.kind(), base, end))
        .or_else(|| linker_place.and_then(|place| refill(restored, place)))
        .or_else(|| {
            let place = callbacks_in_directory(restored, copy, model.kind(), base)?;
            refill(restored, place)
        });

    match original.and_then(|rva| set_tls_directory(restored, model, rva)) {
        Some(()) => Restoration::Restored,
        None if tls_template(restored, copy, model.kind(), base, end).is_some() => {
            Restoration::Lost // the packer wiped the original, its copy still works
        }
        None => {
            clear_directory(restored, model, TLS_DIRECTORY);
            Restoration::Failed
        }
    }
}

fn set_tls_directory(restored: &mut [u8], model: &PeModel, rva: usize) -> Option<()> {
    let size = match model.kind() {
        PeKind::Pe32 => TLS_DIRECTORY_PE32,
        PeKind::Pe32Plus => TLS_DIRECTORY_PE32_PLUS,
    };

    set_directory(restored, model, TLS_DIRECTORY, rva, size)
}

fn find_original_tls(bytes: &[u8], copy: usize, kind: PeKind, end: usize) -> Option<usize> {
    let width = kind.pointer_width();
    let callbacks = width.checked_mul(3)?;
    let length = width.checked_mul(4)?.checked_add(8)?;
    let wanted = bytes.get(copy..copy.checked_add(length)?)?;
    let (before, after) = (wanted.get(..callbacks)?, wanted.get(callbacks + width..)?);

    unique((FIRST_SECTION_RVA..end).step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && bytes.get(*at..at.saturating_add(callbacks)) == Some(before)
            && bytes.get(at.saturating_add(callbacks + width)..at.saturating_add(length))
                == Some(after)
    }))
}

fn callbacks_in_directory(bytes: &[u8], copy: usize, kind: PeKind, base: usize) -> Option<usize> {
    let width = kind.pointer_width();
    let zero_fill = width.checked_mul(4)?;
    let callbacks = read_pointer(bytes, copy.checked_add(width * 3)?, kind).ok()?;
    (read_u32(bytes, copy.checked_add(zero_fill)?).ok()? == 0).then_some(())?;

    callbacks.checked_sub(base)?.checked_sub(zero_fill) // borland points the empty callback list at the directory's own zero fill
}

fn find_tls_by_template(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    base: usize,
    end: usize,
) -> Option<usize> {
    let template = |at: usize, limit: usize| tls_template(bytes, at, kind, base, limit);
    let (start, stop) = template(copy, bytes.len())?;
    let wanted = bytes.get(start..stop)?;

    unique((FIRST_SECTION_RVA..end).step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && template(*at, end).is_some_and(|(other_start, other_stop)| {
                other_start != start && bytes.get(other_start..other_stop) == Some(wanted)
            })
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
    let image = |pointer: usize| pointer.checked_sub(base).filter(|rva| *rva < limit);

    let start = image(read_pointer(bytes, at, kind).ok()?)?;
    let stop = image(read_pointer(bytes, at.checked_add(width)?, kind).ok()?)?;
    image(read_pointer(bytes, at.checked_add(width * 2)?, kind).ok()?)?;

    (stop > start).then_some((start, stop))
}
