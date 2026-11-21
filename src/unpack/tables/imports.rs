use super::read_c_string;
use crate::pe::bytes::{read_pointer, read_u32};
use crate::pe::{
    HINT_SIZE, IAT_DIRECTORY, IMPORT_DESCRIPTOR_SIZE, IMPORT_DIRECTORY, IMPORT_IAT_OFFSET,
    IMPORT_NAME_OFFSET, MAX_IMPORT_DESCRIPTORS, MAX_IMPORTS, PeKind, PeModel,
};
use crate::unpack::{ImportedFunction, ModuleImports, PackerImports};

pub(crate) const THUNK_SIZE: usize = 4; // PE32 packers only
pub(crate) const ORDINAL_FLAG: u32 = 0x8000_0000;

pub(crate) trait OriginalBytes {
    fn original_u32(&mut self, rva: usize) -> Option<u32>;
    fn original_string(&mut self, rva: usize) -> Option<String>;
}

impl OriginalBytes for &[u8] {
    fn original_u32(&mut self, rva: usize) -> Option<u32> {
        read_u32(self, rva).ok()
    }

    fn original_string(&mut self, rva: usize) -> Option<String> {
        read_c_string(self, rva).map(|(name, _)| name)
    }
}

pub(crate) fn imports_from_original(
    restored: &mut [u8],
    model: &PeModel,
    import_rva: usize,
    original: &mut impl OriginalBytes,
) -> Option<PackerImports> {
    let modules = listed_imports(import_rva, original)?;
    iat_filled(restored, &modules, PeKind::Pe32, true).then_some(())?;
    apply_listed_imports(restored, model, modules)
}

pub(crate) fn listed_imports(
    import_rva: usize,
    original: &mut impl OriginalBytes,
) -> Option<Vec<ModuleImports>> {
    let mut modules = Vec::new();
    for index in 0..=MAX_IMPORT_DESCRIPTORS {
        let descriptor = import_rva.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let lookup = original.original_u32(descriptor)? as usize;
        let name = original.original_u32(descriptor.checked_add(IMPORT_NAME_OFFSET)?)? as usize;
        let iat = original.original_u32(descriptor.checked_add(IMPORT_IAT_OFFSET)?)? as usize;

        if name == 0 && iat == 0 {
            return Some(modules);
        }

        let module = original.original_string(name)?;
        let source = match lookup {
            0 => iat, // borland: names in the iat itself
            _ => lookup,
        };

        modules.push(ModuleImports {
            module: Some(module),
            first_thunk: u32::try_from(iat).ok()?,
            functions: listed_functions(source, original)?,
        });
    }

    None // no end marker within the cap
}

fn listed_functions(
    source: usize,
    original: &mut impl OriginalBytes,
) -> Option<Vec<ImportedFunction>> {
    let mut functions = Vec::new();
    for slot in 0..=MAX_IMPORTS {
        let entry = original.original_u32(source.checked_add(slot.checked_mul(THUNK_SIZE)?)?)?;
        if entry == 0 {
            return Some(functions);
        }

        functions.push(match entry & ORDINAL_FLAG {
            0 => ImportedFunction::Name(
                original.original_string((entry as usize).checked_add(HINT_SIZE)?)?,
            ),
            _ => ImportedFunction::Ordinal(entry as u16),
        });
    }

    None
}

// terminated: the slot after a module's last must still be its zero end
pub(crate) fn iat_filled(
    restored: &[u8],
    modules: &[ModuleImports],
    kind: PeKind,
    terminated: bool,
) -> bool {
    let width = kind.pointer_width();
    modules.iter().all(|module| {
        let iat = module.first_thunk as usize;
        let filled = |slot: usize| {
            read_pointer(
                restored,
                iat.saturating_add(slot.saturating_mul(width)),
                kind,
            )
            .is_ok_and(|value| value != 0)
        };
        (0..module.functions.len()).all(filled) && !(terminated && filled(module.functions.len()))
    })
}

pub(crate) fn apply_listed_imports(
    restored: &mut [u8],
    model: &PeModel,
    modules: Vec<ModuleImports>,
) -> Option<PackerImports> {
    let tables = modules
        .iter()
        .map(|module| (module.first_thunk as usize, module.functions.len()));
    let (first, span) = iat_span(tables, THUNK_SIZE)?;
    model.clear_directory(restored, IMPORT_DIRECTORY);
    model.set_directory(restored, IAT_DIRECTORY, first, span)?;

    Some(PackerImports::Listed(modules))
}

pub(crate) fn iat_span(
    tables: impl IntoIterator<Item = (usize, usize)>, // first slot, slot count
    width: usize,
) -> Option<(usize, usize)> {
    let mut first = usize::MAX;
    let mut end = 0;
    for (start, slots) in tables {
        first = first.min(start);
        end = end.max(start.checked_add(slots.checked_add(1)?.checked_mul(width)?)?); // plus the terminator
    }

    (first < end).then(|| (first, end - first))
}

// the lowest slot the import descriptors fill: msvc and its kin open .rdata with it
pub(crate) fn iat_start(image: &[u8], descriptors: usize) -> Option<usize> {
    (0..MAX_IMPORT_DESCRIPTORS)
        .map(|index| descriptors + index * IMPORT_DESCRIPTOR_SIZE)
        .map_while(|at| {
            let first_thunk = read_u32(image, at + IMPORT_IAT_OFFSET).ok()?;
            (first_thunk != 0).then_some(first_thunk as usize)
        })
        .min()
}
