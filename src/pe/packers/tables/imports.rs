use super::{clear_directory, read_c_string, set_directory};
use crate::pe::image::read_u32;
use crate::pe::packers::{ImportedFunction, ModuleImports, PackerImports};
use crate::pe::{IAT_DIRECTORY, IMPORT_DIRECTORY, PeModel};

pub(crate) const IMPORT_DESCRIPTOR_SIZE: usize = 20;
pub(crate) const IMPORT_NAME_OFFSET: usize = 12;
pub(crate) const IMPORT_IAT_OFFSET: usize = 16;
pub(crate) const MAX_IMPORT_DESCRIPTORS: usize = 4_096;
pub(crate) const MAX_THUNKS: usize = 65_536;
pub(crate) const THUNK_SIZE: usize = 4; // only PE32 packers hand over an import list
pub(crate) const ORDINAL_FLAG: u32 = 0x8000_0000;
pub(crate) const HINT_SIZE: usize = 2; // a name entry starts with its export hint

pub(crate) trait OriginalImage {
    fn original_u32(&mut self, rva: usize) -> Option<u32>;
    fn original_string(&mut self, rva: usize) -> Option<String>;
}

impl OriginalImage for &[u8] {
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
    original: &mut impl OriginalImage,
) -> Option<PackerImports> {
    let modules = listed_imports(import_rva, original)?;
    iat_filled(restored, &modules).then_some(())?;
    apply_listed_imports(restored, model, modules)
}

pub(crate) fn listed_imports(
    import_rva: usize,
    original: &mut impl OriginalImage,
) -> Option<Vec<ModuleImports>> {
    let mut modules = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor = import_rva.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let lookup = original.original_u32(descriptor)? as usize;
        let name = original.original_u32(descriptor.checked_add(IMPORT_NAME_OFFSET)?)? as usize;
        let iat = original.original_u32(descriptor.checked_add(IMPORT_IAT_OFFSET)?)? as usize;

        if name == 0 && iat == 0 {
            break;
        }

        let module = original.original_string(name)?;
        let source = match lookup {
            0 => iat, // borland linkers leave the names in the iat itself
            _ => lookup,
        };

        let mut functions = Vec::new();
        for slot in 0..MAX_THUNKS {
            let entry =
                original.original_u32(source.checked_add(slot.checked_mul(THUNK_SIZE)?)?)?;

            if entry == 0 {
                break;
            }

            functions.push(match entry & ORDINAL_FLAG {
                0 => ImportedFunction::Name(
                    original.original_string((entry as usize).checked_add(HINT_SIZE)?)?,
                ),
                _ => ImportedFunction::Ordinal(entry as u16),
            });
        }

        modules.push(ModuleImports {
            module,
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });
    }

    Some(modules)
}

pub(crate) fn iat_filled(restored: &[u8], modules: &[ModuleImports]) -> bool {
    modules.iter().all(|module| {
        let iat = module.first_thunk as usize;
        let filled = |slot: usize| {
            read_u32(restored, iat.saturating_add(slot * THUNK_SIZE)).is_ok_and(|value| value != 0)
        };
        (0..module.functions.len()).all(filled) && !filled(module.functions.len())
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
    clear_directory(restored, model, IMPORT_DIRECTORY);
    set_directory(restored, model, IAT_DIRECTORY, first, span)?;

    Some(PackerImports::Listed(modules))
}

pub(crate) fn iat_span(
    tables: impl IntoIterator<Item = (usize, usize)>, // first slot and slot count of each table
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
