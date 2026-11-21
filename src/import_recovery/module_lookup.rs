use std::collections::{BTreeMap, BTreeSet};

use super::code_references::Reference;
use super::iat_scan::named_in;
use super::resolve_slot::resolve_value;
use super::{
    ImportEntry, ImportGroup, ImportPlan, ImportSource, commit_group, is_representable,
    read_pointer, slot_value,
};
use crate::pe::PeImage;
use crate::pe::exports::ExportIndex;
use crate::pe::import_list::{ImportedFunction, ModuleImports};

pub(super) fn add_packed_module(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    module: &ModuleImports,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let width = image.model().kind.pointer_width();
    let slot_at = |index: usize| {
        u32::try_from(index.saturating_mul(width))
            .ok()
            .and_then(|offset| module.first_thunk.checked_add(offset))
    };

    let name = match &module.module {
        Some(name) => Some(name.clone()),
        None => owning_module(image, exports, module, slot_at),
    };
    let Some(name) = name else {
        plan.undetermined_module_slots = plan
            .undetermined_module_slots
            .saturating_add(module.functions.len());
        return;
    };

    let mut current: Option<ImportGroup> = None;
    for (index, function) in module.functions.iter().enumerate() {
        let slot = slot_at(index);
        let entry = slot
            .and_then(|slot| packed_entry(image, observed_base, exports, &name, function, slot))
            .filter(|(owner, entry)| is_representable(owner, entry.name.as_deref(), entry.ordinal));
        let (Some((owner, entry)), Some(slot)) = (entry, slot) else {
            plan.unrepresentable = plan.unrepresentable.saturating_add(1);

            if let Some(group) = current.take() {
                commit_group(group, width, referenced, plan);
            }
            continue;
        };

        let finished = current.take_if(|group| !group.module.eq_ignore_ascii_case(&owner));
        if let Some(group) = finished {
            commit_group(group, width, referenced, plan);
        }

        current
            .get_or_insert_with(|| ImportGroup {
                module: owner,
                first_thunk: slot,
                entries: Vec::new(),
                source: ImportSource::Packer,
            })
            .entries
            .push(entry);
    }

    if let Some(group) = current {
        commit_group(group, width, referenced, plan);
    }
}

fn owning_module(
    image: &PeImage<'_>,
    exports: &ExportIndex,
    module: &ModuleImports,
    slot_at: impl Fn(usize) -> Option<u32>,
) -> Option<String> {
    let memory = image.bytes();
    let width = image.model().kind.pointer_width();

    let naming = module
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| {
            let value = read_pointer(memory, slot_at(index)? as usize, width)?;
            let modules = exports
                .modules_at(value)
                .map(|(candidate, _)| candidate.to_ascii_lowercase())
                .filter(|candidate| exports_function(exports, value, candidate, function))
                .collect::<BTreeSet<String>>();
            Some(modules)
        });

    sole_shared_module(naming)
}

fn exports_function(
    exports: &ExportIndex,
    value: usize,
    module: &str,
    function: &ImportedFunction,
) -> bool {
    match function {
        ImportedFunction::Name(name) => exports.export_named(value, module, name).is_some(),
        ImportedFunction::Ordinal(ordinal) => {
            exports.ordinal_in(value, module) == Some(u32::from(*ordinal))
        }
        ImportedFunction::NameFromAddress
        | ImportedFunction::NameFromAddressAmong(_)
        | ImportedFunction::OrdinalFromAddress => true,
    }
}

fn sole_shared_module(naming: impl Iterator<Item = Option<BTreeSet<String>>>) -> Option<String> {
    let mut shared: Option<BTreeSet<String>> = None;
    for modules in naming {
        let modules = modules?;
        shared = Some(match shared {
            Some(shared) => shared.intersection(&modules).cloned().collect(),
            None => modules,
        });
    }

    let mut shared = shared?.into_iter();
    let only = shared.next()?;
    shared.next().is_none().then_some(only)
}

fn resolved_entry(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    value: usize,
) -> Option<(String, ImportEntry)> {
    let kind = image.model().kind;
    let found = resolve_value(image.bytes(), observed_base, kind, value, exports).ok()?;
    let entry = ImportEntry {
        name: found.symbol.name.clone(),
        ordinal: found.symbol.ordinal,
        aliased: found.aliased,
    };

    (!found.ambiguous).then(|| (found.symbol.module.clone(), entry))
}

fn packed_entry(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    module: &str,
    function: &ImportedFunction,
    slot: u32,
) -> Option<(String, ImportEntry)> {
    let listed = |name: Option<String>, ordinal: u32, aliased: bool| {
        let entry = ImportEntry {
            name,
            ordinal,
            aliased,
        };
        (module.to_owned(), entry)
    };
    let elsewhere = |value: usize| resolved_entry(image, observed_base, exports, value);

    match function {
        ImportedFunction::Name(name) => Some(listed(Some(name.clone()), 0, false)),
        ImportedFunction::Ordinal(ordinal) => Some(listed(None, u32::from(*ordinal), false)),
        ImportedFunction::NameFromAddress => {
            let value = slot_value(image, slot)?;
            named_in(exports, value, module)
                .map(|(symbol, aliased)| listed(symbol.name, 0, aliased))
                .or_else(|| elsewhere(value))
        }
        ImportedFunction::NameFromAddressAmong(names) => {
            let value = slot_value(image, slot)?;
            let host_name = || exports.names_at(value).find(|name| names.contains(*name));
            let listed_name = exports
                .names_in(value, module)
                .find(|name| names.contains(*name))
                .or_else(host_name); // an api set is named by its host
            match listed_name {
                Some(name) => Some(listed(Some(name.to_owned()), 0, false)),
                None => exports
                    .ordinal_in(value, module)
                    .map(|ordinal| listed(None, ordinal, false))
                    .or_else(|| elsewhere(value)),
            }
        }
        ImportedFunction::OrdinalFromAddress => {
            let value = slot_value(image, slot)?;
            exports
                .ordinal_in(value, module)
                .map(|ordinal| listed(None, ordinal, false))
                .or_else(|| elsewhere(value))
        }
    }
}
