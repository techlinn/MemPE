use std::collections::{HashMap, HashSet};
use std::ops::RangeInclusive;
use std::sync::Arc;

pub(crate) type NameHints = HashMap<u32, NameHint>; // by import slot

#[derive(Clone)]
pub(crate) enum NameHint {
    Length(RangeInclusive<usize>), // alias tiebreak
    Ordinal(u32),
    Among(&'static [&'static str]), // the names known callers import
}

#[derive(Clone)]
pub(crate) struct ModuleImports {
    pub(crate) module: Option<String>, // none: named from its slots
    pub(crate) first_thunk: u32,
    pub(crate) functions: Vec<ImportedFunction>,
}

#[derive(Clone)]
pub(crate) enum ImportedFunction {
    Name(String),
    Ordinal(u16),
    OrdinalFromAddress,
    NameFromAddress,
    NameFromAddressAmong(Arc<HashSet<String>>), // alias and ordinal tiebreak
}
