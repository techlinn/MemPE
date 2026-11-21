use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

use crate::pe::bytes;
use crate::pe::parse::{map_disk_image, parse_disk_image, parse_memory_image};
use crate::pe::{
    EXPORT_DIRECTORY, EXPORT_DIRECTORY_SIZE, EXPORT_ENTRY_SIZE, EXPORT_FUNCTION_COUNT_OFFSET,
    EXPORT_FUNCTIONS_OFFSET, EXPORT_NAME_COUNT_OFFSET, EXPORT_NAME_OFFSET, EXPORT_NAMES_OFFSET,
    EXPORT_ORDINAL_BASE_OFFSET, EXPORT_ORDINAL_SIZE, EXPORT_ORDINALS_OFFSET, HINT_SIZE,
    MAX_EXPORTS, MAX_NAME_LENGTH, PeImage, PeKind, Rva,
};

const MAX_EXPORT_NAMES: usize = 1_048_576;

#[derive(Clone)]
pub(crate) struct ExportSymbol {
    pub(crate) module: String,
    pub(crate) name: Option<String>,
    pub(crate) ordinal: u32,
    pub(crate) forwarded: bool,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ExportStats {
    pub(crate) modules: usize,
    pub(crate) addresses: usize,
    pub(crate) forwarders: usize,
    pub(crate) unresolved_forwarders: usize,
}

#[derive(Default)]
pub(crate) struct ExportIndex {
    addresses: HashMap<usize, Exported>,
    image_ranges: Vec<Range<usize>>,
    variables: HashSet<usize>,
    stats: ExportStats,
}

#[derive(Default)]
struct Exported {
    symbols: Vec<ExportSymbol>, // by module name, ordinal, then name-table order
    importers: HashMap<String, usize>,
}

struct ForwardedExport {
    source: ExportSymbol,
    target: String,
    kind: Option<PeKind>, // none: a contract file, not a loaded image
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum NamingPriority {
    ApiSetAlias,
    Implementation,
    Facade,
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum ExportKey {
    Name(String),
    Ordinal(u32),
}

type ModuleKey = (String, PeKind);
type Pending<'a> = HashMap<(ModuleKey, ExportKey), Option<&'a ForwardedExport>>;

struct ParsedExports {
    kind: PeKind,
    module: String,
    direct: Vec<(usize, ExportSymbol)>,
    variables: Vec<usize>,
    redirected: Vec<(usize, ExportSymbol)>,
    forwarders: Vec<ForwardedExport>,
}

#[derive(Default)]
struct ExportDefinitions {
    images: HashMap<ModuleKey, usize>,
    by_module: HashMap<(ModuleKey, ExportKey), Option<usize>>,
    hosts: HashMap<(PeKind, String), Option<usize>>,
}

impl ExportDefinitions {
    fn add_image(&mut self, module: &str, kind: PeKind) {
        let count = self
            .images
            .entry((module.to_ascii_lowercase(), kind))
            .or_default();
        *count = count.saturating_add(1);
    }

    fn add(&mut self, kind: PeKind, address: usize, symbol: &ExportSymbol) {
        let module = (symbol.module.to_ascii_lowercase(), kind);
        self.define(
            (module.clone(), ExportKey::Ordinal(symbol.ordinal)),
            address,
        );

        if let Some(name) = &symbol.name {
            self.define((module, ExportKey::Name(name.clone())), address);
        }
    }

    fn define(&mut self, key: (ModuleKey, ExportKey), address: usize) {
        self.by_module
            .entry(key)
            .and_modify(|known| {
                if *known != Some(address) {
                    *known = None;
                }
            })
            .or_insert(Some(address));
    }

    fn find_hosts(&mut self) {
        for (((_, kind), key), address) in &self.by_module {
            let ExportKey::Name(name) = key else {
                continue;
            };

            self.hosts
                .entry((*kind, name.clone()))
                .and_modify(|known| *known = None) // a second module exports it
                .or_insert(*address);
        }
    }

    fn duplicated(&self, module: &ModuleKey) -> bool {
        self.images.get(module).is_some_and(|count| *count > 1)
    }
}

impl Exported {
    fn settle(&mut self) {
        let mut seen = HashSet::new();
        self.symbols.retain(|symbol| {
            seen.insert((
                symbol.module.to_ascii_lowercase(),
                symbol.name.clone(),
                symbol.ordinal,
                symbol.forwarded,
            ))
        });

        self.symbols
            .sort_by_cached_key(|symbol| (symbol.module.to_ascii_lowercase(), symbol.ordinal));
    }

    fn importers_of(&self, symbol: &ExportSymbol) -> usize {
        symbol
            .name
            .as_deref()
            .and_then(|name| self.importers.get(name))
            .copied()
            .unwrap_or(0)
    }

    // strict majority of the importing modules, else table order
    fn preferred<'a>(&self, candidates: &[&'a ExportSymbol]) -> Option<&'a ExportSymbol> {
        let best = candidates.iter().map(|symbol| naming_class(symbol)).max()?;
        let ranked: Vec<&ExportSymbol> = candidates
            .iter()
            .copied()
            .filter(|symbol| naming_class(symbol) == best)
            .collect();

        let names: HashSet<&str> = ranked
            .iter()
            .filter_map(|symbol| symbol.name.as_deref())
            .collect();
        let total = names
            .iter()
            .filter_map(|name| self.importers.get(*name))
            .fold(0usize, |sum, count| sum.saturating_add(*count));
        let majority = ranked
            .iter()
            .copied()
            .find(|symbol| self.importers_of(symbol).saturating_mul(2) > total);

        majority.or_else(|| ranked.first().copied())
    }
}

impl ForwardedExport {
    fn kinds(&self) -> &'static [PeKind] {
        match self.kind {
            Some(PeKind::Pe32) => &[PeKind::Pe32],
            Some(PeKind::Pe32Plus) => &[PeKind::Pe32Plus],
            None => &[PeKind::Pe32, PeKind::Pe32Plus],
        }
    }
}

impl ExportIndex {
    pub(crate) fn build<'a>(
        images: impl IntoIterator<Item = (usize, &'a [u8], Option<&'a str>)>,
        api_sets: &[Vec<u8>],
    ) -> Self {
        let mut index = Self::default();
        let mut definitions = ExportDefinitions::default();
        let mut forwarders = Vec::new();
        let mut redirected = Vec::new();
        let mut imported = Vec::new();

        for (base, bytes, loaded_name) in images {
            index.stats.modules = index.stats.modules.saturating_add(1);
            index
                .image_ranges
                .push(base..base.saturating_add(bytes.len()));

            let Ok(image) = parse_memory_image(bytes) else {
                continue;
            };
            imported.extend(imported_names(&image));

            let Some(parsed) = parse_exports(base, &image, loaded_name) else {
                continue;
            };
            definitions.add_image(&parsed.module, parsed.kind);

            for (address, symbol) in parsed.direct {
                definitions.add(parsed.kind, address, &symbol);
                index.add(address, symbol);
            }

            forwarders.extend(parsed.forwarders);
            redirected.extend(parsed.redirected);
            index.variables.extend(parsed.variables);
        }

        definitions.find_hosts();
        index.stats.forwarders = forwarders.len();
        index.stats.unresolved_forwarders =
            resolve_forwarders(&mut index, &definitions, &forwarders);

        let contracts: Vec<ForwardedExport> = api_sets
            .iter()
            .flat_map(|file| api_set_forwarders(file))
            .collect();
        resolve_forwarders(&mut index, &definitions, &contracts);

        index.image_ranges.sort_unstable_by_key(|range| range.start);
        for (address, symbol) in redirected {
            if index.covers(address) {
                index.add(address, symbol);
            }
        }

        index.settle(imported);
        index.stats.addresses = index.addresses.len();

        index
    }

    fn add(&mut self, address: usize, symbol: ExportSymbol) {
        self.addresses
            .entry(address)
            .or_default()
            .symbols
            .push(symbol);
    }

    fn settle(&mut self, imported: Vec<(usize, String)>) {
        for exported in self.addresses.values_mut() {
            exported.settle();
        }

        for (address, name) in imported {
            let Some(exported) = self.addresses.get_mut(&address) else {
                continue;
            };

            // a slot that still holds the export it names
            let intact = exported
                .symbols
                .iter()
                .any(|symbol| symbol.name.as_deref() == Some(name.as_str()));

            if intact {
                let count = exported.importers.entry(name).or_default();
                *count = count.saturating_add(1);
            }
        }
    }

    pub(crate) fn stats(&self) -> ExportStats {
        self.stats
    }

    pub(crate) fn is_variable(&self, address: usize) -> bool {
        self.variables.contains(&address)
    }

    pub(crate) fn covers(&self, address: usize) -> bool {
        let following = self
            .image_ranges
            .partition_point(|range| range.start <= address);
        following
            .checked_sub(1)
            .and_then(|index| self.image_ranges.get(index))
            .is_some_and(|range| range.contains(&address))
    }

    pub(crate) fn resolve(&self, address: usize) -> Option<Resolved<'_>> {
        let exported = self.addresses.get(&address)?;
        let best = exported.symbols.iter().map(naming_class).max()?;
        let top: Vec<&ExportSymbol> = exported
            .symbols
            .iter()
            .filter(|symbol| naming_class(symbol) == best)
            .collect();

        let module = &top.first()?.module; // name order, never load order
        let own: Vec<&ExportSymbol> = top
            .iter()
            .copied()
            .filter(|symbol| symbol.module.eq_ignore_ascii_case(module))
            .collect();
        let symbol = exported.preferred(&own)?;

        let rival_name = top.iter().any(|other| {
            modules_differ(other, symbol) && !own.iter().any(|mine| mine.name == other.name)
        });
        let ambiguous = rival_name || definitions_conflict(&exported.symbols);
        let aliased = !ambiguous
            && exported
                .symbols
                .iter()
                .any(|other| is_another_pick(other, symbol, best));

        Some(Resolved {
            symbol,
            ambiguous,
            aliased,
        })
    }

    // the preferred name first, the others in table order
    pub(crate) fn names_in(&self, address: usize, module: &str) -> impl Iterator<Item = &str> {
        let named: Vec<&ExportSymbol> = self
            .symbols_at(address)
            .filter(|symbol| symbol.module.eq_ignore_ascii_case(module) && symbol.name.is_some())
            .collect();
        let first = self
            .addresses
            .get(&address)
            .and_then(|exported| exported.preferred(&named))
            .and_then(|symbol| symbol.name.as_deref());

        let others = named
            .into_iter()
            .filter_map(|symbol| symbol.name.as_deref())
            .filter(move |name| Some(*name) != first);

        first.into_iter().chain(others)
    }

    pub(crate) fn export_named(
        &self,
        address: usize,
        module: &str,
        name: &str,
    ) -> Option<ExportSymbol> {
        self.symbols_at(address)
            .find(|symbol| {
                symbol.module.eq_ignore_ascii_case(module) && symbol.name.as_deref() == Some(name)
            })
            .cloned()
    }

    pub(crate) fn addresses(&self) -> impl Iterator<Item = usize> + '_ {
        self.addresses.keys().copied()
    }

    pub(crate) fn address_of(&self, module: &str, name: &str) -> Option<usize> {
        self.addresses
            .iter()
            .find(|(_, exported)| {
                exported.symbols.iter().any(|symbol| {
                    symbol.module.eq_ignore_ascii_case(module)
                        && symbol.name.as_deref() == Some(name)
                })
            })
            .map(|(address, _)| *address)
    }

    pub(crate) fn names_at(&self, address: usize) -> impl Iterator<Item = &str> {
        self.symbols_at(address)
            .filter_map(|symbol| symbol.name.as_deref())
    }

    fn symbols_at(&self, address: usize) -> impl Iterator<Item = &ExportSymbol> {
        self.addresses
            .get(&address)
            .into_iter()
            .flat_map(|exported| &exported.symbols)
    }

    pub(crate) fn modules_at(&self, address: usize) -> impl Iterator<Item = (&str, bool)> {
        self.symbols_at(address)
            .map(|symbol| (symbol.module.as_str(), symbol.forwarded))
    }

    pub(crate) fn resolve_fitting(
        &self,
        address: usize,
        fits: impl Fn(&str) -> bool,
    ) -> Option<&ExportSymbol> {
        let fitting: Vec<&ExportSymbol> = self
            .symbols_at(address)
            .filter(|symbol| symbol.name.as_deref().is_some_and(&fits))
            .collect();
        let name = &fitting.first()?.name;

        fitting
            .iter()
            .all(|symbol| &symbol.name == name)
            .then(|| {
                fitting
                    .iter()
                    .copied()
                    .min_by_key(|symbol| Reverse(naming_priority(symbol)))
            })
            .flatten()
    }

    pub(crate) fn resolve_ordinal(&self, address: usize, ordinal: u32) -> Option<ExportSymbol> {
        let symbol = self
            .symbols_at(address)
            .filter(|symbol| symbol.ordinal == ordinal)
            .min_by_key(|symbol| Reverse(naming_priority(symbol)))?;

        Some(ExportSymbol {
            name: None,
            ..symbol.clone()
        })
    }

    pub(crate) fn ordinal_in(&self, address: usize, module: &str) -> Option<u32> {
        self.symbols_at(address)
            .find(|symbol| symbol.module.eq_ignore_ascii_case(module))
            .map(|symbol| symbol.ordinal)
    }
}

pub(crate) struct Resolved<'a> {
    pub(crate) symbol: &'a ExportSymbol,
    pub(crate) ambiguous: bool,
    pub(crate) aliased: bool,
}

fn naming_class(symbol: &ExportSymbol) -> (bool, NamingPriority) {
    (is_undecorated(symbol), naming_priority(symbol))
}

fn is_undecorated(symbol: &ExportSymbol) -> bool {
    symbol
        .name
        .as_deref()
        .is_some_and(|name| !name.starts_with('?'))
}

fn naming_priority(symbol: &ExportSymbol) -> NamingPriority {
    if is_api_set(&symbol.module) {
        return NamingPriority::ApiSetAlias;
    }

    match symbol.forwarded {
        true => NamingPriority::Facade,
        false => NamingPriority::Implementation,
    }
}

fn is_another_pick(
    other: &ExportSymbol,
    picked: &ExportSymbol,
    best: (bool, NamingPriority),
) -> bool {
    let other_name = other.name != picked.name;
    let other_ordinal = picked.name.is_none() && other.ordinal != picked.ordinal;
    let other_module = naming_class(other) == best && modules_differ(other, picked);

    other_name || other_ordinal || other_module
}

fn definitions_conflict(symbols: &[ExportSymbol]) -> bool {
    let definitions = symbols
        .iter()
        .filter(|symbol| !symbol.forwarded)
        .collect::<Vec<_>>();

    definitions.iter().enumerate().any(|(index, left)| {
        definitions
            .iter()
            .skip(index.saturating_add(1))
            .any(|right| modules_differ(left, right) && left.name != right.name)
    })
}

fn modules_differ(left: &ExportSymbol, right: &ExportSymbol) -> bool {
    !left.module.eq_ignore_ascii_case(&right.module)
}

pub(crate) fn embedded_module_name(bytes: &[u8]) -> Option<String> {
    let image = parse_memory_image(bytes).ok()?;
    let (rva, _) = export_directory(&image)?;

    stored_module_name(bytes, rva)
        .as_deref()
        .map(normalize_module)
}

struct ExportHeader {
    ordinal_base: u32,
    function_count: usize,
    name_count: usize,
    functions_rva: usize,
    names_rva: usize,
    ordinals_rva: usize,
    directory_rva: u32,
    directory_end: u32,
}

impl ExportHeader {
    fn forwards(&self, function_rva: u32) -> bool {
        (self.directory_rva..self.directory_end).contains(&function_rva) // a name, not code
    }
}

impl ParsedExports {
    fn place(
        &mut self,
        image: &PeImage<'_>,
        base: usize,
        header: &ExportHeader,
        function_rva: u32,
        symbol: ExportSymbol,
    ) {
        let model = image.model();

        if header.forwards(function_rva) {
            if let Some(target) = read_ascii(image.bytes(), function_rva as usize) {
                self.forwarders.push(ForwardedExport {
                    source: ExportSymbol {
                        forwarded: true,
                        ..symbol
                    },
                    target,
                    kind: Some(self.kind),
                });
            }

            return;
        }

        let Some(address) = export_address(base, self.kind, function_rva) else {
            return;
        };

        if function_rva >= model.image_size {
            let facade = ExportSymbol {
                forwarded: true,
                ..symbol
            };
            self.redirected.push((address, facade)); // user32 turns its ntdll forwarders into rvas past itself
            return;
        }

        if !model.executable_rva(Rva(function_rva)) {
            self.variables.push(address);
        }

        self.direct.push((address, symbol));
    }
}

fn parse_exports(
    base: usize,
    image: &PeImage<'_>,
    loaded_name: Option<&str>,
) -> Option<ParsedExports> {
    let bytes = image.bytes();
    let kind = image.model().kind;
    export_address(base, kind, 0)?; // pe32 mapped above 4 GiB

    let header = export_header(image)?;
    let module = module_name(bytes, &header, loaded_name)?;
    let mut names = export_names(bytes, &header)?;

    let mut parsed = ParsedExports {
        kind,
        module: module.clone(),
        direct: Vec::new(),
        variables: Vec::new(),
        redirected: Vec::new(),
        forwarders: Vec::new(),
    };

    for index in 0..header.function_count {
        let Some(function_rva) = table_entry(bytes, header.functions_rva, index) else {
            break; // the table leaves the image
        };

        if function_rva == 0 {
            continue;
        }

        let Some(ordinal) = u32::try_from(index)
            .ok()
            .and_then(|step| header.ordinal_base.checked_add(step))
        else {
            continue;
        };

        let aliases: Vec<Option<String>> = match names.remove(&index) {
            Some(names) => names.into_iter().map(Some).collect(),
            None => vec![None],
        };

        for name in aliases {
            let symbol = ExportSymbol {
                module: module.clone(),
                name,
                ordinal,
                forwarded: false,
            };
            parsed.place(image, base, &header, function_rva, symbol);
        }
    }

    Some(parsed)
}

fn export_address(base: usize, kind: PeKind, function_rva: u32) -> Option<usize> {
    match kind {
        // 32-bit wraparound
        PeKind::Pe32 => Some(u32::try_from(base).ok()?.wrapping_add(function_rva) as usize),
        PeKind::Pe32Plus => base.checked_add(function_rva as usize),
    }
}

fn module_name(bytes: &[u8], header: &ExportHeader, loaded_name: Option<&str>) -> Option<String> {
    let embedded = stored_module_name(bytes, header.directory_rva)
        .as_deref()
        .map(normalize_module);

    match (embedded, loaded_name.map(normalize_module)) {
        (Some(embedded), Some(loaded)) if embedded.eq_ignore_ascii_case(&loaded) => Some(embedded),
        (_, Some(loaded)) => Some(loaded),
        (embedded, None) => embedded, // nameless: no import can refer to it
    }
}

pub(crate) fn export_rva(bytes: &[u8], name: &str) -> Option<usize> {
    let image = parse_memory_image(bytes).ok()?;
    let header = export_header(&image)?;

    let (_, slot) = (0..header.name_count)
        .map_while(|index| name_entry(bytes, &header, index))
        .find(|(name_rva, _)| {
            read_ascii(bytes, *name_rva as usize).is_some_and(|found| found == name)
        })?;
    (slot < header.function_count).then_some(())?;

    let function = table_entry(bytes, header.functions_rva, slot)?;
    (!header.forwards(function)).then_some(function as usize)
}

fn export_directory(image: &PeImage<'_>) -> Option<(u32, u32)> {
    let directory = image.directory(EXPORT_DIRECTORY)?;
    let size = directory.size();
    (size >= EXPORT_DIRECTORY_SIZE as u32).then_some((directory.rva().get(), size))
}

fn stored_module_name(bytes: &[u8], directory_rva: u32) -> Option<String> {
    let field = (directory_rva as usize).checked_add(EXPORT_NAME_OFFSET)?;
    let name_rva = read_u32(bytes, field)?;

    read_ascii(bytes, name_rva as usize)
}

fn export_header(image: &PeImage<'_>) -> Option<ExportHeader> {
    let (directory_rva, directory_size) = export_directory(image)?;
    let bytes = image.bytes();
    let field = |offset: usize| read_u32(bytes, (directory_rva as usize).checked_add(offset)?);

    let function_count = field(EXPORT_FUNCTION_COUNT_OFFSET)? as usize;
    let name_count = field(EXPORT_NAME_COUNT_OFFSET)? as usize;

    if function_count == 0 || name_count > MAX_EXPORT_NAMES {
        return None;
    }

    Some(ExportHeader {
        ordinal_base: field(EXPORT_ORDINAL_BASE_OFFSET)?,
        function_count: function_count.min(MAX_EXPORTS),
        name_count,
        functions_rva: field(EXPORT_FUNCTIONS_OFFSET)? as usize,
        names_rva: field(EXPORT_NAMES_OFFSET)? as usize,
        ordinals_rva: field(EXPORT_ORDINALS_OFFSET)? as usize,
        directory_rva,
        directory_end: directory_rva.checked_add(directory_size)?,
    })
}

fn table_entry(bytes: &[u8], table: usize, index: usize) -> Option<u32> {
    read_u32(
        bytes,
        table.checked_add(index.checked_mul(EXPORT_ENTRY_SIZE)?)?,
    )
}

fn name_entry(bytes: &[u8], header: &ExportHeader, index: usize) -> Option<(u32, usize)> {
    let name_rva = table_entry(bytes, header.names_rva, index)?;
    let slot = read_u16(
        bytes,
        header
            .ordinals_rva
            .checked_add(index.checked_mul(EXPORT_ORDINAL_SIZE)?)?,
    )?;

    Some((name_rva, usize::from(slot)))
}

fn export_names(bytes: &[u8], header: &ExportHeader) -> Option<HashMap<usize, Vec<String>>> {
    let mut names = HashMap::<usize, Vec<String>>::new();
    for index in 0..header.name_count {
        // table leaves the image: count not trustworthy
        let (name_rva, slot) = name_entry(bytes, header, index)?;

        if slot >= header.function_count {
            continue;
        }

        if let Some(name) = read_ascii(bytes, name_rva as usize) {
            names.entry(slot).or_default().push(name);
        }
    }

    Some(names)
}

// the dlls the loader mapped for the image's own import table, lower case
pub(crate) fn imported_dlls(image: &PeImage<'_>) -> HashSet<String> {
    let bytes = image.bytes();

    image
        .import_descriptors()
        .filter_map(|descriptor| read_ascii(bytes, descriptor.name as usize))
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

fn imported_names(image: &PeImage<'_>) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let bytes = image.bytes();
    let kind = image.model().kind;
    let mut budget = bytes.len() / kind.pointer_width(); // no image holds more thunks than this

    for descriptor in image.import_descriptors() {
        let (lookup, thunks) = (descriptor.lookup, descriptor.iat);
        if lookup == 0 {
            continue; // names already overwritten by addresses
        }

        for index in 0usize.. {
            let Some(left) = budget.checked_sub(1) else {
                return found;
            };
            budget = left;

            let entry = thunk(bytes, kind, lookup, index);
            let Some(entry) = entry.filter(|entry| *entry != 0) else {
                break;
            };

            if entry as u64 & kind.ordinal_flag() != 0 {
                continue;
            }

            let value = thunk(bytes, kind, thunks, index);
            let name = entry
                .checked_add(HINT_SIZE)
                .and_then(|at| read_ascii(bytes, at));

            if let (Some(value), Some(name)) = (value, name) {
                found.push((value, name));
            }
        }
    }

    found
}

fn thunk(bytes: &[u8], kind: PeKind, table: u32, index: usize) -> Option<usize> {
    let at = (table as usize).checked_add(index.checked_mul(kind.pointer_width())?)?;

    bytes::read_pointer(bytes, at, kind).ok()
}

fn resolve_forwarders(
    index: &mut ExportIndex,
    definitions: &ExportDefinitions,
    forwarders: &[ForwardedExport],
) -> usize {
    let mut pending = Pending::new();
    for forwarder in forwarders {
        let module = forwarder.source.module.to_ascii_lowercase();

        for kind in forwarder.kinds() {
            let owner = (module.clone(), *kind);
            let ordinal = ExportKey::Ordinal(forwarder.source.ordinal);
            hold(&mut pending, (owner.clone(), ordinal), forwarder);

            if let Some(name) = &forwarder.source.name {
                hold(
                    &mut pending,
                    (owner, ExportKey::Name(name.clone())),
                    forwarder,
                );
            }
        }
    }

    let mut unresolved = 0usize;
    for forwarder in forwarders {
        let mut reached = false;

        for kind in forwarder.kinds() {
            let Some(address) = resolve_target(&forwarder.target, *kind, definitions, &pending)
            else {
                continue;
            };

            reached = true;
            index.add(address, forwarder.source.clone());
        }

        if !reached {
            unresolved = unresolved.saturating_add(1);
        }
    }

    unresolved
}

fn hold<'a>(
    pending: &mut Pending<'a>,
    key: (ModuleKey, ExportKey),
    forwarder: &'a ForwardedExport,
) {
    pending
        .entry(key)
        .and_modify(|known| {
            if known.is_some_and(|known| known.target != forwarder.target) {
                *known = None;
            }
        })
        .or_insert(Some(forwarder));
}

fn api_set_forwarders(file: &[u8]) -> Vec<ForwardedExport> {
    let mapped = parse_disk_image(file)
        .ok()
        .and_then(|disk| map_disk_image(file, disk.model().image_size as usize));
    let Some(mapped) = mapped else {
        return Vec::new();
    };
    let Ok(image) = parse_memory_image(&mapped) else {
        return Vec::new();
    };

    let mut forwarders = parse_exports(0, &image, None)
        .map(|parsed| parsed.forwarders)
        .unwrap_or_default();
    for forwarder in &mut forwarders {
        forwarder.kind = None;
    }

    forwarders
}

fn resolve_target(
    target: &str,
    kind: PeKind,
    definitions: &ExportDefinitions,
    pending: &Pending<'_>,
) -> Option<usize> {
    let (mut module, mut key) = parse_forward_target(target)?;
    let mut visited = HashSet::new();

    loop {
        let owner = (module.to_ascii_lowercase(), kind);
        let lookup = (owner.clone(), key.clone());

        if !visited.insert(lookup.clone()) || definitions.duplicated(&owner) {
            return None;
        }

        if let Some(address) = definitions.by_module.get(&lookup) {
            return *address;
        }

        if let (true, ExportKey::Name(name)) = (is_api_set(&owner.0), &key)
            && let Some(host) = definitions.hosts.get(&(kind, name.clone()))
        {
            return *host;
        }

        let next = (*pending.get(&lookup)?)?;
        (module, key) = parse_forward_target(&next.target)?;
    }
}

pub(crate) fn is_api_set(module: &str) -> bool {
    let Some(head) = module.as_bytes().get(..4) else {
        return false;
    };

    head.eq_ignore_ascii_case(b"api-") || head.eq_ignore_ascii_case(b"ext-")
}

fn parse_forward_target(target: &str) -> Option<(String, ExportKey)> {
    let (module, symbol) = target.rsplit_once('.')?;
    let key = match symbol.strip_prefix('#') {
        Some(value) => ExportKey::Ordinal(value.parse().ok()?),
        None => ExportKey::Name(symbol.to_owned()),
    };

    Some((normalize_module(module), key))
}

fn normalize_module(name: &str) -> String {
    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);

    if basename.contains('.') {
        basename.to_owned()
    } else {
        format!("{basename}.dll")
    }
}

fn read_ascii(bytes: &[u8], offset: usize) -> Option<String> {
    (offset != 0).then_some(())?; // a zero rva names nothing
    bytes::read_ascii(bytes, offset, MAX_NAME_LENGTH).map(str::to_owned)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes::read_u16(bytes, offset).ok()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes::read_u32(bytes, offset).ok()
}
