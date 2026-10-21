use std::cmp::Reverse;
use std::collections::HashMap;

use crate::pe::image;
use crate::pe::parse::parse_memory_image;
use crate::pe::{PeImage, Rva};

const EXPORT_DIRECTORY: usize = 0;
const EXPORT_HEADER_SIZE: usize = 40;
const MAX_EXPORTS: usize = 1_048_576;
const MAX_EXPORT_NAME: usize = 4_096;
const MAX_FORWARD_DEPTH: usize = 8;

#[derive(Clone)]
pub(crate) struct ResolvedExport {
    pub(crate) module: String,
    pub(crate) name: Option<String>,
    pub(crate) ordinal: u32,
    forwarded: bool,
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
    addresses: HashMap<usize, Vec<ResolvedExport>>,
    stats: ExportStats,
}

struct ForwardedExport {
    source: ResolvedExport,
    target: String,
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

struct ParsedExports {
    direct: Vec<(usize, ResolvedExport)>,
    forwarders: Vec<ForwardedExport>,
}

struct Definitions {
    by_module: HashMap<(String, ExportKey), usize>,
    unique_by_key: HashMap<ExportKey, Option<usize>>,
}

impl Definitions {
    fn build(by_module: HashMap<(String, ExportKey), usize>) -> Self {
        let mut unique_by_key = HashMap::<ExportKey, Option<usize>>::with_capacity(by_module.len());
        for ((_, key), address) in &by_module {
            unique_by_key
                .entry(key.clone())
                .and_modify(|known| {
                    if *known != Some(*address) {
                        *known = None;
                    }
                })
                .or_insert(Some(*address));
        }
        Self {
            by_module,
            unique_by_key,
        }
    }
}

impl ExportIndex {
    pub(crate) fn build<'a>(
        images: impl IntoIterator<Item = (usize, &'a [u8], Option<&'a str>)>,
    ) -> Self {
        let mut index = Self::default();
        let mut definitions = HashMap::<(String, ExportKey), usize>::new();
        let mut forwarders = Vec::new();

        for (base, bytes, fallback_name) in images {
            index.stats.modules = index.stats.modules.saturating_add(1);
            let Some(parsed) = parse_exports(base, bytes, fallback_name) else {
                continue;
            };
            for (address, symbol) in parsed.direct {
                add_definition(&mut definitions, address, &symbol);
                index.addresses.entry(address).or_default().push(symbol);
            }
            forwarders.extend(parsed.forwarders);
        }

        index.stats.forwarders = forwarders.len();
        resolve_forwarders(&mut index, &Definitions::build(definitions), &forwarders);
        index.stats.addresses = index.addresses.len();
        index
    }

    pub(crate) fn stats(&self) -> ExportStats {
        self.stats
    }

    pub(crate) fn resolve(&self, address: usize) -> Option<Resolved<'_>> {
        let symbols = self.addresses.get(&address)?;
        let symbol = preferred_symbol(symbols)?;
        let ambiguous = symbols
            .iter()
            .any(|other| modules_differ(other, symbol) && !names_match(other, symbol));
        let aliased = !ambiguous
            && symbols.len() > 1
            && symbols.iter().any(|other| !names_match(other, symbol));
        Some(Resolved {
            symbol,
            ambiguous,
            aliased,
        })
    }
}

pub(crate) struct Resolved<'a> {
    pub(crate) symbol: &'a ResolvedExport,
    pub(crate) ambiguous: bool,
    pub(crate) aliased: bool,
}

fn preferred_symbol(symbols: &[ResolvedExport]) -> Option<&ResolvedExport> {
    symbols
        .iter()
        .min_by_key(|symbol| Reverse((is_undecorated(symbol), naming_priority(symbol))))
}

fn is_undecorated(symbol: &ResolvedExport) -> bool {
    symbol
        .name
        .as_deref()
        .is_some_and(|name| !name.starts_with('?'))
}

fn naming_priority(symbol: &ResolvedExport) -> NamingPriority {
    if is_api_set(&symbol.module) {
        return NamingPriority::ApiSetAlias;
    }
    match symbol.forwarded {
        true => NamingPriority::Facade,
        false => NamingPriority::Implementation,
    }
}

fn names_match(left: &ResolvedExport, right: &ResolvedExport) -> bool {
    match (left.name.as_deref(), right.name.as_deref()) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

fn modules_differ(left: &ResolvedExport, right: &ResolvedExport) -> bool {
    !left.module.eq_ignore_ascii_case(&right.module)
}

pub(crate) fn embedded_module_name(bytes: &[u8]) -> Option<String> {
    let image = parse_memory_image(bytes).ok()?;
    let (rva, size) = directory(&image, EXPORT_DIRECTORY)?;
    if size < EXPORT_HEADER_SIZE as u32 {
        return None;
    }
    let name_rva = read_u32(bytes, rva as usize + 12)?;
    read_ascii(bytes, name_rva as usize)
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

fn parse_exports(base: usize, bytes: &[u8], fallback_name: Option<&str>) -> Option<ParsedExports> {
    let image = parse_memory_image(bytes).ok()?;
    let model = image.model();
    let header = export_header(&image, bytes)?;
    let embedded = read_u32(bytes, header.directory_rva as usize + 12)
        .and_then(|rva| read_ascii(bytes, rva as usize));
    let module = normalize_module(
        embedded
            .as_deref()
            .or(fallback_name)
            .unwrap_or("unknown.dll"),
    );
    let names = export_names(bytes, &header)?;

    let mut direct = Vec::new();
    let mut forwarders = Vec::new();
    for index in 0..header.function_count {
        let entry = index
            .checked_mul(4)
            .and_then(|step| header.functions_rva.checked_add(step));
        let Some(function_rva) = entry.and_then(|offset| read_u32(bytes, offset)) else {
            continue;
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
        let aliases = names
            .get(&index)
            .cloned()
            .unwrap_or_else(|| vec![String::new()]);
        let forwarded =
            function_rva >= header.directory_rva && function_rva < header.directory_end;
        for alias in aliases {
            let symbol = ResolvedExport {
                module: module.clone(),
                name: (!alias.is_empty()).then_some(alias),
                ordinal,
                forwarded,
            };
            if forwarded {
                if let Some(target) = read_ascii(bytes, function_rva as usize) {
                    forwarders.push(ForwardedExport {
                        source: symbol,
                        target,
                    });
                }
                continue;
            }
            if function_rva < model.image_size()
                && let Some(address) = base.checked_add(function_rva as usize)
            {
                direct.push((address, symbol));
            }
        }
    }
    Some(ParsedExports { direct, forwarders })
}

fn export_header(image: &PeImage<'_>, bytes: &[u8]) -> Option<ExportHeader> {
    let (directory_rva, directory_size) = directory(image, EXPORT_DIRECTORY)?;
    if directory_size < EXPORT_HEADER_SIZE as u32 {
        return None;
    }
    let directory_offset = directory_rva as usize;
    let ordinal_base = read_u32(bytes, directory_offset + 16)?;
    let function_count = read_u32(bytes, directory_offset + 20)? as usize;
    let name_count = read_u32(bytes, directory_offset + 24)? as usize;
    if function_count == 0 || function_count > MAX_EXPORTS || name_count > MAX_EXPORTS {
        return None;
    }
    let functions_rva = read_u32(bytes, directory_offset + 28)? as usize;
    let names_rva = read_u32(bytes, directory_offset + 32)? as usize;
    let ordinals_rva = read_u32(bytes, directory_offset + 36)? as usize;
    checked_array(bytes, functions_rva, function_count, 4)?;
    checked_array(bytes, names_rva, name_count, 4)?;
    checked_array(bytes, ordinals_rva, name_count, 2)?;
    Some(ExportHeader {
        ordinal_base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
        directory_rva,
        directory_end: directory_rva.checked_add(directory_size)?,
    })
}

fn export_names(bytes: &[u8], header: &ExportHeader) -> Option<HashMap<usize, Vec<String>>> {
    let mut names = HashMap::<usize, Vec<String>>::new();
    for index in 0..header.name_count {
        let name_rva = read_u32(bytes, header.names_rva.checked_add(index.checked_mul(4)?)?)?;
        let ordinal_index = read_u16(
            bytes,
            header.ordinals_rva.checked_add(index.checked_mul(2)?)?,
        )?;
        let ordinal_index = usize::from(ordinal_index);
        if ordinal_index >= header.function_count {
            continue;
        }
        if let Some(name) = read_ascii(bytes, name_rva as usize) {
            names.entry(ordinal_index).or_default().push(name);
        }
    }
    Some(names)
}

fn resolve_forwarders(
    index: &mut ExportIndex,
    definitions: &Definitions,
    forwarders: &[ForwardedExport],
) {
    let mut pending = HashMap::<(String, ExportKey), &ForwardedExport>::new();
    for forwarder in forwarders {
        let module = forwarder.source.module.to_ascii_lowercase();
        pending.insert(
            (module.clone(), ExportKey::Ordinal(forwarder.source.ordinal)),
            forwarder,
        );
        if let Some(name) = &forwarder.source.name {
            pending.insert(
                (module, ExportKey::Name(name.to_ascii_lowercase())),
                forwarder,
            );
        }
    }
    for forwarder in forwarders {
        let Some((module, key)) = parse_forward_target(&forwarder.target) else {
            index.stats.unresolved_forwarders = index.stats.unresolved_forwarders.saturating_add(1);
            continue;
        };
        let Some(address) = resolve_key(&module, &key, definitions, &pending) else {
            index.stats.unresolved_forwarders = index.stats.unresolved_forwarders.saturating_add(1);
            continue;
        };
        index
            .addresses
            .entry(address)
            .or_default()
            .push(forwarder.source.clone());
    }
}

fn resolve_key(
    module: &str,
    key: &ExportKey,
    definitions: &Definitions,
    pending: &HashMap<(String, ExportKey), &ForwardedExport>,
) -> Option<usize> {
    let mut module = normalize_module(module).to_ascii_lowercase();
    let mut key = key.clone();
    for _hop in 0..MAX_FORWARD_DEPTH {
        let lookup = (module.clone(), key.clone());
        if let Some(address) = definitions.by_module.get(&lookup) {
            return Some(*address);
        }
        if is_api_set(&module) {
            match definitions.unique_by_key.get(&key) {
                Some(Some(address)) => return Some(*address),
                Some(None) => return None,
                None => {}
            }
        }
        let next = pending.get(&lookup)?;
        (module, key) = parse_forward_target(&next.target)?;
        module.make_ascii_lowercase();
    }
    None
}

fn is_api_set(module: &str) -> bool {
    let Some(head) = module.as_bytes().get(..4) else {
        return false;
    };
    head.eq_ignore_ascii_case(b"api-") || head.eq_ignore_ascii_case(b"ext-")
}

fn add_definition(
    definitions: &mut HashMap<(String, ExportKey), usize>,
    address: usize,
    symbol: &ResolvedExport,
) {
    let module = symbol.module.to_ascii_lowercase();
    definitions
        .entry((module.clone(), ExportKey::Ordinal(symbol.ordinal)))
        .or_insert(address);
    if let Some(name) = &symbol.name {
        definitions
            .entry((module, ExportKey::Name(name.to_ascii_lowercase())))
            .or_insert(address);
    }
}

fn parse_forward_target(target: &str) -> Option<(String, ExportKey)> {
    let (module, symbol) = target.rsplit_once('.')?;
    let key = match symbol.strip_prefix('#') {
        Some(value) => ExportKey::Ordinal(value.parse().ok()?),
        None => ExportKey::Name(symbol.to_ascii_lowercase()),
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

fn directory(image: &PeImage<'_>, index: usize) -> Option<(u32, u32)> {
    let directory = image.directory(index).ok()??;
    Some((directory.rva().get(), directory.size()))
}

fn checked_array(bytes: &[u8], offset: usize, count: usize, width: usize) -> Option<()> {
    let length = count.checked_mul(width)?;
    bytes.get(offset..offset.checked_add(length)?).map(|_| ())
}

fn read_ascii(bytes: &[u8], offset: usize) -> Option<String> {
    let rva = u32::try_from(offset).ok().map(Rva)?;
    image::read_ascii(bytes, rva, MAX_EXPORT_NAME).map(str::to_owned)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    image::read_u16(bytes, offset).ok()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    image::read_u32(bytes, offset).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Definitions, ExportIndex, ExportKey, ResolvedExport, parse_forward_target};

    fn export(name: &str, module: &str) -> ResolvedExport {
        ResolvedExport {
            module: module.to_owned(),
            name: Some(name.to_owned()),
            ordinal: 1,
            forwarded: false,
        }
    }

    fn index_with(address: usize, symbols: Vec<ResolvedExport>) -> ExportIndex {
        let mut index = ExportIndex::default();
        index.addresses.insert(address, symbols);
        index
    }

    #[test]
    fn prefers_an_undecorated_alias_over_a_mangled_one() -> Result<(), Box<dyn std::error::Error>> {
        let index = index_with(
            0x1000,
            vec![
                export(
                    "?GetCurrentThreadId@platform@details@Concurrency@@YAJXZ",
                    "MSVCP140.dll",
                ),
                export("_Thrd_id", "MSVCP140.dll"),
            ],
        );

        let found = index.resolve(0x1000).ok_or("address is indexed")?;

        assert_eq!(found.symbol.name.as_deref(), Some("_Thrd_id"));
        assert!(found.aliased);
        assert!(!found.ambiguous);
        Ok(())
    }

    #[test]
    fn keeps_the_only_name_when_nothing_aliases_it() -> Result<(), Box<dyn std::error::Error>> {
        let index = index_with(0x2000, vec![export("?mangled@@YAXXZ", "one.dll")]);

        let found = index.resolve(0x2000).ok_or("address is indexed")?;

        assert_eq!(found.symbol.name.as_deref(), Some("?mangled@@YAXXZ"));
        assert!(!found.aliased);
        Ok(())
    }

    #[test]
    fn reports_cross_module_collisions_as_ambiguous_not_aliased()
    -> Result<(), Box<dyn std::error::Error>> {
        let index = index_with(
            0x3000,
            vec![export("shared", "one.dll"), export("other", "two.dll")],
        );

        let found = index.resolve(0x3000).ok_or("address is indexed")?;

        assert!(found.ambiguous);
        assert!(!found.aliased);
        Ok(())
    }

    #[test]
    fn ignores_a_zero_export_name_rva() {
        let mut image = vec![0u8; 0x200];
        image[..4].copy_from_slice(b"MZ\0\0");
        image[0x100..0x108].copy_from_slice(b"real.dll");

        assert_eq!(super::read_ascii(&image, 0), None);
        assert_eq!(
            super::read_ascii(&image, 0x100).as_deref(),
            Some("real.dll")
        );
    }

    #[test]
    fn parses_named_and_ordinal_forwarders() {
        assert!(parse_forward_target("KERNELBASE.CreateFileW").is_some());
        assert!(parse_forward_target("NTDLL.#42").is_some());
        assert!(parse_forward_target("broken").is_none());
    }

    #[test]
    fn keeps_only_unambiguous_addresses_per_key() {
        let by_module = HashMap::from([
            (("a.dll".to_owned(), ExportKey::Ordinal(1)), 0x10),
            (("b.dll".to_owned(), ExportKey::Ordinal(1)), 0x10),
            (("a.dll".to_owned(), ExportKey::Ordinal(2)), 0x20),
            (("b.dll".to_owned(), ExportKey::Ordinal(2)), 0x30),
        ]);

        let definitions = Definitions::build(by_module);

        assert_eq!(
            definitions.unique_by_key.get(&ExportKey::Ordinal(1)),
            Some(&Some(0x10))
        );
        assert_eq!(
            definitions.unique_by_key.get(&ExportKey::Ordinal(2)),
            Some(&None)
        );
        assert_eq!(definitions.unique_by_key.get(&ExportKey::Ordinal(3)), None);
    }
}
