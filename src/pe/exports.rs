use std::collections::HashMap;

use crate::pe::parse::parse_memory_image;

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

#[derive(Clone, Eq, Hash, PartialEq)]
enum ExportKey {
    Name(String),
    Ordinal(u32),
}

struct ParsedExports {
    direct: Vec<(usize, ResolvedExport)>,
    forwarders: Vec<ForwardedExport>,
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
        resolve_forwarders(&mut index, &definitions, &forwarders);
        index.stats.addresses = index.addresses.len();
        index
    }

    pub(crate) fn stats(&self) -> ExportStats {
        self.stats
    }

    pub(crate) fn resolve(&self, address: usize) -> Option<(&ResolvedExport, bool)> {
        let symbols = self.addresses.get(&address)?;
        let first = symbols.first()?;
        let ambiguous = symbols
            .iter()
            .any(|symbol| !symbol.module.eq_ignore_ascii_case(&first.module));
        Some((first, ambiguous))
    }
}

pub(crate) fn embedded_module_name(bytes: &[u8]) -> Option<String> {
    let model = parse_memory_image(bytes).ok()?;
    let (rva, size) = directory(bytes, &model, EXPORT_DIRECTORY)?;
    if size < EXPORT_HEADER_SIZE as u32 {
        return None;
    }
    let name_rva = read_u32(bytes, rva as usize + 12)?;
    read_ascii(bytes, name_rva as usize)
        .as_deref()
        .map(normalize_module)
}

fn parse_exports(base: usize, bytes: &[u8], fallback_name: Option<&str>) -> Option<ParsedExports> {
    let model = parse_memory_image(bytes).ok()?;
    let (directory_rva, directory_size) = directory(bytes, &model, EXPORT_DIRECTORY)?;
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

    let embedded =
        read_u32(bytes, directory_offset + 12).and_then(|rva| read_ascii(bytes, rva as usize));
    let module = normalize_module(
        embedded
            .as_deref()
            .or(fallback_name)
            .unwrap_or("unknown.dll"),
    );
    let mut names = HashMap::<usize, Vec<String>>::new();
    for index in 0..name_count {
        let name_rva = read_u32(bytes, names_rva.checked_add(index.checked_mul(4)?)?)?;
        let ordinal_index = read_u16(bytes, ordinals_rva.checked_add(index.checked_mul(2)?)?)?;
        let ordinal_index = usize::from(ordinal_index);
        if ordinal_index >= function_count {
            continue;
        }
        if let Some(name) = read_ascii(bytes, name_rva as usize) {
            names.entry(ordinal_index).or_default().push(name);
        }
    }

    let directory_end = directory_rva.checked_add(directory_size)?;
    let mut direct = Vec::new();
    let mut forwarders = Vec::new();
    for index in 0..function_count {
        let function_rva = read_u32(bytes, functions_rva.checked_add(index.checked_mul(4)?)?)?;
        if function_rva == 0 {
            continue;
        }
        let ordinal = ordinal_base.checked_add(u32::try_from(index).ok()?)?;
        let aliases = names
            .get(&index)
            .cloned()
            .unwrap_or_else(|| vec![String::new()]);
        for alias in aliases {
            let symbol = ResolvedExport {
                module: module.clone(),
                name: (!alias.is_empty()).then_some(alias),
                ordinal,
            };
            if function_rva >= directory_rva && function_rva < directory_end {
                if let Some(target) = read_ascii(bytes, function_rva as usize) {
                    forwarders.push(ForwardedExport {
                        source: symbol,
                        target,
                    });
                }
                continue;
            }
            if function_rva < model.image_size
                && let Some(address) = base.checked_add(function_rva as usize)
            {
                direct.push((address, symbol));
            }
        }
    }
    Some(ParsedExports { direct, forwarders })
}

fn resolve_forwarders(
    index: &mut ExportIndex,
    definitions: &HashMap<(String, ExportKey), usize>,
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
    definitions: &HashMap<(String, ExportKey), usize>,
    pending: &HashMap<(String, ExportKey), &ForwardedExport>,
) -> Option<usize> {
    let mut module = normalize_module(module).to_ascii_lowercase();
    let mut key = key.clone();
    for _hop in 0..MAX_FORWARD_DEPTH {
        let lookup = (module.clone(), key.clone());
        if let Some(address) = definitions.get(&lookup) {
            return Some(*address);
        }
        if is_api_set(&module) {
            let mut match_address = None;
            for ((_, candidate_key), address) in definitions {
                if candidate_key != &key {
                    continue;
                }
                if match_address.is_some_and(|known| known != *address) {
                    return None;
                }
                match_address = Some(*address);
            }
            if match_address.is_some() {
                return match_address;
            }
        }
        let next = pending.get(&lookup)?;
        (module, key) = parse_forward_target(&next.target)?;
        module.make_ascii_lowercase();
    }
    None
}

fn is_api_set(module: &str) -> bool {
    module.starts_with("api-") || module.starts_with("ext-")
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

fn directory(bytes: &[u8], model: &crate::pe::PeModel, index: usize) -> Option<(u32, u32)> {
    if index >= model.directory_count {
        return None;
    }
    let offset = model
        .data_directory_offset
        .checked_add(index.checked_mul(8)?)?;
    let rva = read_u32(bytes, offset)?;
    let size = read_u32(bytes, offset.checked_add(4)?)?;
    (rva != 0 && size != 0).then_some((rva, size))
}

fn checked_array(bytes: &[u8], offset: usize, count: usize, width: usize) -> Option<()> {
    let length = count.checked_mul(width)?;
    bytes.get(offset..offset.checked_add(length)?).map(|_| ())
}

fn read_ascii(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let length = tail
        .iter()
        .take(MAX_EXPORT_NAME)
        .position(|byte| *byte == 0)?;
    if length == 0 {
        return None;
    }
    let value = tail.get(..length)?;
    value
        .is_ascii()
        .then(|| String::from_utf8_lossy(value).into_owned())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use super::parse_forward_target;

    #[test]
    fn parses_named_and_ordinal_forwarders() {
        assert!(parse_forward_target("KERNELBASE.CreateFileW").is_some());
        assert!(parse_forward_target("NTDLL.#42").is_some());
        assert!(parse_forward_target("broken").is_none());
    }
}
