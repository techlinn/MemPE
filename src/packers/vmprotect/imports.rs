use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::{Range, RangeInclusive};

use iced_x86::{FlowControl, Instruction};

use super::IAT_SECTION;
use super::demutation::Payload;
use super::layout::Layout;
use crate::pe::bytes::write_pointer;
use crate::pe::exports::ExportIndex;
use crate::pe::{IAT_DIRECTORY, PeKind, PeModel};
use crate::unpack::tables::{SectionKind, append, next_section_rva};
use crate::unpack::wrapped_imports::wrapped_import;
use crate::unpack::x86::branches::{
    CALL_REL32, JUMP_REL32, REL32_LEN, direct_branches, is_near_immediate, rel32_target,
};
use crate::unpack::x86::opcodes::{
    CALL_MODRM, GROUP_FF, INDIRECT_LEN, JUMP_MODRM, MODRM_DISP32, MOV_EAX_MOFFS32, MOV_LOAD, NOP,
    POP_REG, PUSH_REG, PUSHF, REX_W,
};
use crate::unpack::x86::{self, Flow, SEEDS, StubExit, StubRunner, WrappedCall};
use crate::unpack::{NameHints, Origin, PackerImports};

const MAX_STUB_SITES: usize = 200_000;
const CRT_CONTRACT: &str = "api-ms-win-crt-";

const PUSH_OR_POP: RangeInclusive<u8> = PUSH_REG..=POP_REG + 7;
const REX: RangeInclusive<u8> = 0x40..=0x4F;
const LOAD_EAX_LEN: usize = 5;
const REX_LEN: usize = 1;
const EAX: u8 = 0;

#[derive(Clone)]
pub(super) struct Import {
    site: usize,
    len: usize,
    flow: Flow,
    target: u64,
    wrapper: bool, // read through a wrapper in vmp's virtual machine, not a stub
}

#[derive(Clone)]
enum Reading {
    Import(Import),
    NopOrJunk { call: Import, nop: Import },
    Unresolved(Why),
    Stray,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Why {
    PackerCode,
    SmallSection,
    Budget,
    Unmodelled,
    NotAnExport,
    NoReading,
    Mixed,
    Conflict,
    Overlap,
    Stray,
}

impl Why {
    fn describe(self) -> &'static str {
        match self {
            Self::PackerCode => "into the packer's sections outside its stub section",
            Self::SmallSection => {
                "into the executable section before the packer's, too small to be taken for its stubs"
            }
            Self::Budget => "the emulator ran out of steps on",
            Self::Unmodelled => "the emulator could not follow",
            Self::NotAnExport => "leading to an address no captured module exports",
            Self::NoReading => "with no reading that ends as a stub does",
            Self::Mixed => "that failed differently from each start tried",
            Self::Conflict => "with two readings that cannot both be right",
            Self::Overlap => "sharing bytes with another site",
            Self::Stray => "the emulator left at once, could not decode, or followed nowhere",
        }
    }
}

#[derive(Default)]
pub(super) struct Unresolved {
    counts: BTreeMap<Why, usize>,
    truncated: bool,
}

impl Unresolved {
    fn add(&mut self, why: Why, count: usize) {
        if count > 0 {
            *self.counts.entry(why).or_default() += count;
        }
    }

    pub(super) fn total(&self) -> usize {
        self.counts.values().sum()
    }

    pub(super) fn enters_packer_code(&self) -> bool {
        self.counts.contains_key(&Why::PackerCode)
    }

    pub(super) fn describe(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .counts
            .iter()
            .map(|(why, count)| format!("{count} calls and jumps {}", why.describe()))
            .collect();
        if self.truncated {
            lines.push(format!("only the first {MAX_STUB_SITES} sites were read"));
        }
        lines
    }
}

pub(super) struct Found {
    pub(super) resolved: Vec<Import>,
    pub(super) virtualized: Vec<u64>, // apis only virtualized code calls: no site to patch
    pub(super) vm_entries: BTreeSet<usize>,
    linked: HashSet<String>,
    pub(super) unresolved: Unresolved,
    pub(super) sites: usize, // decoded branches into the stub section
    pub(super) placed_by_branches: usize,
}

pub(super) fn is_stub(bytes: &[u8], origin: &Origin<'_>, bits: u32, site: usize) -> bool {
    matches!(
        read_site(bytes, origin, bits, site),
        Reading::Import(_) | Reading::NopOrJunk { .. } | Reading::Unresolved(Why::Conflict)
    )
}

pub(super) fn site_exit(bytes: &[u8], origin: &Origin<'_>, bits: u32, at: usize) -> StubExit {
    let exit = agreed_exit(
        candidate_starts(bytes, at, bits)
            .into_iter()
            .map(|start| exit_from(bytes, origin, bits, start, at)),
    );
    if exit != StubExit::Unknown {
        return exit;
    }

    let back = (origin.base + at + REL32_LEN) as u64; // a wrapper returns where a call does
    match wrapper_called(bytes, origin, bits, at) {
        Some(_) => StubExit::Returns(back),
        None => StubExit::Unknown,
    }
}

// vmp's resource protection swaps an import's stub for a wrapper run in its virtual machine; the
// wrapper hands the call on to the api it stands for
fn wrapper_called(bytes: &[u8], origin: &Origin<'_>, bits: u32, at: usize) -> Option<WrappedCall> {
    (bytes.get(at) == Some(&CALL_REL32)).then_some(())?;
    let base = origin.base as u64;
    let runner = StubRunner {
        image: bytes,
        base,
        bits,
        memory: origin.memory,
    };
    let wrapper = base + rel32_target(bytes, at)? as u64;
    runner.wrapped_call(wrapper, base + (at + REL32_LEN) as u64)
}

fn agreed_exit(exits: impl Iterator<Item = StubExit>) -> StubExit {
    let mut known = exits.filter(|exit| *exit != StubExit::Unknown);
    let Some(first) = known.next() else {
        return StubExit::Unknown;
    };

    match known.all(|other| other == first) {
        true => first,
        false => StubExit::Unknown,
    }
}

fn exit_from(bytes: &[u8], origin: &Origin<'_>, bits: u32, start: usize, at: usize) -> StubExit {
    let base = origin.base as u64;
    let (start, site) = (base + start as u64, base + at as u64);
    x86::stub_exit(bytes, base, bits, start, site, Some(origin.memory))
}

fn unresolved_reason(failure: x86::Failure) -> Option<Why> {
    match failure {
        x86::Failure::Coincidence => None,
        x86::Failure::Budget => Some(Why::Budget),
        x86::Failure::Unmodelled => Some(Why::Unmodelled),
        x86::Failure::Mismatch => Some(Why::NoReading),
    }
}

pub(super) fn resolve(
    bytes: &[u8],
    bits: u32,
    layout: &Layout,
    code: &[Range<usize>],
    payload: &Payload<'_>,
    origin: &Origin<'_>,
    mut linked: HashSet<String>,
) -> Found {
    let stubs = layout.stubs.clone().unwrap_or(layout.block.clone()); // stubs only, never mempe's sections
    let base = origin.base as u64;
    let mut unresolved = Unresolved::default();

    let readings = RefCell::new(HashMap::<usize, Reading>::new());
    let reading = |at: usize| -> Reading {
        if let Some(known) = readings.borrow().get(&at) {
            return known.clone();
        }
        let fresh = read_site(bytes, origin, bits, at);
        readings.borrow_mut().insert(at, fresh.clone());
        fresh
    };
    // code goes on past vmp's spare byte, never at it: read as an instruction, that byte can swallow
    // the next site's call and become a site of its own
    let after_stub = |insn: &Instruction| {
        let site = usize::try_from(insn.ip().checked_sub(base)?).ok()?;
        let target = usize::try_from(insn.near_branch_target().checked_sub(base)?).ok()?;
        let branch = matches!(
            insn.flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::Call
        );
        let into_stub = branch
            && is_near_immediate(insn)
            && stubs.contains(&target)
            && readings.borrow().len() < MAX_STUB_SITES;

        match into_stub.then(|| reading(site))? {
            Reading::Import(import) => Some(base + (import.site + import.len) as u64),
            _ => None,
        }
    };
    let resume = |insn: &Instruction| payload.resume_after(insn).or_else(|| after_stub(insn));

    let branches = direct_branches(bytes, base, bits, code, &resume);
    let targets: HashSet<usize> = branches.iter().map(|branch| branch.target).collect();
    let mut placed = HashSet::new();
    let mut by_landing = |call: &Import, nop: &Import| {
        let site = choose_by_landing(call, nop, &targets);
        placed.extend(site.as_ref().map(|site| site.site));
        site
    };

    let mut decoded = Vec::new();
    let mut read = HashSet::new();
    let mut vm_entries = BTreeSet::new();
    let mut sites = 0;
    for branch in branches {
        if !stubs.contains(&branch.target) {
            let into_vm = layout.block.contains(&branch.target);
            if into_vm {
                vm_entries.insert(branch.target);
            }
            let undersized = layout.undersized.as_ref().is_some_and(|section| {
                section.contains(&branch.target) && !section.contains(&branch.site)
            });
            unresolved.add(Why::PackerCode, usize::from(into_vm));
            unresolved.add(Why::SmallSection, usize::from(undersized));
            continue;
        }
        if sites >= MAX_STUB_SITES {
            unresolved.truncated = true;
            break;
        }

        sites += 1;
        read.insert(branch.site);
        match reading(branch.site) {
            Reading::Import(site) => decoded.push(site),
            Reading::NopOrJunk { call, nop } => match by_landing(&call, &nop) {
                Some(site) => decoded.push(site),
                None => unresolved.add(Why::Conflict, 1),
            },
            Reading::Unresolved(why) => unresolved.add(why, 1),
            Reading::Stray => unresolved.add(Why::Stray, 1),
        }
    }
    let decoded_sites = sites;
    let mut kept = drop_overlaps(decoded, &mut unresolved);

    let missed = code
        .iter()
        .flat_map(|range| range.clone())
        .filter(|at| matches!(bytes.get(*at), Some(&CALL_REL32 | &JUMP_REL32)))
        .filter(|at| !read.contains(at))
        .filter(|at| rel32_target(bytes, *at).is_some_and(|target| stubs.contains(&target))); // decode desync after a stub's junk byte
    let mut recovered = Vec::new();
    for at in missed {
        if sites >= MAX_STUB_SITES {
            unresolved.truncated = true;
            break;
        }

        sites += 1;
        match read_site(bytes, origin, bits, at) {
            Reading::Import(site) if !overlaps_any(&site, &kept) => recovered.push(site),
            Reading::NopOrJunk { call, nop } => match by_landing(&call, &nop) {
                Some(site) if !overlaps_any(&site, &kept) => recovered.push(site),
                Some(_) => {}
                None => unresolved.add(Why::Conflict, 1),
            },
            Reading::Import(_) | Reading::Stray => {} // undecoded bytes: a chance match is no site
            Reading::Unresolved(why) => unresolved.add(why, 1),
        }
    }

    kept.extend(drop_overlaps(recovered, &mut unresolved));
    kept.sort_by_key(|site| site.site);

    linked.extend(
        kept.iter()
            .filter(|site| !site.wrapper)
            .filter_map(|site| module_of(origin, site.target)),
    );

    let before = kept.len();
    let kept: Vec<Import> = kept
        .into_iter()
        .filter(|site| !site.wrapper || from_linked(origin, &linked, site.target))
        .collect();
    unresolved.add(Why::NotAnExport, before - kept.len());

    Found {
        placed_by_branches: kept
            .iter()
            .filter(|site| placed.contains(&site.site))
            .count(),
        resolved: kept,
        virtualized: Vec::new(),
        vm_entries,
        linked,
        unresolved,
        sites: decoded_sites,
    }
}

pub(super) fn virtualized_calls<'a>(
    bytes: &[u8],
    bits: u32,
    layout: &Layout,
    origin: &Origin<'_>,
    found: &Found,
    entries: impl Iterator<Item = &'a usize>,
) -> Vec<u64> {
    let base = origin.base as u64;
    let runner = StubRunner {
        image: bytes,
        base,
        bits,
        memory: origin.memory,
    };
    let packer = base + layout.block.start as u64..base + layout.block.end as u64;
    let called: BTreeSet<u64> = entries
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|entry| runner.virtualized_calls(base + *entry as u64, &packer))
        .flatten()
        .collect();

    let stubbed: HashSet<u64> = found.resolved.iter().map(|site| site.target).collect();
    called
        .into_iter()
        .filter(|api| !stubbed.contains(api) && from_linked(origin, &found.linked, *api))
        .collect()
}

fn from_linked(origin: &Origin<'_>, linked: &HashSet<String>, api: u64) -> bool {
    module_of(origin, api).is_some_and(|module| linked.contains(&module))
}

fn module_of(origin: &Origin<'_>, api: u64) -> Option<String> {
    origin
        .exports
        .resolve(usize::try_from(api).ok()?)
        .map(|resolved| resolved.symbol.module.to_ascii_lowercase())
}

fn overlaps_any(site: &Import, sites: &[Import]) -> bool {
    let range = site.site..site.site + site.len;
    sites
        .iter()
        .any(|other| other.site < range.end && range.start < other.site + other.len)
}

pub(super) fn rebuild(
    restored: &mut Vec<u8>,
    model: &PeModel,
    found: &Found,
    msvc: bool,
    origin: &Origin<'_>,
) -> Option<PackerImports> {
    let sites = &found.resolved;
    let targets: Vec<u64> = sites
        .iter()
        .map(|site| site.target)
        .chain(found.virtualized.iter().copied())
        .collect();
    (!targets.is_empty()).then_some(())?;

    let base = origin.base;
    let width = model.kind.pointer_width();
    let table = table_layout(&targets, msvc, origin.exports);

    let iat_size = table.slots.len().checked_mul(width)?;
    let mut slots = vec![0u8; iat_size];
    for (index, target) in table.slots.iter().enumerate() {
        if let Some(target) = target {
            write_pointer(&mut slots, index * width, model.kind, *target).ok()?;
        }
    }

    let image_len = restored.len();
    let patches_for = |iat_rva: usize| -> Option<Vec<(Range<usize>, Vec<u8>)>> {
        sites
            .iter()
            .map(|site| {
                let slot_rva = iat_rva + table.slot_of.get(&site.target)? * width;
                let end = site.site.checked_add(site.len)?;
                let disp = match model.kind {
                    PeKind::Pe32Plus => i32::try_from(slot_rva as i64 - end as i64).ok()?, // rip relative vs absolute
                    PeKind::Pe32 => {
                        i32::from_ne_bytes(u32::try_from(base + slot_rva).ok()?.to_ne_bytes())
                    }
                };

                let encoded = encode(site.flow, site.len, model.kind, disp);
                (encoded.len() == site.len && end <= image_len).then_some((site.site..end, encoded))
            })
            .collect()
    };

    patches_for(next_section_rva(restored, model)?)?;
    let iat_rva = append(restored, model, IAT_SECTION, SectionKind::Data, &slots)?;
    for (range, encoded) in patches_for(iat_rva)? {
        restored[range].copy_from_slice(&encoded); // append only grows the image
    }

    let rva = u32::try_from(iat_rva).ok()?;
    let size = u32::try_from(iat_size).ok()?;
    if model.directory_offset(IAT_DIRECTORY).is_some() {
        model.set_directory(restored, IAT_DIRECTORY, iat_rva, iat_size)?;
    }

    Some(PackerImports::FilledIat {
        rva,
        size,
        names: NameHints::new(),
    })
}

struct Table {
    slots: Vec<Option<u64>>, // None ends one module's run
    slot_of: HashMap<u64, usize>,
}

// msvc links the ucrt through ucrt.lib, whose import records name the api-ms-win-crt contracts
fn table_layout(targets: &[u64], msvc: bool, exports: &ExportIndex) -> Table {
    let contract = |target: u64| {
        let mut contracts = exports
            .modules_at(target as usize)
            .map(|(module, _)| module.to_ascii_lowercase())
            .filter(|module| module.starts_with(CRT_CONTRACT));
        let first = contracts.next()?;
        contracts.all(|other| other == first).then_some(first)
    };
    let module = |target: u64| {
        msvc.then(|| contract(target)).flatten().or_else(|| {
            exports
                .resolve(target as usize)
                .map(|resolved| resolved.symbol.module.to_ascii_lowercase())
        })
    };
    let mut targets: Vec<(Option<String>, u64)> = targets
        .iter()
        .map(|target| (module(*target), *target))
        .collect();
    targets.sort_unstable();
    targets.dedup();

    let mut table = Table {
        slots: Vec::new(),
        slot_of: HashMap::new(),
    };
    let mut previous: Option<Option<String>> = None;
    for (module, target) in targets {
        if previous
            .as_ref()
            .is_some_and(|previous| *previous != module)
        {
            table.slots.push(None);
        }

        table.slot_of.insert(target, table.slots.len());
        table.slots.push(Some(target));
        previous = Some(module);
    }
    table
}

fn read_site(bytes: &[u8], origin: &Origin<'_>, bits: u32, at: usize) -> Reading {
    let readings: Vec<_> = candidate_starts(bytes, at, bits)
        .into_iter()
        .map(|start| place(bytes, origin, bits, start, at))
        .collect();
    let no_stub = readings.iter().all(Result::is_err);
    if let Some(site) = no_stub
        .then(|| wrapper_site(bytes, origin, bits, at))
        .flatten()
    {
        return Reading::Import(site); // no start reads as a stub: a wrapper in the vm
    }

    match choose(readings.iter().cloned()) {
        Reading::Unresolved(Why::Conflict) => {
            nop_or_junk(bytes, &readings).unwrap_or(Reading::Unresolved(Why::Conflict))
        }
        reading => reading,
    }
}

// a jump stub never returns, so only the code around it says whether vmp's spare byte is the nop in front or the byte after
fn nop_or_junk(bytes: &[u8], readings: &[Result<Import, Option<Why>>]) -> Option<Reading> {
    let [call, nop] = readings
        .iter()
        .filter_map(|reading| reading.as_ref().ok())
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    let same = call.target == nop.target && call.flow == Flow::Jump && nop.flow == Flow::Jump;
    let nop_in_front =
        nop.site.checked_add(1) == Some(call.site) && bytes.get(nop.site) == Some(&NOP);

    (same && nop_in_front).then(|| Reading::NopOrJunk {
        call: call.clone(),
        nop: nop.clone(),
    })
}

fn choose_by_landing(call: &Import, nop: &Import, targets: &HashSet<usize>) -> Option<Import> {
    let after = call.site + REL32_LEN; // past an unconditional jump only a branch reaches code
    match (targets.contains(&after), targets.contains(&call.site)) {
        (false, _) => Some(call.clone()),
        (true, false) => Some(nop.clone()),
        (true, true) => None,
    }
}

fn choose(readings: impl Iterator<Item = Result<Import, Option<Why>>>) -> Reading {
    let mut chosen: Option<Import> = None;
    let mut conflict = false;
    let mut refusals = BTreeSet::new();

    for reading in readings {
        let site = match reading {
            Ok(site) => site,
            Err(why) => {
                refusals.extend(why);
                continue;
            }
        };

        let against = chosen.as_ref().map(|kept| {
            let same = kept.target == site.target && kept.flow == site.flow;
            (same, site.len.cmp(&kept.len))
        });
        match against {
            None | Some((true, Ordering::Less)) => chosen = Some(site), // shorter reading wins
            Some((true, Ordering::Greater)) => {}
            Some(_) => conflict = true, // same length from two starts: either byte may be the junk one
        }
    }

    let mut reasons = refusals.into_iter();
    match (chosen, conflict) {
        (Some(site), false) => Reading::Import(site),
        (Some(_), true) => Reading::Unresolved(Why::Conflict),
        (None, _) => match (reasons.next(), reasons.next()) {
            (None, _) => Reading::Stray,
            (Some(only), None) => Reading::Unresolved(only),
            (Some(_), Some(_)) => Reading::Unresolved(Why::Mixed),
        },
    }
}

fn candidate_starts(bytes: &[u8], at: usize, bits: u32) -> Vec<usize> {
    let before = |back: usize| {
        at.checked_sub(back)
            .and_then(|position| bytes.get(position))
            .copied()
    };
    let neutral = |byte: u8| PUSH_OR_POP.contains(&byte) || byte == PUSHF || byte == NOP;

    let mut starts = vec![at];
    if before(1).is_some_and(neutral) {
        starts.push(at - 1); // neutral byte before call
        if bits == 64 && before(2).is_some_and(|byte| REX.contains(&byte)) {
            starts.push(at - 2);
        }
    }
    starts
}

fn place(
    bytes: &[u8],
    origin: &Origin<'_>,
    bits: u32,
    start: usize,
    at: usize,
) -> Result<Import, Option<Why>> {
    let base = origin.base as u64;
    let address = |offset: usize| base + offset as u64;
    let resolve = |seed| {
        x86::resolve(
            bytes,
            base,
            bits,
            address(start),
            address(at),
            seed,
            Some(origin.memory),
        )
        .map_err(unresolved_reason)
    };
    let first = resolve(SEEDS[0])?;
    let others = SEEDS[1..]
        .iter()
        .map(|seed| resolve(*seed))
        .collect::<Result<Vec<_>, _>>()?;

    let target = usize::try_from(first.target).map_err(|_| None)?;
    if origin.exports.resolve(target).is_none() {
        return Err(Some(Why::NotAnExport));
    }
    let agree = others.iter().all(|other| {
        first.target == other.target && first.flow == other.flow && first.end == other.end
    });
    if !agree {
        return Err(Some(Why::NoReading));
    }

    let len = match first.end {
        Some(end) => end
            .checked_sub(address(start))
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Some(Why::NoReading))?,
        None => (at - start + REL32_LEN).max(INDIRECT_LEN), // jump stub, no return address
    };
    if !fits(first.flow, len, bits) || start + len > bytes.len() {
        return Err(Some(Why::NoReading));
    }

    Ok(Import {
        site: start,
        len,
        flow: first.flow,
        target: first.target,
        wrapper: false,
    })
}

// the cleaned copy pads a wrapper's call with a nop, room for the call through a slot
fn wrapper_site(bytes: &[u8], origin: &Origin<'_>, bits: u32, at: usize) -> Option<Import> {
    let padded = bytes.get(at + REL32_LEN) == Some(&NOP);
    padded.then_some(())?;
    let wrapped = wrapper_called(bytes, origin, bits, at)?;

    Some(Import {
        site: at,
        len: REL32_LEN + 1,
        flow: Flow::Call,
        target: wrapped_import(origin.exports, origin.memory, bits, &wrapped)?,
        wrapper: true,
    })
}

fn fits(flow: Flow, len: usize, bits: u32) -> bool {
    let wide = bits == 64;
    match flow {
        Flow::Call | Flow::Jump => len == INDIRECT_LEN || (wide && len == INDIRECT_LEN + REX_LEN), // optional rex.w
        Flow::Load(_) if wide => len == INDIRECT_LEN + REX_LEN,
        Flow::Load(reg) => len == INDIRECT_LEN || (len == LOAD_EAX_LEN && reg.number() == EAX),
    }
}

fn drop_overlaps(mut sites: Vec<Import>, unresolved: &mut Unresolved) -> Vec<Import> {
    sites.sort_by_key(|site| site.site);

    let mut clash = vec![false; sites.len()];
    let mut reach: Option<(usize, usize)> = None;
    for (index, site) in sites.iter().enumerate() {
        if let Some((end, owner)) = reach
            && site.site < end
        {
            clash[index] = true;
            clash[owner] = true; // overlap drops both
        }

        let end = site.site + site.len;
        if reach.is_none_or(|(furthest, _)| end > furthest) {
            reach = Some((end, index));
        }
    }

    let before = sites.len();
    let kept: Vec<Import> = sites
        .into_iter()
        .zip(clash)
        .filter_map(|(site, clashed)| (!clashed).then_some(site))
        .collect();
    unresolved.add(Why::Overlap, before - kept.len());
    kept
}

fn encode(flow: Flow, len: usize, kind: PeKind, disp: i32) -> Vec<u8> {
    let mut bytes = match flow {
        Flow::Call | Flow::Jump => {
            let modrm = match flow {
                Flow::Call => CALL_MODRM,
                _ => JUMP_MODRM,
            };
            match len == INDIRECT_LEN + REX_LEN {
                true => vec![REX_W, GROUP_FF, modrm],
                false => vec![GROUP_FF, modrm],
            }
        }
        Flow::Load(reg) if kind == PeKind::Pe32Plus => {
            let reg = reg.number();
            let extended = (reg >> 3) << 2; // rex.r
            vec![REX_W | extended, MOV_LOAD, ((reg & 7) << 3) | MODRM_DISP32]
        }
        Flow::Load(_) if len == LOAD_EAX_LEN => vec![MOV_EAX_MOFFS32],
        Flow::Load(reg) => vec![MOV_LOAD, (reg.number() << 3) | MODRM_DISP32],
    };
    bytes.extend_from_slice(&disp.to_le_bytes());
    bytes
}
