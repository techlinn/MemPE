use std::path::Path;

use crate::capture::Capture;
use crate::console::{Console, LABEL_WIDTH};
use crate::dump::output_folder::{OutputFile, OutputFolder, WrittenFile};
use crate::dump::{self, DumpOutcome, DumpSummary};
use crate::launch::{Method, Reached, Session};
use crate::packers::LayoutBasis;
use crate::process::TargetProcess;
use crate::unpack::{PackerReport, State, counted};

pub(crate) fn render_launch(console: &Console, path: &Path, session: &Session) {
    console.section("LAUNCH");
    console.field("File", format_args!("{}", path.display()));

    match session.stop.reached {
        Reached::EntryPoint if session.basis == LayoutBasis::NoPacker => console.field(
            "Stopped",
            format_args!(
                "at the file's header entry point, 0x{:08X}",
                session.stop.rva
            ),
        ),
        Reached::EntryPoint => console.field(
            "Stopped",
            format_args!("at the original entry point, 0x{:08X}", session.stop.rva),
        ),
        Reached::ThroughPacker => console.field(
            "Stopped",
            format_args!(
                "in program code at 0x{:08X}, not confirmed as the original entry point; the image may not be fully unpacked",
                session.stop.rva
            ),
        ),
    }

    let method = match session.method {
        Method::Debugger => "debugger",
        Method::InjectedHandler => {
            "exception handler inside the process (the packer looks for debuggers)"
        }
    };
    console.field("Method", format_args!("{method}"));
    if session.basis == LayoutBasis::NoPacker {
        console.warning(format_args!(
            "No packer recognised, so mempe stopped at the file's own entry point; if the file is packed, that is packer code and the dump is still packed"
        ));
    }
    console.field("After", format_args!("{} ms", session.elapsed.as_millis()));
    console.blank();
}

pub(crate) fn render_target(console: &Console, target: &TargetProcess) {
    console.section("TARGET");
    console.field("Name", format_args!("{}", target.name));
    console.field("PID", format_args!("{}", target.pid.get()));
    console.field("Arch", format_args!("{}", target.architecture));

    match &target.main_module {
        Some(module) => console.field(
            "Image",
            format_args!("0x{:016X} ({})", module.base, format_size(module.size)),
        ),
        None => console.field("Image", format_args!("resolved during capture")),
    }

    if let Some(error) = &target.module_listing_error {
        console.warning(format_args!(
            "The loader's module list could not be read ({error}), so image names come from mapped files"
        ));
    }

    if target.main_module_unlisted {
        console.warning(format_args!(
            "No module in the loader list matches the target image, so the main image is found from mapped files; the target may have edited its module list"
        ));
    }

    console.blank();
}

pub(crate) fn render_capture(console: &Console, capture: &Capture, launched: bool) {
    console.section("CAPTURE");
    console.field("Method", format_args!("{}", capture.mode));
    console.field(
        "Setup",
        format_args!("{} ms", capture.setup_elapsed.as_millis()),
    );
    console.field("Images", format_args!("{}", capture.images.len()));

    if let Some(reason) = &capture.fallback_reason
        && !launched
    {
        console.warning(format_args!(
            "PSS was unavailable ({reason}); live memory may have changed"
        ));
    }

    console.blank();
}

pub(crate) fn render_verdict(console: &Console, outcome: &DumpOutcome) {
    let shortfalls = outcome.shortfalls();
    if shortfalls.is_empty() {
        console.done(format_args!("Analysis-ready memory images"));
        return;
    }

    console.partial(format_args!("{}", shortfalls.join("; ")));
}

pub(crate) fn render_output(console: &Console, output: &OutputFolder, outcome: &DumpOutcome) {
    console.section("OUTPUT");
    if let Some(main) = outcome
        .artifacts
        .iter()
        .find(|artifact| artifact.context.is_main)
    {
        render_main_artifact(console, main);
    }

    for copy in &outcome.fresh_copies {
        console.field("Fresh copy", format_args!("{}", copy.display()));
    }

    console.field("DLLs", format_args!("{}", outcome.summary.dlls));

    if outcome.summary.other_images > 0 {
        console.field(
            "Other",
            format_args!(
                "{} mapped images that are not DLLs",
                outcome.summary.other_images
            ),
        );
    }

    console.field(
        "Hidden PEs",
        format_args!("{}", outcome.summary.hidden_images),
    );
    console.field(
        "Embedded",
        format_args!("{} carved PEs", outcome.summary.embedded_pes),
    );

    if outcome.summary.raw_regions > 0 {
        console.field(
            "Regions",
            format_args!("{} written", outcome.summary.raw_regions),
        );
    }

    console.field("Folder", format_args!("{}", output.directory().display()));
    console.blank();
}

fn render_main_artifact(console: &Console, main: &WrittenFile<dump::FileReport>) {
    let rebuild = &main.context.rebuild;
    console.field("Main", format_args!("{}", main.path.display()));
    console.field(
        "Layout",
        format_args!(
            "{}, {} sections ({} write+execute in memory), base 0x{:016X}",
            main.context
                .kind
                .map(|kind| kind.to_string())
                .unwrap_or_default(),
            rebuild.sections,
            rebuild.write_execute_sections,
            main.context.base
        ),
    );
    console.field(
        "Entry",
        format_args!(
            "0x{:08X} ({}{})",
            rebuild.entry_point,
            rebuild
                .entry_section
                .as_deref()
                .unwrap_or("outside every section"),
            unwind_note(rebuild.entry_unwind_covered)
        ),
    );

    if let Some(packer) = &rebuild.packer {
        render_packer(console, packer);
    }

    if rebuild.managed {
        console.field(
            "Managed",
            format_args!(
                "CLR image; the code is IL, so a native capture reproduces the mapped file"
            ),
        );
    }

    if rebuild.declared_iat_slots > 0 {
        console.field(
            "IAT",
            format_args!("{} slots declared", rebuild.declared_iat_slots),
        );
    }

    render_page_writes(console, &main.context);
}

fn render_page_writes(console: &Console, main: &dump::FileReport) {
    if !main.pages_measured {
        console.field(
            "Runtime",
            format_args!("not measured; the image's pages could not be queried"),
        );
        return;
    }

    if main.resident_pages == 0 {
        console.field(
            "Runtime",
            format_args!(
                "not measurable; no page of the image was reported resident, or the query failed"
            ),
        );
        return;
    }

    console.field(
        "Runtime",
        format_args!(
            "{} of {} resident pages are private copies (written since mapping, the loader's own writes included)",
            main.private_pages, main.resident_pages
        ),
    );
}

fn render_packer(console: &Console, packer: &PackerReport) {
    console.field(
        "Packer",
        format_args!("{packer}, {}", restored_parts(packer)),
    );
    render_packer_gaps(console, packer);
}

fn restored_parts(packer: &PackerReport) -> String {
    let restored = packer.listed(State::Restored);
    match restored.is_empty() {
        true => "nothing restored".to_owned(),
        false => format!("restored {}", restored.join(", ")),
    }
}

fn render_packer_gaps(console: &Console, packer: &PackerReport) {
    let inferred = packer.listed(State::Inferred);
    if !inferred.is_empty() {
        console.field("Inferred", format_args!("{}", inferred.join(", ")));
    }

    let failed = packer.listed(State::Failed);
    if !failed.is_empty() {
        console.field("Unrestored", format_args!("{}", failed.join(", ")));
    }

    let lost = packer.listed(State::Lost);
    if !lost.is_empty() {
        console.field("Lost", format_args!("{}", lost.join(", ")));
    }

    for (index, note) in packer.notes.iter().enumerate() {
        let label = match index {
            0 => "Detail",
            _ => "",
        };
        console.field(label, note);
    }
}

fn unwind_note(covered: Option<bool>) -> &'static str {
    match covered {
        Some(true) => ", unwind-covered",
        Some(false) => ", no unwind entry",
        None => "",
    }
}

// the program's own images; windows' dlls go to the report file
pub(crate) fn render_analysis(console: &Console, outcome: &DumpOutcome) {
    console.section("ANALYSIS");
    render_packed_images(console, outcome);

    let program = program_summary(outcome);
    console.field(
        "Imports",
        format_args!(
            "{} newly recovered across {}",
            program.counts.imports_rebuilt,
            counted(program.rebuilt_images, "program image", "program images")
        ),
    );
    render_recovery_confidence(console, &program);

    if program.counts.imports.unresolved_delay > 0 {
        console.field(
            "Delay",
            format_args!(
                "{} declared but not called yet",
                program.counts.imports.unresolved_delay
            ),
        );
    }

    console.field(
        "TLS",
        format_args!("{} callbacks", program.counts.tls_callbacks),
    );
    console.field(
        "Non-image",
        format_args!(
            "{} executable allocations, {} holding no complete PE (--raw-regions writes those)",
            outcome.capture.executable_non_image_allocations,
            outcome.capture.unmatched_non_image()
        ),
    );
}

fn render_packed_images(console: &Console, outcome: &DumpOutcome) {
    for artifact in outcome
        .artifacts
        .iter()
        .filter(|artifact| !artifact.context.is_main)
    {
        let Some(packer) = &artifact.context.rebuild.packer else {
            continue;
        };

        let name = artifact
            .path
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default();
        console.field(
            "Packer",
            format_args!("{name}: {packer}, {}", restored_parts(packer)),
        );
        render_packer_gaps(console, packer);
    }
}

pub(crate) const REPORT_FILE: &str = "report.txt";

#[derive(Clone, Copy)]
enum Level {
    Warn, // the dump may be wrong or incomplete
    Note, // mempe repaired or noticed it, nothing to do
}

#[derive(Default)]
struct Findings {
    warnings: Vec<String>,
    notes: Vec<String>,
}

impl Findings {
    fn push(&mut self, level: Level, line: String) {
        match level {
            Level::Warn => self.warnings.push(line),
            Level::Note => self.notes.push(line),
        }
    }

    fn counts(&mut self, counts: &[(usize, Level, &str)]) {
        for (count, level, label) in counts {
            if *count > 0 {
                self.push(*level, format!("{label}: {count}"));
            }
        }
    }
}

pub(crate) fn render_warnings(console: &Console, outcome: &DumpOutcome) {
    let Findings {
        warnings,
        mut notes,
    } = findings(outcome);
    let modules = module_findings(outcome).len();
    if modules > 0 {
        notes.push(format!(
            "{modules} more findings about loaded modules no packer touched, Windows' own DLLs mostly, are in {REPORT_FILE}"
        ));
    }

    if !warnings.is_empty() {
        console.blank();
        console.section("WARNINGS");
        for line in warnings {
            console.warning(format_args!("{line}"));
        }
    }

    if !notes.is_empty() {
        console.blank();
        console.section("NOTES");
        for line in notes {
            console.note(format_args!("{line}"));
        }
    }
}

pub(crate) fn write_report_file(
    console: &Console,
    output: &mut OutputFolder,
    outcome: &DumpOutcome,
) {
    let mut text = console.transcript();
    let modules = module_summary(outcome);
    let stats = &outcome.export_stats;
    let fields = [
        (
            "Images",
            format!(
                "{} loaded modules no packer touched",
                modules.rebuilt_images
            ),
        ),
        (
            "Exports",
            format!("{} modules, {} addresses", stats.modules, stats.addresses),
        ),
        (
            "Forwarders",
            format!(
                "{}, {} with no single loaded target",
                stats.forwarders, stats.unresolved_forwarders
            ),
        ),
        (
            "Imports",
            format!("{} newly recovered", modules.counts.imports_rebuilt),
        ),
    ];

    text.push_str("\r\nLOADED MODULES\r\n");
    for (name, value) in fields {
        text.push_str(&format!("  {name:<LABEL_WIDTH$} {value}\r\n"));
    }
    for line in module_findings(outcome) {
        text.push_str(&format!("  {line}\r\n"));
    }

    let written = output.write(OutputFile {
        preferred_name: REPORT_FILE.to_string(),
        bytes: text.into_bytes(),
        context: (),
    });
    if let Err(error) = written {
        console.error(format_args!("{REPORT_FILE} was not written: {error}"));
    }
}

fn findings(outcome: &DumpOutcome) -> Findings {
    let mut findings = Findings::default();

    if outcome.capture.main_image_missing {
        findings.push(Level::Warn, "The main image was not present in the captured address space; every other module was still dumped".to_string());
    }

    for artifact in &outcome.artifacts {
        if let Some(rva) = artifact.context.rebuild.unusable_observed_entry {
            findings.push(Level::Warn, format!(
                "{}: the entry point seen at run time (0x{rva:08X}) is outside its executable sections, so the header's entry point was kept",
                artifact.path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
    }

    image_findings(&mut findings, &program_summary(outcome));

    for failure in &outcome.failures {
        findings.push(
            Level::Warn,
            format!(
                "{} at 0x{:016X} was not written: {}",
                failure.name, failure.base, failure.error
            ),
        );
    }

    if outcome.summary.resource_protection > 0 {
        findings.push(Level::Warn, "ntdll's resource lookups (LdrFindResource_U, LdrAccessResource) jump out of ntdll and the main image is VMProtect, which is how VMProtect resource protection shows; if it is active, protected resources and strings decrypt only on access, so any the program had not reached before the dump are missing here".to_string());
    }

    capture_findings(&mut findings, &outcome.capture);
    findings
}

fn program_summary(outcome: &DumpOutcome) -> DumpSummary {
    DumpSummary::from_artifacts(
        outcome
            .artifacts
            .iter()
            .filter(|artifact| !artifact.context.is_plain_module()),
    )
}

fn module_summary(outcome: &DumpOutcome) -> DumpSummary {
    DumpSummary::from_artifacts(
        outcome
            .artifacts
            .iter()
            .filter(|artifact| artifact.context.is_plain_module()),
    )
}

fn module_findings(outcome: &DumpOutcome) -> Vec<String> {
    let mut findings = Findings::default();
    image_findings(&mut findings, &module_summary(outcome));

    let Findings { warnings, notes } = findings;
    warnings
        .into_iter()
        .map(|line| format!("WARN  {line}"))
        .chain(notes.into_iter().map(|line| format!("NOTE  {line}")))
        .collect()
}

fn capture_findings(findings: &mut Findings, capture: &dump::CaptureCounts) {
    let skipped = capture.skipped;
    findings.counts(&[
        (
            skipped.over_image_cap,
            Level::Warn,
            "Images skipped past the image count limit",
        ),
        (
            skipped.oversized,
            Level::Warn,
            "Images skipped as larger than the image size limit",
        ),
        (
            skipped.over_budget,
            Level::Warn,
            "Images skipped for the memory budget",
        ),
        (
            skipped.unreadable,
            Level::Warn,
            "Images skipped because they could not be read",
        ),
        (
            capture.hidden_rejected.uncommitted,
            Level::Warn,
            "PE headers in private memory whose image is not fully committed; carved, not rebuilt",
        ),
        (
            capture.hidden_rejected.file_layout,
            Level::Warn,
            "PE files held in private memory in file layout; carved, not rebuilt",
        ),
        (
            capture.unknown_protection_images,
            Level::Note,
            "Images with pages the target made inaccessible, so their run-time permissions are unknown",
        ),
        (
            capture.unconfirmed_backing,
            Level::Warn,
            "Images whose backing file could not be confirmed",
        ),
    ]);

    if capture.raw_bytes_skipped > 0 {
        findings.push(
            Level::Warn,
            format!(
                "Raw regions left out for the raw region budget: {}",
                format_size(capture.raw_bytes_skipped)
            ),
        );
    }

    if let Some(conflict) = capture.main_base_conflict {
        findings.push(Level::Warn, format!(
            "The loader list puts the main image at 0x{:016X} but the PEB says 0x{:016X}; the loader list was used",
            conflict.loader_list, conflict.peb
        ));
    }

    if capture.unscanned_bytes > 0 {
        findings.push(
            Level::Warn,
            format!(
                "Memory left unscanned for embedded PEs, past the scan budget: {}",
                format_size(capture.unscanned_bytes)
            ),
        );
    }

    if !capture.headerless_live_code.is_empty() {
        let bases = capture
            .headerless_live_code
            .iter()
            .map(|base| format!("0x{base:016X}"))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(
            Level::Warn,
            format!("Threads began in executable memory holding no PE, so its code is not in the dump: {bases} (--raw-regions writes it)"),
        );
    }

    if capture.locked_bytes > 0 {
        findings.push(
            Level::Note,
            format!(
                "No-access memory mempe could not open to look for PEs in: {}",
                format_size(capture.locked_bytes)
            ),
        );
    }
}

fn image_findings(findings: &mut Findings, summary: &dump::DumpSummary) {
    let counts = &summary.counts;
    let imports = &counts.imports;
    findings.counts(&[
        (
            summary.partly_unpacked,
            Level::Warn,
            "Packed images mempe could not fully restore",
        ),
        (
            counts.never_decrypted_sections,
            Level::Warn,
            "Executable sections holding high-entropy pages never written after loading (an entropy heuristic), so mempe's copy may still be encrypted",
        ),
        (
            counts.absent_sections,
            Level::Warn,
            "Executable sections that are entirely zero in the process at dump time",
        ),
        (
            counts.unemitted_imports,
            Level::Warn,
            "Recovered imports left out because the rebuilt headers could not describe them",
        ),
        (
            imports.lost_import_slots,
            Level::Warn,
            "Import slots left out of the rebuilt table (unresolved table slots, refused scanned runs, lone slots, tables with no single owning DLL, or past mempe's table limit)",
        ),
        (
            imports.ambiguous_imports,
            Level::Warn,
            "Ambiguous import pointers skipped",
        ),
        (
            imports.unresolved_unknown_stub,
            Level::Warn,
            "Called pointers into their own image's code that mempe could not trace to an export",
        ),
        (
            imports.unresolved_other_module,
            Level::Warn,
            "Called pointers into another module at no export",
        ),
        (
            imports.unresolved_outside_image,
            Level::Warn,
            "Called pointers outside every captured image",
        ),
        (
            imports.unresolved_chain_exhausted,
            Level::Warn,
            "Called pointers whose thunk chain never reached an export",
        ),
        (
            imports.rival_import_tables,
            Level::Warn,
            "Images with several candidate import tables, none used",
        ),
        (
            imports.descriptor_scan_truncated,
            Level::Warn,
            "Images whose import table scan stopped early",
        ),
        (
            imports.code_scan_truncated,
            Level::Warn,
            "Images whose code reference scan stopped early",
        ),
        (
            summary.overlays_left,
            Level::Warn,
            "Images whose file has data after its last section (an overlay or a signature) that the dump does not carry",
        ),
        (summary.unreadable_pages, Level::Warn, "Unreadable pages zero-filled"),
        (
            summary.path_mismatches,
            Level::Warn,
            "Images mapped from a different file than the loader reports",
        ),
        (
            summary.unlinked_images,
            Level::Warn,
            "Mapped images missing from the loader module list",
        ),
        (
            summary.overlays_unchecked,
            Level::Note,
            "Images whose file could not be checked for an overlay",
        ),
        (
            summary.raw_region_unreadable_pages,
            Level::Note,
            "Unreadable pages zero-filled inside raw regions",
        ),
        (
            counts.invalid_pdata_sections,
            Level::Note,
            "Sections named .pdata whose contents do not parse as a runtime-function table",
        ),
        (
            summary.disk_header_repairs,
            Level::Note,
            "Images rebuilt with disk headers, section data from memory",
        ),
        (summary.repaired_headers, Level::Note, "Damaged PE headers repaired"),
        (
            summary.fixed_image_bases,
            Level::Note,
            "Images that lost ASLR because they have no relocations",
        ),
        (
            imports.aliased_names,
            Level::Note,
            "Import names picked from several equally valid export aliases",
        ),
        (
            imports.tied_module_runs,
            Level::Note,
            "Import runs several DLLs could name equally, left with per-slot names",
        ),
        (
            imports.slots_outside_data_sections,
            Level::Note,
            "Code-referenced slots holding an export address skipped because they lie outside any data section",
        ),
        (
            imports.runtime_lookup_slots,
            Level::Note,
            "Slots the program's own code writes to, treated as run-time lookups and not imports",
        ),
        (
            imports.packer_slots_skipped,
            Level::Note,
            "Code-referenced slots inside the packer's kept sections, left out as the packer's own",
        ),
        (
            imports.skipped_delay_descriptors,
            Level::Note,
            "Delay-load descriptors skipped",
        ),
        (
            imports.table_located_by_scan,
            Level::Note,
            "Images whose import table was located by scanning",
        ),
        (
            imports.unreliable_section_flags,
            Level::Note,
            "Images where every section is writable and executable, so slot classification is unreliable",
        ),
        (
            counts.invalid_unwind_entries,
            Level::Note,
            "Invalid x64 unwind entries removed",
        ),
        (
            counts.cleared_directories,
            Level::Note,
            "Invalid or file-only directories cleared",
        ),
        (
            counts.repaired_debug_entries,
            Level::Note,
            "Debug entries repointed at the rebuilt layout",
        ),
        (
            counts.renamed_sections,
            Level::Note,
            "Unreadable section names replaced",
        ),
        (
            counts.named_empty_sections,
            Level::Note,
            "Empty section names filled in",
        ),
        (
            counts.unreplaced_section_names,
            Level::Note,
            "Section names mempe could not replace",
        ),
        (
            counts.patched_section_headers,
            Level::Note,
            "Section headers corrected from run-time protections",
        ),
        (
            counts.clamped_directories,
            Level::Note,
            "Directory sizes clamped to their section",
        ),
        (
            summary.executable_flags_added,
            Level::Note,
            "Images given a missing IMAGE_FILE_EXECUTABLE_IMAGE flag",
        ),
    ]);

    if !summary.notable_cleared_directories.is_empty() {
        let names = summary
            .notable_cleared_directories
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Level::Warn, format!("Notable directories cleared: {names}"));
    }
}

fn render_recovery_confidence(console: &Console, summary: &dump::DumpSummary) {
    let counts = &summary.counts.imports;
    let tiered = counts
        .recovered_attested
        .saturating_add(counts.recovered_scanned)
        .saturating_add(counts.recovered_delayed)
        .saturating_add(counts.recovered_inferred)
        .saturating_add(counts.recovered_packer);
    if tiered == 0 {
        return;
    }

    let from_packer = match counts.recovered_packer {
        0 => String::new(),
        count => format!("{count} from packer, "),
    };

    console.field(
        "Recovered",
        format_args!(
            "{from_packer}{} attested, {} scanned, {} delay, {} inferred",
            counts.recovered_attested,
            counts.recovered_scanned,
            counts.recovered_delayed,
            counts.recovered_inferred
        ),
    );

    let tabled = counts
        .recovered_attested
        .saturating_add(counts.recovered_scanned)
        .saturating_add(counts.recovered_packer);
    if tabled > 0 {
        console.field(
            "Call sites",
            format_args!(
                "{} of {} tabled slots are referenced by code",
                counts.slots_with_call_sites, tabled
            ),
        );
    }

    if counts.mixed_module_runs > 0 {
        console.field(
            "Mixed runs",
            format_args!(
                "{} scanned runs spanned more than one module",
                counts.mixed_module_runs
            ),
        );
    }
}

fn format_size(bytes: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let bytes = bytes as f64;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}
