mod cli;
mod console;
mod dump;
mod memory;
mod output;
mod pe;
mod process;

use std::fmt::{Display, Formatter};
use std::process::ExitCode;

use cli::{Command, Request};
use console::Console;
use dump::DumpOutcome;
use output::OutputPlan;
use process::{ProcessId, TargetProcess};

pub(crate) type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AppError(String);

impl AppError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

fn main() -> ExitCode {
    let console = Console::new();
    match cli::parse(std::env::args_os()) {
        Ok(None) => {
            print!("{}", cli::HELP);
            ExitCode::SUCCESS
        }
        Ok(Some(command)) => {
            console.banner();
            process::enable_debug_privilege();
            run(&console, command)
        }
        Err(error) => {
            console.error(format_args!("{error}"));
            eprintln!("\n{}", cli::HELP);
            ExitCode::from(1)
        }
    }
}

fn run(console: &Console, request: Request) -> ExitCode {
    let Request {
        command,
        entry_point,
        raw_regions,
        only,
    } = request;
    let watched = matches!(&command, Command::Watch(_));
    let output = match output::prepare() {
        Ok(Some(plan)) => plan,
        Ok(None) => return ExitCode::from(1),
        Err(error) => {
            console.error(format_args!("{error}"));
            return ExitCode::from(1);
        }
    };
    let target = match find_target(console, command) {
        Ok(target) => target,
        Err(error) => {
            console.error(format_args!("{error}"));
            return ExitCode::from(2);
        }
    };
    render_target(console, &target);
    if watched {
        render_stability(console, &target);
    }

    let capture = match memory::capture(&target, raw_regions) {
        Ok(capture) => capture,
        Err(error) => {
            console.error(format_args!("Capture failed: {error}"));
            return ExitCode::from(2);
        }
    };
    console.section("CAPTURE");
    console.field("Method", format_args!("{}", capture.mode));
    console.field(
        "Setup",
        format_args!("{} ms", capture.setup_elapsed.as_millis()),
    );
    console.field("Images", format_args!("{}", capture.images.len()));
    if let Some(reason) = &capture.fallback_reason {
        console.warning(format_args!(
            "PSS was unavailable ({reason}); live memory may have changed"
        ));
    }
    console.blank();

    finish_dump(
        console,
        &output,
        &target,
        capture,
        entry_point,
        only.as_deref(),
    )
}

fn render_target(console: &Console, target: &TargetProcess) {
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
    if target.module_listing_denied {
        console.warning(format_args!(
            "Module enumeration was denied, so image names come from mapped files, not the loader"
        ));
    }
    console.blank();
}

fn render_stability(console: &Console, target: &TargetProcess) {
    match memory::wait_until_stable(target) {
        Ok(info) if info.settled => console.success(format_args!(
            "Memory was stable after {} ms",
            info.elapsed.as_millis()
        )),
        Ok(info) => console.warning(format_args!(
            "Memory did not settle after {} ms; using the latest state",
            info.elapsed.as_millis()
        )),
        Err(error) => console.warning(format_args!("Could not check memory stability: {error}")),
    }
}

fn finish_dump(
    console: &Console,
    output: &OutputPlan,
    target: &TargetProcess,
    capture: memory::Capture,
    entry_point: Option<pe::EntryPointRva>,
    only: Option<&str>,
) -> ExitCode {
    let outcome = match dump::build(target, capture, entry_point, only).write(output) {
        Ok(outcome) => outcome,
        Err(error) => {
            console.error(format_args!("Could not write mempe: {error}"));
            return ExitCode::from(2);
        }
    };
    render_output(console, output, &outcome);
    render_analysis(console, &outcome);
    render_warnings(console, &outcome);

    if outcome.is_complete() {
        console.done(format_args!("Analysis-ready memory images"));
        ExitCode::SUCCESS
    } else {
        match outcome.selected_images {
            Some(0) => console.partial(format_args!(
                "No captured image matched the requested name or base address"
            )),
            _ => console.partial(format_args!(
                "Main rebuilt: {}; DLL failures: {}",
                outcome.main_rebuilt, outcome.dll_failures
            )),
        }
        ExitCode::from(3)
    }
}

fn render_output(console: &Console, output: &OutputPlan, outcome: &DumpOutcome) {
    console.section("OUTPUT");
    if let Some(main) = outcome
        .artifacts
        .iter()
        .find(|artifact| artifact.context.is_main)
    {
        render_main_artifact(console, main);
    }
    console.field("DLLs", format_args!("{}", outcome.summary.dlls));
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

fn render_main_artifact(console: &Console, main: &output::WrittenFile<dump::ArtifactInfo>) {
    console.field("Main", format_args!("{}", main.path.display()));
    console.field(
        "Layout",
        format_args!(
            "{}, {} sections ({} write+execute), base 0x{:016X}",
            main.context.kind,
            main.context.sections,
            main.context.write_execute_sections,
            main.context.base
        ),
    );
    console.field(
        "Entry",
        format_args!(
            "0x{:08X} ({}{})",
            main.context.entry_point,
            main.context
                .entry_section
                .as_deref()
                .unwrap_or("outside every section"),
            unwind_note(main.context.entry_unwind_covered)
        ),
    );
    if main.context.managed {
        console.field(
            "Managed",
            format_args!(
                "CLR image; the code is IL, so a native capture reproduces the mapped file"
            ),
        );
    }
    if main.context.declared_iat_slots > 0 {
        console.field(
            "IAT",
            format_args!("{} slots declared", main.context.declared_iat_slots),
        );
    }
    if main.context.private_pages > 0 {
        console.field(
            "Runtime",
            format_args!(
                "{} of {} resident pages were written after load",
                main.context.private_pages, main.context.resident_pages
            ),
        );
        return;
    }
    console.field(
        "Runtime",
        format_args!("not measurable; re-run against a freshly started process"),
    );
}

fn unwind_note(covered: Option<bool>) -> &'static str {
    match covered {
        Some(true) => ", unwind-covered",
        Some(false) => ", no unwind entry",
        None => "",
    }
}

fn render_analysis(console: &Console, outcome: &DumpOutcome) {
    console.section("ANALYSIS");
    console.field(
        "Exports",
        format_args!(
            "{} modules, {} addresses",
            outcome.export_stats.modules, outcome.export_stats.addresses
        ),
    );
    console.field(
        "Forwarders",
        format_args!("{}", outcome.export_stats.forwarders),
    );
    console.field(
        "Imports",
        format_args!(
            "{} newly recovered across {} images",
            outcome.summary.imports_rebuilt, outcome.summary.rebuilt_images
        ),
    );
    if outcome.summary.unresolved_delay > 0 {
        console.field(
            "Delay",
            format_args!(
                "{} declared but not called yet, across {} images",
                outcome.summary.unresolved_delay, outcome.summary.rebuilt_images
            ),
        );
    }
    console.field(
        "TLS",
        format_args!(
            "{} callbacks across {} images",
            outcome.summary.tls_callbacks, outcome.summary.rebuilt_images
        ),
    );
    console.field(
        "Non-image",
        format_args!(
            "{} executable allocations",
            outcome.executable_non_image_allocations
        ),
    );
}

fn render_warnings(console: &Console, outcome: &DumpOutcome) {
    if !outcome.has_warnings() {
        return;
    }
    console.blank();
    console.section("WARNINGS");
    if outcome.main_image_missing {
        console.warning(format_args!(
            "The main image was not present in the captured address space; every other module was still dumped"
        ));
    }
    render_repair_warnings(console, outcome);
    render_import_warnings(console, outcome);
    render_build_failures(console, outcome);
    if outcome.images_skipped > 0 {
        console.warning(format_args!(
            "Images skipped for the memory budget: {}",
            outcome.images_skipped
        ));
    }
    if outcome.unscanned_non_image_bytes > 0 {
        console.warning(format_args!(
            "Non-image memory left unscanned for embedded PEs: {}",
            format_size(outcome.unscanned_non_image_bytes)
        ));
    }
    let unmatched_non_image = outcome
        .executable_non_image_allocations
        .saturating_sub(outcome.hidden_non_image_images);
    if unmatched_non_image > 0 {
        console.warning(format_args!(
            "Executable non-image allocations holding no complete PE: {unmatched_non_image}"
        ));
    }
}

fn render_repair_warnings(console: &Console, outcome: &DumpOutcome) {
    let summary = &outcome.summary;
    for (count, label) in repair_warning_counts(summary) {
        if count > 0 {
            console.warning(format_args!("{label}: {count}"));
        }
    }
    if summary.notable_cleared_directories.is_empty() {
        return;
    }
    let names = summary
        .notable_cleared_directories
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    console.warning(format_args!("Notable directories cleared: {names}"));
}

fn repair_warning_counts(summary: &dump::DumpSummary) -> [(usize, &'static str); 15] {
    [
        (
            summary.never_decrypted_sections,
            "High-entropy sections never written after loading, so mempe's copy may still be encrypted",
        ),
        (
            summary.absent_sections,
            "Executable sections that are entirely zero in the dump, so their real content was never captured",
        ),
        (
            summary.invalid_pdata_sections,
            "Sections named .pdata that hold no valid runtime-function table, so their contents are not real",
        ),
        (summary.unreadable_pages, "Unreadable pages zero-filled"),
        (
            summary.raw_region_unreadable_pages,
            "Unreadable pages zero-filled inside raw regions",
        ),
        (
            summary.path_mismatches,
            "Images mapped from a different file than the loader reports",
        ),
        (
            summary.disk_header_repairs,
            "Images rebuilt with disk headers, section data from memory",
        ),
        (summary.repaired_headers, "Damaged PE headers repaired"),
        (
            summary.unlinked_images,
            "Mapped images missing from the loader module list",
        ),
        (
            summary.fixed_image_bases,
            "Images that lost ASLR because they have no relocations",
        ),
        (
            summary.aliased_names,
            "Import names picked from several equally valid export aliases",
        ),
        (
            summary.cleared_directories,
            "Invalid or file-only directories cleared",
        ),
        (
            summary.repaired_debug_entries,
            "Debug entries repointed at the rebuilt layout",
        ),
        (
            summary.renamed_sections,
            "Unreadable section names replaced",
        ),
        (
            summary.executable_flags_added,
            "Images given a missing IMAGE_FILE_EXECUTABLE_IMAGE flag",
        ),
    ]
}

fn render_import_warnings(console: &Console, outcome: &DumpOutcome) {
    let summary = &outcome.summary;
    if summary.ambiguous_imports > 0 {
        console.warning(format_args!(
            "Ambiguous import pointers skipped: {}",
            summary.ambiguous_imports
        ));
    }
    if summary.invalid_unwind_entries > 0 {
        console.warning(format_args!(
            "Invalid x64 unwind entries removed: {}",
            summary.invalid_unwind_entries
        ));
    }
    if outcome.export_stats.unresolved_forwarders > 0 {
        console.warning(format_args!(
            "Forwarded exports with no matching image: {}",
            outcome.export_stats.unresolved_forwarders
        ));
    }
}

fn render_build_failures(console: &Console, outcome: &DumpOutcome) {
    for failure in &outcome.failures {
        console.warning(format_args!(
            "Could not rebuild {} at 0x{:016X}: {}",
            failure.name, failure.base, failure.error
        ));
    }
}

fn find_target(console: &Console, command: Command) -> AppResult<TargetProcess> {
    match command {
        Command::Pid(pid) => process::query(ProcessId::from(pid)),
        Command::Watch(name) => {
            console.section("WATCH");
            console.field("Process", format_args!("{name}"));
            console.field("Status", format_args!("Waiting for a new process"));
            console.blank();
            process::watch(&name)
        }
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
