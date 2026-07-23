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

    let capture = match memory::capture(&target) {
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

    finish_dump(console, &output, &target, capture, entry_point)
}

fn render_target(console: &Console, target: &TargetProcess) {
    console.section("TARGET");
    console.field("Name", format_args!("{}", target.name));
    console.field("PID", format_args!("{}", target.pid.get()));
    console.field("Arch", format_args!("{}", target.architecture));
    console.field(
        "Image",
        format_args!(
            "0x{:016X} ({})",
            target.main_module.base,
            format_size(target.main_module.size)
        ),
    );
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
) -> ExitCode {
    let outcome = match dump::build(target, capture, entry_point).write(output) {
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
        console.partial(format_args!(
            "Main rebuilt: {}; DLL failures: {}",
            outcome.main_rebuilt(),
            outcome.dll_failures()
        ));
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
        console.field("Main", format_args!("{}", main.path.display()));
        console.field(
            "Layout",
            format_args!(
                "{}, {} sections, base 0x{:016X}",
                main.context.kind, main.context.sections, main.context.base
            ),
        );
    }
    console.field("DLLs", format_args!("{}", outcome.summary.dlls));
    console.field(
        "Hidden PEs",
        format_args!("{}", outcome.summary.hidden_images),
    );
    console.field("Folder", format_args!("{}", output.directory().display()));
    console.blank();
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
        format_args!("{} recovered", outcome.summary.imports_rebuilt),
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
    render_repair_warnings(console, outcome);
    render_import_warnings(console, outcome);
    render_build_failures(console, outcome);
    let unmatched_non_image = outcome
        .executable_non_image_allocations
        .saturating_sub(outcome.hidden_non_image_images);
    if unmatched_non_image > 0 {
        console.warning(format_args!(
            "{unmatched_non_image} executable non-image allocations did not contain a full PE"
        ));
    }
}

fn render_repair_warnings(console: &Console, outcome: &DumpOutcome) {
    let summary = &outcome.summary;
    if summary.unreadable_pages > 0 {
        console.warning(format_args!(
            "{} unreadable pages were zero-filled",
            summary.unreadable_pages
        ));
    }
    if summary.cleared_directories > 0 {
        console.warning(format_args!(
            "{} invalid or file-only directories were cleared",
            summary.cleared_directories
        ));
    }
    if summary.repaired_headers > 0 {
        console.warning(format_args!(
            "{} damaged PE headers were repaired",
            summary.repaired_headers
        ));
    }
    if summary.disk_header_repairs > 0 {
        console.warning(format_args!(
            "{} images used disk headers; section data came from memory",
            summary.disk_header_repairs
        ));
    }
}

fn render_import_warnings(console: &Console, outcome: &DumpOutcome) {
    let summary = &outcome.summary;
    if summary.ambiguous_imports > 0 {
        console.warning(format_args!(
            "{} ambiguous import pointers were skipped",
            summary.ambiguous_imports
        ));
    }
    if summary.invalid_unwind_entries > 0 {
        console.warning(format_args!(
            "{} invalid x64 unwind entries were removed",
            summary.invalid_unwind_entries
        ));
    }
    if outcome.export_stats.unresolved_forwarders > 0 {
        console.warning(format_args!(
            "{} forwarded exports did not match a loaded image",
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
