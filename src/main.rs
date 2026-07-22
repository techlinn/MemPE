mod cli;
mod console;
mod memory;
mod output;
mod pe;
mod process;

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use cli::Command;
use console::Console;
use memory::{Capture, CapturedImage};
use output::{OutputFile, OutputPlan};
use pe::{ExportIndex, ExportStats, PeKind, RebuiltImage};
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

fn run(console: &Console, command: Command) -> ExitCode {
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

    if watched {
        match memory::wait_until_stable(&target) {
            Ok(info) if info.settled => console.success(format_args!(
                "Memory was stable after {} ms",
                info.elapsed.as_millis()
            )),
            Ok(info) => console.warning(format_args!(
                "Memory did not settle after {} ms; using the latest state",
                info.elapsed.as_millis()
            )),
            Err(error) => {
                console.warning(format_args!("Could not check memory stability: {error}"))
            }
        }
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

    finish_dump(console, &output, &target, capture)
}

struct DumpInfo {
    base: usize,
    kind: PeKind,
    sections: usize,
    unreadable_pages: usize,
    salvaged_headers: bool,
    disk_headers_used: bool,
    cleared_directories: usize,
    invalid_unwind_entries: usize,
    imports_rebuilt: usize,
    ambiguous_imports: usize,
    hidden: bool,
    is_main: bool,
}

struct BuiltFiles {
    files: Vec<OutputFile>,
    info: Vec<DumpInfo>,
    failures: Vec<BuildFailure>,
    main_rebuilt: bool,
    dll_failures: usize,
    export_stats: ExportStats,
}

struct BuildFailure {
    name: String,
    base: usize,
    error: AppError,
}

fn finish_dump(
    console: &Console,
    output: &OutputPlan,
    target: &TargetProcess,
    capture: Capture,
) -> ExitCode {
    let private_count = capture.private_executable_allocations;
    let hidden_private_images = capture.images.iter().filter(|image| image.hidden).count();
    let built = build_files(target, capture.images);
    let paths = match output.write_all(built.files) {
        Ok(paths) => paths,
        Err(error) => {
            console.error(format_args!("Could not write mempe: {error}"));
            return ExitCode::from(2);
        }
    };

    let mut total_unreadable_pages = 0usize;
    let mut total_cleared_directories = 0usize;
    let mut repaired_headers = 0usize;
    let mut disk_header_repairs = 0usize;
    let mut imports_rebuilt = 0usize;
    let mut ambiguous_imports = 0usize;
    let mut invalid_unwind_entries = 0usize;
    let mut hidden_images = 0usize;
    for info in &built.info {
        if info.unreadable_pages > 0 {
            total_unreadable_pages = total_unreadable_pages.saturating_add(info.unreadable_pages);
        }
        if info.salvaged_headers {
            repaired_headers = repaired_headers.saturating_add(1);
        }
        if info.disk_headers_used {
            disk_header_repairs = disk_header_repairs.saturating_add(1);
        }
        if info.hidden {
            hidden_images = hidden_images.saturating_add(1);
        }
        imports_rebuilt = imports_rebuilt.saturating_add(info.imports_rebuilt);
        ambiguous_imports = ambiguous_imports.saturating_add(info.ambiguous_imports);
        invalid_unwind_entries = invalid_unwind_entries.saturating_add(info.invalid_unwind_entries);
        total_cleared_directories =
            total_cleared_directories.saturating_add(info.cleared_directories);
    }

    let dll_count = built.info.iter().filter(|info| !info.is_main).count();
    let main = built.info.iter().zip(&paths).find(|(info, _)| info.is_main);
    console.section("OUTPUT");
    if let Some((info, path)) = main {
        console.field("Main", format_args!("{}", path.display()));
        console.field(
            "Layout",
            format_args!(
                "{}, {} sections, base 0x{:016X}",
                info.kind, info.sections, info.base
            ),
        );
    }
    console.field("DLLs", format_args!("{dll_count}"));
    console.field("Hidden PEs", format_args!("{hidden_images}"));
    console.field("Folder", format_args!("{}", output.directory().display()));
    console.blank();

    console.section("ANALYSIS");
    console.field(
        "Exports",
        format_args!(
            "{} modules, {} addresses",
            built.export_stats.modules, built.export_stats.addresses
        ),
    );
    console.field(
        "Forwarders",
        format_args!("{}", built.export_stats.forwarders),
    );
    console.field("Imports", format_args!("{imports_rebuilt} recovered"));
    console.field(
        "Private",
        format_args!("{private_count} executable regions"),
    );

    let has_warnings = total_unreadable_pages > 0
        || total_cleared_directories > 0
        || repaired_headers > 0
        || disk_header_repairs > 0
        || ambiguous_imports > 0
        || invalid_unwind_entries > 0
        || built.export_stats.unresolved_forwarders > 0
        || !built.failures.is_empty();
    if has_warnings {
        console.blank();
        console.section("WARNINGS");
    }
    if total_unreadable_pages > 0 {
        console.warning(format_args!(
            "{total_unreadable_pages} unreadable pages were zero-filled"
        ));
    }
    if total_cleared_directories > 0 {
        console.warning(format_args!(
            "{total_cleared_directories} invalid or file-only directories were cleared"
        ));
    }
    if repaired_headers > 0 {
        console.warning(format_args!(
            "{repaired_headers} damaged PE headers were repaired"
        ));
    }
    if disk_header_repairs > 0 {
        console.warning(format_args!(
            "{disk_header_repairs} images used disk headers; section data came from memory"
        ));
    }
    if ambiguous_imports > 0 {
        console.warning(format_args!(
            "{ambiguous_imports} ambiguous import pointers were skipped"
        ));
    }
    if invalid_unwind_entries > 0 {
        console.warning(format_args!(
            "{invalid_unwind_entries} invalid x64 unwind entries were removed"
        ));
    }
    if built.export_stats.unresolved_forwarders > 0 {
        console.warning(format_args!(
            "{} forwarded exports did not match a loaded image",
            built.export_stats.unresolved_forwarders
        ));
    }
    for failure in &built.failures {
        console.warning(format_args!(
            "Could not rebuild {} at 0x{:016X}: {}",
            failure.name, failure.base, failure.error
        ));
    }
    if private_count > hidden_private_images {
        console.warning(format_args!(
            "{} executable private regions did not contain a full PE",
            private_count.saturating_sub(hidden_private_images)
        ));
    }

    if built.main_rebuilt && built.dll_failures == 0 {
        console.done(format_args!("Analysis-ready memory images"));
        ExitCode::SUCCESS
    } else {
        console.partial(format_args!(
            "Main rebuilt: {}; DLL failures: {}",
            built.main_rebuilt, built.dll_failures
        ));
        ExitCode::from(3)
    }
}

fn build_files(target: &TargetProcess, mut images: Vec<CapturedImage>) -> BuiltFiles {
    images.sort_unstable_by_key(|image| (!image.is_main, image.base));
    for image in &mut images {
        if image.name.is_none() {
            image.name = pe::embedded_module_name(&image.bytes);
        }
    }
    let exports = ExportIndex::build(
        images
            .iter()
            .map(|image| (image.base, image.bytes.as_slice(), image.name.as_deref())),
    );
    let export_stats = exports.stats();
    let captured_bases = images.iter().map(|image| image.base).collect::<Vec<_>>();
    let mut files = Vec::with_capacity(images.len());
    let mut info = Vec::with_capacity(images.len());
    let mut failures = Vec::new();
    let mut main_rebuilt = false;
    let mut dll_failures = target
        .modules
        .iter()
        .filter(|module| {
            module.base != target.main_module.base && !captured_bases.contains(&module.base)
        })
        .count();

    for image in images {
        let known_module = image.name.is_some();
        match rebuild_image(&image, &exports) {
            Ok(rebuilt) if image.is_main || image.hidden || rebuilt.is_dll || known_module => {
                let preferred_name = output_name(target, &image, &rebuilt);
                main_rebuilt |= image.is_main;
                info.push(DumpInfo {
                    base: image.base,
                    kind: rebuilt.kind,
                    sections: rebuilt.section_count,
                    unreadable_pages: image.unreadable_pages,
                    salvaged_headers: rebuilt.salvaged_headers,
                    disk_headers_used: rebuilt.disk_headers_used,
                    cleared_directories: rebuilt.cleared_directories,
                    invalid_unwind_entries: rebuilt.invalid_unwind_entries,
                    imports_rebuilt: rebuilt.imports_rebuilt,
                    ambiguous_imports: rebuilt.ambiguous_imports,
                    hidden: image.hidden,
                    is_main: image.is_main,
                });
                files.push(OutputFile {
                    preferred_name,
                    bytes: rebuilt.bytes,
                });
            }
            Ok(_) => {}
            Err(error) if image.is_main => {
                failures.push(BuildFailure {
                    name: target.name.clone(),
                    base: image.base,
                    error,
                });
            }
            Err(error) if image.hidden => {
                failures.push(BuildFailure {
                    name: "hidden PE".to_owned(),
                    base: image.base,
                    error,
                });
            }
            Err(error) if known_module => {
                let name = image.name.as_deref().unwrap_or("unknown.dll");
                failures.push(BuildFailure {
                    name: name.to_owned(),
                    base: image.base,
                    error,
                });
                dll_failures = dll_failures.saturating_add(1);
            }
            Err(_) => {}
        }
    }

    BuiltFiles {
        files,
        info,
        failures,
        main_rebuilt,
        dll_failures,
        export_stats,
    }
}

fn rebuild_image(image: &CapturedImage, exports: &ExportIndex) -> AppResult<RebuiltImage> {
    match pe::rebuild(&image.bytes, image.base, None, exports) {
        Ok(rebuilt) => Ok(rebuilt),
        Err(memory_error) => {
            let Some(path) = &image.path else {
                return Err(memory_error);
            };
            let disk_headers = read_disk_headers(path).map_err(|disk_error| {
                AppError::new(format!(
                    "{memory_error}; could not read disk headers from {}: {disk_error}",
                    path.display()
                ))
            })?;
            pe::rebuild(&image.bytes, image.base, Some(&disk_headers), exports)
        }
    }
}

fn read_disk_headers(path: &Path) -> AppResult<Vec<u8>> {
    const MAX_DISK_HEADER_BYTES: u64 = 1024 * 1024;
    let file = File::open(path)
        .map_err(|error| AppError::new(format!("cannot open {}: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(MAX_DISK_HEADER_BYTES as usize);
    file.take(MAX_DISK_HEADER_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::new(format!("cannot read {}: {error}", path.display())))?;
    Ok(bytes)
}

fn output_name(target: &TargetProcess, image: &CapturedImage, rebuilt: &RebuiltImage) -> String {
    if image.is_main {
        return with_extension(&target.name, "exe");
    }
    let fallback = format!("module-{:016X}.dll", image.base);
    let name = image.name.as_deref().unwrap_or(&fallback);
    if rebuilt.is_dll {
        with_extension(name, "dll")
    } else {
        with_extension(name, "exe")
    }
}

fn with_extension(name: &str, extension: &str) -> String {
    let mut path = Path::new(name).to_path_buf();
    path.set_extension(extension);
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("dump.{extension}"))
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
