#[cfg(not(windows))]
compile_error!("mempe reads and starts windows processes, so it builds only for windows");

macro_rules! counters {
    ($name:ident $(($nested:ident: $kind:ident))? { $($field:ident),* $(,)? }) => {
        #[derive(Clone, Copy, Default)]
        pub(crate) struct $name {
            $(pub(crate) $nested: $kind,)?
            $(pub(crate) $field: usize,)*
        }

        impl $name {
            pub(crate) fn add(&mut self, other: &Self) {
                $(self.$nested.add(&other.$nested);)?
                $(self.$field = self.$field.saturating_add(other.$field);)*
            }
        }
    };
}

mod capture;
mod cli;
mod console;
mod dump;
mod error;
mod import_recovery;
mod launch;
mod packers;
mod pe;
mod process;
mod rebuild;
mod report;
mod unpack;

use std::process::ExitCode;
use std::time::Duration;

use cli::{Command, Request};
use console::Console;
use dump::output_folder::{self, OutputFolder};
pub(crate) use error::{AppError, AppResult, win32_status, windows_error};
use launch::Session;
use packers::LayoutBasis;
use process::{ProcessId, TargetProcess};
use report::{
    render_analysis, render_capture, render_launch, render_output, render_target, render_verdict,
    render_warnings, write_report_file,
};

#[repr(u8)]
enum Exit {
    Usage = 1,   // bad arguments, or the user said no
    Failed = 2,  // no target, no capture or nothing written
    Partial = 3, // written, but something is missing or unrestored
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit as u8)
    }
}

fn main() -> ExitCode {
    let console = Console::new();
    let code = start(&console);

    console.hold_if_alone();
    code
}

fn start(console: &Console) -> ExitCode {
    match cli::parse(std::env::args_os()) {
        Ok(None) => {
            print!("{}", cli::HELP);
            ExitCode::SUCCESS
        }
        Ok(Some(request)) => {
            console.banner();
            process::enable_debug_privilege();
            run(console, request)
        }
        Err(error) => {
            console.error(format_args!("{error}"));
            eprintln!("\n{}", cli::HELP);
            Exit::Usage.into()
        }
    }
}

fn run(console: &Console, request: Request) -> ExitCode {
    let Request {
        command,
        entry_point,
        raw_regions,
        only,
        timeout,
        folder,
    } = request;

    let watched = matches!(&command, Command::Watch(_));
    let mut output = match output_folder::prepare(folder) {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            console.warning(format_args!("Cancelled, nothing was written"));
            return Exit::Usage.into();
        }
        Err(error) => {
            console.error(format_args!("{error}"));
            return Exit::Failed.into();
        }
    };

    let (target, session) = match find_target(console, command, timeout) {
        Ok(found) => found,
        Err(error) => {
            console.error(format_args!("{error}"));
            return Exit::Failed.into();
        }
    };

    render_target(console, &target);

    let target = match watched {
        true => {
            render_stability(console, &target);
            let fresh = process::query(target.pid).ok();
            fresh
                .filter(|fresh| fresh.created == target.created)
                .unwrap_or(target)
        }
        false => target,
    };

    let capture = match capture::capture(&target, raw_regions) {
        Ok(capture) => capture,
        Err(error) => {
            console.error(format_args!("Capture failed: {error}"));
            return Exit::Failed.into();
        }
    };

    render_capture(console, &capture, session.is_some());

    finish_dump(
        console,
        &mut output,
        &target,
        capture,
        entry_point.or_else(|| session.as_ref().and_then(Session::entry_point)),
        only.as_ref(),
        session
            .as_ref()
            .is_some_and(|session| session.basis == LayoutBasis::NoPacker),
    )
}

fn render_stability(console: &Console, target: &TargetProcess) {
    match capture::wait_until_stable(target) {
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
    output: &mut OutputFolder,
    target: &TargetProcess,
    capture: capture::Capture,
    entry_point: Option<rebuild::EntryPointRva>,
    only: Option<&cli::ImageSelector>,
    stopped_without_packer: bool,
) -> ExitCode {
    let mut outcome = dump::build(target, capture, entry_point, only, output).finish();
    outcome.stopped_without_packer = stopped_without_packer;

    render_output(console, output, &outcome);
    render_analysis(console, &outcome);
    render_warnings(console, &outcome);
    render_verdict(console, &outcome);
    write_report_file(console, output, &outcome);

    match outcome.is_complete() {
        true => ExitCode::SUCCESS,
        false if outcome.artifacts.is_empty() => Exit::Failed.into(),
        false => Exit::Partial.into(),
    }
}

fn find_target(
    console: &Console,
    command: Command,
    timeout: Duration,
) -> AppResult<(TargetProcess, Option<Session>)> {
    match command {
        Command::Launch(path) => {
            let session = launch::launch(&path, timeout)?;
            render_launch(console, &path, &session);

            let target = session.target()?;
            Ok((target, Some(session)))
        }
        Command::Pid(pid) => Ok((process::query(ProcessId::from(pid))?, None)),
        Command::Watch(name) => {
            console.section("WATCH");
            console.field("Process", format_args!("{name}"));
            console.field("Status", format_args!("Waiting for a new process"));
            console.blank();

            let target = process::watch(&name, &mut |notice| {
                console.warning(format_args!("{notice}"));
            })?;
            Ok((target, None))
        }
    }
}
