use std::ffi::OsString;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::rebuild::EntryPointRva;
use crate::{AppError, AppResult};

const IMAGE_ALIGNMENT: usize = 0x10000; // windows maps images on allocation granularity
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60); // vmp's virtual machine can take half a minute to start

pub const HELP: &str = "mempe - Windows PE memory dumper and rebuilder\n\n\
Usage:\n\
  mempe.exe <file> [--timeout <seconds>] [-e|--entry-point <RVA>] [--raw-regions] [--only <name>]\n\
  mempe.exe -p <PID> [-e|--entry-point <RVA>] [--raw-regions] [--only <name>]\n\
  mempe.exe -w <program.exe> [-e|--entry-point <RVA>] [--raw-regions] [--only <name>]\n\
  any of them takes -o|--output <folder>\n\
  mempe.exe -h\n\n\
<file> starts an exe or a dll (inside rundll32) under mempe, lets its packer\n\
unpack it, and dumps it before the program's own code runs. The packer's\n\
code does run, so use a virtual machine for files you do not trust.\n\
--timeout ends the attempt when the program's code is not reached in that\n\
many seconds (60 by default).\n\
-w waits up to 24 hours for a new matching process. Press Ctrl+C to stop.\n\
--raw-regions also writes the untouched bytes of executable non-image\n\
allocations that held no full PE. Off by default; it can add many files.\n\
--only writes just the images matching a module name, with or without its\n\
extension, or a hex base address. Every image is still captured and indexed,\n\
so imports resolve the same as in a full dump. --raw-regions still writes its\n\
regions with --only.\n\
-e takes the entry point as a hex RVA, with or without 0x: 1A90 and 0x1A90 match.\n\n\
Output goes to a folder named mempe inside the folder you run mempe from,\n\
or to the folder -o names. report.txt there holds the whole report, the\n\
findings about loaded DLLs the console leaves out included.\n\
Exit codes: 0 done, 1 bad arguments or cancelled, 2 failed, 3 written but\n\
incomplete; the last line says what is missing.\n";

pub enum ImageSelector {
    Base(usize),
    Name(String),
}

impl ImageSelector {
    fn parse(text: String) -> AppResult<Self> {
        if let Some(hex) = strip_hex(&text) {
            return usize::from_str_radix(hex, 16)
                .map(Self::Base)
                .map_err(|_| AppError::new("--only base address is not a hex number"));
        }

        match usize::from_str_radix(&text, 16) {
            Ok(base) if base != 0 && base.is_multiple_of(IMAGE_ALIGNMENT) => Ok(Self::Base(base)),
            _ => Ok(Self::Name(text)),
        }
    }

    pub fn matches(&self, base: usize, name: Option<&str>) -> bool {
        let named = |wanted: &str, name: &str| {
            let stem = Path::new(name).file_stem().and_then(|stem| stem.to_str());
            name.eq_ignore_ascii_case(wanted)
                || stem.is_some_and(|stem| stem.eq_ignore_ascii_case(wanted))
        };

        match self {
            Self::Base(wanted) => *wanted == base,
            Self::Name(wanted) => name.is_some_and(|name| named(wanted, name)),
        }
    }
}

pub struct Request {
    pub command: Command,
    pub entry_point: Option<EntryPointRva>,
    pub raw_regions: bool,
    pub only: Option<ImageSelector>,
    pub timeout: Duration,
    pub folder: Option<PathBuf>,
}

pub enum Command {
    Launch(PathBuf),
    Pid(NonZeroU32),
    Watch(String),
}

pub fn parse<I>(args: I) -> AppResult<Option<Request>>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(None);
    }
    move_command_first(&mut args);

    let mut args = args.into_iter();
    let option = args
        .next()
        .ok_or_else(|| AppError::new("missing a file, -p, -w, or -h"))?;

    let command = if !option.to_string_lossy().starts_with('-') {
        parse_file(option).map(Command::Launch)?
    } else if option == "-p" || option == "-w" {
        let value = args
            .next()
            .ok_or_else(|| AppError::new(format!("{} needs a value", option.to_string_lossy())))?;

        if option == "-p" {
            parse_pid(value).map(Command::Pid)?
        } else {
            parse_watch_name(value).map(Command::Watch)?
        }
    } else {
        return Err(AppError::new(format!(
            "unknown option: {}",
            option.to_string_lossy()
        )));
    };

    let options = parse_trailing_options(&mut args)?;
    if options.timeout.is_some() && !matches!(command, Command::Launch(_)) {
        return Err(AppError::new(
            "--timeout only applies when mempe starts the file itself",
        ));
    }

    Ok(Some(Request {
        command,
        entry_point: options.entry_point,
        raw_regions: options.raw_regions,
        only: options.only,
        timeout: options.timeout.unwrap_or(DEFAULT_TIMEOUT),
        folder: options.folder,
    }))
}

fn move_command_first(args: &mut [OsString]) {
    const TAKES_VALUE: [&str; 6] = [
        "--timeout",
        "-e",
        "--entry-point",
        "--only",
        "-o",
        "--output",
    ];

    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if TAKES_VALUE.iter().any(|option| arg == *option) {
            index += 2;
            continue;
        }

        let length = match arg.to_string_lossy().as_ref() {
            "-p" | "-w" => 2,
            text if !text.starts_with('-') => 1,
            _ => {
                index += 1;
                continue;
            }
        };
        let end = (index + length).min(args.len());
        args[..end].rotate_right(end - index);
        return;
    }
}

fn parse_file(value: OsString) -> AppResult<PathBuf> {
    let path = std::path::absolute(&value)
        .map_err(|error| AppError::new(format!("cannot use {value:?} as a path: {error}")))?;

    if !path.is_file() {
        return Err(AppError::new(format!("no such file: {}", path.display())));
    }

    Ok(path)
}

fn parse_pid(value: OsString) -> AppResult<NonZeroU32> {
    let text = value
        .into_string()
        .map_err(|_| AppError::new("PID must use valid text"))?;
    let parsed = parse_u32(&text).map_err(|_| AppError::new(format!("invalid PID: {text:?}")))?;

    NonZeroU32::new(parsed).ok_or_else(|| AppError::new("PID must be greater than zero"))
}

fn parse_watch_name(value: OsString) -> AppResult<String> {
    let mut name = value
        .into_string()
        .map_err(|_| AppError::new("process name must use valid text"))?;
    if name.is_empty() {
        return Err(AppError::new("process name cannot be empty"));
    }

    if name.contains(['\\', '/']) {
        return Err(AppError::new("-w takes a file name, not a path"));
    }
    if Path::new(&name).extension().is_none() {
        name.push_str(".exe"); // a bare name never matches
    }

    Ok(name)
}

#[derive(Default)]
struct Options {
    entry_point: Option<EntryPointRva>,
    raw_regions: bool,
    only: Option<ImageSelector>,
    timeout: Option<Duration>,
    folder: Option<PathBuf>,
}

fn parse_trailing_options(args: &mut impl Iterator<Item = OsString>) -> AppResult<Options> {
    let mut options = Options::default();

    while let Some(option) = args.next() {
        match option.to_str().unwrap_or_default() {
            "--raw-regions" if options.raw_regions => {
                return Err(AppError::new("--raw-regions was given twice"));
            }
            "--raw-regions" => options.raw_regions = true,
            "--only" => {
                once(&options.only, "--only")?;
                let name = args
                    .next()
                    .ok_or_else(|| AppError::new("--only needs a module name or base address"))?
                    .into_string()
                    .map_err(|_| AppError::new("--only value is not valid Unicode"))?;
                if name.is_empty() {
                    return Err(AppError::new("--only value cannot be empty"));
                }

                options.only = Some(ImageSelector::parse(name)?);
            }
            "-o" | "--output" => {
                once(&options.folder, "--output")?;
                let value = args
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| AppError::new("--output needs a folder"))?;
                let folder = std::path::absolute(&value).map_err(|error| {
                    AppError::new(format!("cannot use {value:?} as a folder: {error}"))
                })?;

                options.folder = Some(folder);
            }
            "--timeout" => {
                once(&options.timeout, "--timeout")?;
                let value = args
                    .next()
                    .ok_or_else(|| AppError::new("--timeout needs a number of seconds"))?;

                options.timeout = Some(parse_timeout(value)?);
            }
            "-e" | "--entry-point" => {
                once(&options.entry_point, "--entry-point")?;
                let value = args
                    .next()
                    .ok_or_else(|| AppError::new("--entry-point needs an RVA"))?;

                options.entry_point = Some(parse_entry_point(value)?);
            }
            _ => {
                return Err(AppError::new(format!(
                    "unknown option: {}",
                    option.to_string_lossy()
                )));
            }
        }
    }

    Ok(options)
}

fn once<T>(slot: &Option<T>, option: &str) -> AppResult<()> {
    match slot {
        Some(_) => Err(AppError::new(format!("{option} was given twice"))),
        None => Ok(()),
    }
}

fn parse_entry_point(value: OsString) -> AppResult<EntryPointRva> {
    let text = value
        .into_string()
        .map_err(|_| AppError::new("entry-point RVA must use valid text"))?;
    let hex = strip_hex(&text).unwrap_or(&text); // rvas are read and written in hex everywhere
    let parsed = u32::from_str_radix(hex, 16)
        .map_err(|_| AppError::new(format!("invalid entry-point RVA: {text:?}")))?;
    EntryPointRva::new(parsed)
        .ok_or_else(|| AppError::new("entry-point RVA must be greater than zero"))
}

fn parse_timeout(value: OsString) -> AppResult<Duration> {
    let text = value
        .into_string()
        .map_err(|_| AppError::new("timeout must use valid text"))?;
    let seconds = text
        .parse::<u32>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| AppError::new(format!("invalid timeout: {text:?}")))?;

    Ok(Duration::from_secs(u64::from(seconds)))
}

fn parse_u32(text: &str) -> Result<u32, std::num::ParseIntError> {
    match strip_hex(text) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse::<u32>(),
    }
}

fn strip_hex(text: &str) -> Option<&str> {
    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
}
