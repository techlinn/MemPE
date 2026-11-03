use std::ffi::OsString;
use std::num::NonZeroU32;

use crate::pe::EntryPointRva;
use crate::{AppError, AppResult};

const MAX_TRAILING_OPTIONS: usize = 4;

pub const HELP: &str = "mempe - Windows PE memory dumper and rebuilder\n\n\
Usage:\n\
  mempe.exe -p <PID> [-e|--entry-point <RVA>] [--raw-regions] [--only <name>]\n\
  mempe.exe -w <program.exe> [-e|--entry-point <RVA>] [--raw-regions] [--only <name>]\n\
  mempe.exe -h\n\n\
-w waits up to 24 hours for a new matching process. Press Ctrl+C to stop.\n\
--raw-regions also writes the untouched bytes of executable non-image\n\
allocations that held no full PE. Off by default; it can add many files.\n\
--only writes just the images matching a module name or a 0x-prefixed base\n\
address. Every image is still captured and indexed, so imports resolve the\n\
same as in a full dump.\n";

#[derive(Debug, Eq, PartialEq)]
pub struct Request {
    pub command: Command,
    pub entry_point: Option<EntryPointRva>,
    pub raw_regions: bool,
    pub only: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Pid(NonZeroU32),
    Watch(String),
}

pub fn parse<I>(args: I) -> AppResult<Option<Request>>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let option = args
        .next()
        .ok_or_else(|| AppError::new("missing -p, -w, or -h"))?;

    if option == "-h" || option == "--help" {
        if args.next().is_some() {
            return Err(AppError::new("help does not take more arguments"));
        }
        return Ok(None);
    }

    if option != "-p" && option != "-w" {
        return Err(AppError::new(format!(
            "unknown option: {}",
            option.to_string_lossy()
        )));
    }
    let value = args
        .next()
        .ok_or_else(|| AppError::new(format!("{} needs a value", option.to_string_lossy())))?;
    let command = if option == "-p" {
        parse_pid(value).map(Command::Pid)?
    } else {
        parse_watch_name(value).map(Command::Watch)?
    };
    let options = parse_trailing_options(&mut args)?;
    Ok(Some(Request {
        command,
        entry_point: options.entry_point,
        raw_regions: options.raw_regions,
        only: options.only,
    }))
}

fn parse_pid(value: OsString) -> AppResult<NonZeroU32> {
    let text = value
        .into_string()
        .map_err(|_| AppError::new("PID must use valid text"))?;
    let parsed = parse_u32(&text).map_err(|_| AppError::new(format!("invalid PID: {text:?}")))?;

    NonZeroU32::new(parsed).ok_or_else(|| AppError::new("PID must be greater than zero"))
}

fn parse_watch_name(value: OsString) -> AppResult<String> {
    let name = value
        .into_string()
        .map_err(|_| AppError::new("process name must use valid text"))?;
    if name.is_empty() {
        return Err(AppError::new("process name cannot be empty"));
    }
    if name.contains(['\\', '/']) {
        return Err(AppError::new("-w takes a file name, not a path"));
    }
    Ok(name)
}

#[derive(Default)]
struct TrailingOptions {
    entry_point: Option<EntryPointRva>,
    raw_regions: bool,
    only: Option<String>,
}

fn parse_trailing_options(args: &mut impl Iterator<Item = OsString>) -> AppResult<TrailingOptions> {
    let mut options = TrailingOptions::default();
    for _slot in 0..MAX_TRAILING_OPTIONS {
        let Some(option) = args.next() else {
            return Ok(options);
        };
        if option == "--raw-regions" {
            if options.raw_regions {
                return Err(AppError::new("--raw-regions was given twice"));
            }
            options.raw_regions = true;
            continue;
        }
        if option == "--only" {
            if options.only.is_some() {
                return Err(AppError::new("--only was given twice"));
            }
            let value = args
                .next()
                .ok_or_else(|| AppError::new("--only needs a module name or base address"))?;
            let name = value
                .into_string()
                .map_err(|_| AppError::new("--only value is not valid Unicode"))?;
            if name.is_empty() {
                return Err(AppError::new("--only value cannot be empty"));
            }
            options.only = Some(name);
            continue;
        }
        if option != "-e" && option != "--entry-point" {
            return Err(AppError::new(format!(
                "unknown option: {}",
                option.to_string_lossy()
            )));
        }
        if options.entry_point.is_some() {
            return Err(AppError::new("--entry-point was given twice"));
        }
        let value = args
            .next()
            .ok_or_else(|| AppError::new("--entry-point needs an RVA"))?;
        options.entry_point = Some(parse_entry_point(value)?);
    }
    Err(AppError::new("too many arguments"))
}

fn parse_entry_point(value: OsString) -> AppResult<EntryPointRva> {
    let text = value
        .into_string()
        .map_err(|_| AppError::new("entry-point RVA must use valid text"))?;
    let parsed = parse_u32(&text)
        .map_err(|_| AppError::new(format!("invalid entry-point RVA: {text:?}")))?;
    EntryPointRva::new(parsed)
        .ok_or_else(|| AppError::new("entry-point RVA must be greater than zero"))
}

fn parse_u32(text: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        text.parse::<u32>()
    }
}
