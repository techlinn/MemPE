use std::ffi::OsString;
use std::num::NonZeroU32;

use crate::{AppError, AppResult};

pub const HELP: &str = "mempe - Windows PE memory dumper and rebuilder\n\n\
Usage:\n\
  mempe.exe -p <PID>\n\
  mempe.exe -w <program.exe>\n\
  mempe.exe -h\n";

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Pid(NonZeroU32),
    Watch(String),
}

pub fn parse<I>(args: I) -> AppResult<Option<Command>>
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

    let value = args
        .next()
        .ok_or_else(|| AppError::new("this option needs a value"))?;
    if args.next().is_some() {
        return Err(AppError::new("too many arguments"));
    }

    if option == "-p" {
        return parse_pid(value).map(Command::Pid).map(Some);
    }
    if option == "-w" {
        return parse_watch_name(value).map(Command::Watch).map(Some);
    }

    Err(AppError::new(format!(
        "unknown option: {}",
        option.to_string_lossy()
    )))
}

fn parse_pid(value: OsString) -> AppResult<NonZeroU32> {
    let text = value
        .into_string()
        .map_err(|_| AppError::new("PID must use valid text"))?;
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        text.parse::<u32>()
    }
    .map_err(|_| AppError::new(format!("invalid PID: {text}")))?;

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

#[cfg(test)]
mod tests {
    use super::{Command, parse};
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_decimal_and_hex_pid() -> Result<(), Box<dyn std::error::Error>> {
        let decimal = parse(args(&["mempe", "-p", "4216"]))?;
        let hexadecimal = parse(args(&["mempe", "-p", "0x1078"]))?;

        assert_eq!(decimal, hexadecimal);
        assert!(matches!(decimal, Some(Command::Pid(_))));
        Ok(())
    }

    #[test]
    fn rejects_paths_in_watch_mode() {
        let result = parse(args(&["mempe", "-w", "C:\\tools\\program.exe"]));

        assert!(result.is_err());
        assert_ne!(result, Ok(None));
    }

    #[test]
    fn help_requires_no_tail() {
        let help = parse(args(&["mempe", "-h"]));
        let invalid = parse(args(&["mempe", "-h", "extra"]));

        assert_eq!(help, Ok(None));
        assert!(invalid.is_err());
    }
}
