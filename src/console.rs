use std::fmt::Arguments;
use std::io::{IsTerminal, stderr, stdout};

use windows::Win32::System::Console::{
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleMode,
};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

pub(crate) struct Console {
    stdout_color: bool,
    stderr_color: bool,
}

impl Console {
    pub(crate) fn new() -> Self {
        let stdout_color = stdout().is_terminal() && enable_color(STD_OUTPUT_HANDLE);
        let stderr_color = stderr().is_terminal() && enable_color(STD_ERROR_HANDLE);
        Self {
            stdout_color,
            stderr_color,
        }
    }

    pub(crate) fn banner(&self) {
        self.stdout(BOLD, format_args!("mempe {}", env!("CARGO_PKG_VERSION")));
        println!();
    }

    pub(crate) fn section(&self, name: &str) {
        self.stdout(CYAN, format_args!("{name}"));
    }

    pub(crate) fn field(&self, name: &str, value: Arguments<'_>) {
        println!("  {name:<11}{value}");
    }

    pub(crate) fn success(&self, message: Arguments<'_>) {
        self.stdout(GREEN, format_args!("  OK  {message}"));
    }

    pub(crate) fn warning(&self, message: Arguments<'_>) {
        self.stdout(YELLOW, format_args!("  WARN  {message}"));
    }

    pub(crate) fn error(&self, message: Arguments<'_>) {
        if self.stderr_color {
            eprintln!("{RED}  ERROR  {message}{RESET}");
        } else {
            eprintln!("  ERROR  {message}");
        }
    }

    pub(crate) fn done(&self, message: Arguments<'_>) {
        println!();
        self.stdout(GREEN, format_args!("DONE  {message}"));
    }

    pub(crate) fn partial(&self, message: Arguments<'_>) {
        println!();
        self.stdout(YELLOW, format_args!("PARTIAL  {message}"));
    }

    pub(crate) fn blank(&self) {
        println!();
    }

    fn stdout(&self, color: &str, message: Arguments<'_>) {
        if self.stdout_color {
            println!("{color}{message}{RESET}");
        } else {
            println!("{message}");
        }
    }
}

fn enable_color(handle_name: windows::Win32::System::Console::STD_HANDLE) -> bool {
    let Ok(handle) = (unsafe { GetStdHandle(handle_name) }) else {
        return false;
    };
    let mut mode = Default::default();
    if unsafe { GetConsoleMode(handle, &mut mode) }.is_err() {
        return false;
    }
    unsafe { SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) }.is_ok()
}
