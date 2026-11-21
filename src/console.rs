use std::cell::RefCell;
use std::fmt::{Arguments, Display};
use std::io::{IsTerminal, Write, stderr, stdin, stdout}; // writeln: a closed pipe must not panic

use windows::Win32::System::Console::{
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleProcessList, GetStdHandle,
    STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode,
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
    transcript: RefCell<String>, // what stdout showed, for the report file
}

pub(crate) const LABEL_WIDTH: usize = 10;

impl Console {
    pub(crate) fn new() -> Self {
        let stdout_color = stdout().is_terminal() && enable_color(STD_OUTPUT_HANDLE);
        let stderr_color = stderr().is_terminal() && enable_color(STD_ERROR_HANDLE);
        Self {
            stdout_color,
            stderr_color,
            transcript: RefCell::default(),
        }
    }

    pub(crate) fn transcript(&self) -> String {
        self.transcript.borrow().clone()
    }

    pub(crate) fn banner(&self) {
        self.stdout(BOLD, format_args!("mempe {}", env!("CARGO_PKG_VERSION")));
        self.blank();
    }

    pub(crate) fn section(&self, name: &str) {
        self.stdout(CYAN, format_args!("{name}"));
    }

    pub(crate) fn field(&self, name: &str, value: impl Display) {
        self.stdout("", format_args!("  {name:<LABEL_WIDTH$} {value}"));
    }

    pub(crate) fn success(&self, message: Arguments<'_>) {
        self.stdout(GREEN, format_args!("  OK  {message}"));
    }

    pub(crate) fn warning(&self, message: Arguments<'_>) {
        self.stdout(YELLOW, format_args!("  WARN  {message}"));
    }

    pub(crate) fn note(&self, message: Arguments<'_>) {
        self.stdout("", format_args!("  NOTE  {message}"));
    }

    pub(crate) fn error(&self, message: Arguments<'_>) {
        let message = printable(message);
        if self.stderr_color {
            let _ = writeln!(stderr(), "{RED}  ERROR  {message}{RESET}");
        } else {
            let _ = writeln!(stderr(), "  ERROR  {message}");
        }
    }

    pub(crate) fn done(&self, message: Arguments<'_>) {
        self.blank();
        self.stdout(GREEN, format_args!("DONE  {message}"));
    }

    pub(crate) fn partial(&self, message: Arguments<'_>) {
        self.blank();
        self.stdout(YELLOW, format_args!("PARTIAL  {message}"));
    }

    pub(crate) fn blank(&self) {
        self.transcript.borrow_mut().push_str("\r\n");
        let _ = writeln!(stdout());
    }

    pub(crate) fn hold_if_alone(&self) {
        let mut processes = [0u32; 2];
        let alone = unsafe { GetConsoleProcessList(&mut processes) } == 1; // own console: the window closes with mempe
        if alone && stdin().is_terminal() {
            let _ = writeln!(stdout(), "\nPress Enter to close");
            let _ = stdin().read_line(&mut String::new());
        }
    }

    fn stdout(&self, color: &str, message: Arguments<'_>) {
        let message = printable(message);
        let mut transcript = self.transcript.borrow_mut();
        transcript.push_str(&message);
        transcript.push_str("\r\n");
        drop(transcript);

        if self.stdout_color && !color.is_empty() {
            let _ = writeln!(stdout(), "{color}{message}{RESET}");
        } else {
            let _ = writeln!(stdout(), "{message}");
        }
    }
}

fn printable(message: impl Display) -> String {
    message
        .to_string()
        .replace(|c: char| c.is_control() && c != '\n' && c != '\t', "?") // the target's text: no escape sequences
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
