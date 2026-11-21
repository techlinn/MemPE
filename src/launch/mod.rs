mod code_cache;
mod debug_loop;
mod execute_trap;
mod handler_setup;
mod hide_debugger;
mod injected_handler;
mod remote_memory;
mod spawn;
mod stop_point;
mod syscall_hooks;
mod system_files;
mod thread_context;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::Range;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, ERROR_SEM_TIMEOUT, HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, WaitForDebugEvent,
};
use windows::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetCurrentThread, GetThreadPriority, SetPriorityClass,
    SetThreadPriority, THREAD_PRIORITY, THREAD_PRIORITY_ABOVE_NORMAL,
};

use self::debug_loop::Debuggee;
use self::execute_trap::Trap;
use self::spawn::ChildProcess;
use self::stop_point::Image;
pub(crate) use self::stop_point::{Reached, Stop};
use crate::packers::LayoutBasis;
use crate::pe::{self, CLR_DIRECTORY, PAGE_SIZE, PeKind};
use crate::process::{DriveMap, FileIdentity};
use crate::process::{LoadedModule, ProcessId, TargetProcess};
use crate::rebuild::EntryPointRva;
use crate::windows_error;
use crate::{AppError, AppResult};

const EVENT_WAIT_MS: u32 = 100;

#[derive(Clone, Copy)]
pub(crate) enum Method {
    Debugger,
    InjectedHandler, // vmp sees any debugger
}

pub(crate) struct Session {
    child: ChildProcess,
    library: Option<LoadedModule>,
    pub(crate) stop: Stop,
    pub(crate) basis: LayoutBasis,
    pub(crate) method: Method,
    pub(crate) elapsed: Duration,
}

struct Stopped {
    stop: Stop,
    span: Range<usize>,
    basis: LayoutBasis,
}

impl Session {
    pub(crate) fn target(&self) -> AppResult<TargetProcess> {
        let pid = NonZeroU32::new(self.child.pid)
            .ok_or_else(|| AppError::new("the launched process has no PID"))?;
        let mut target = crate::process::query(ProcessId::from(pid))?;

        if let Some(library) = &self.library {
            target.name.clone_from(&library.name);
            target.path.clone_from(&library.path);
            target.main_module = Some(library.clone());
            target.main_module_unlisted = false;
        }

        Ok(target)
    }

    pub(crate) fn entry_point(&self) -> Option<EntryPointRva> {
        match self.stop.reached {
            Reached::EntryPoint if self.basis == LayoutBasis::NoPacker => None, // the file's own entry
            Reached::EntryPoint => EntryPointRva::observed(self.stop.rva),
            Reached::ThroughPacker => EntryPointRva::handed_over(self.stop.rva),
        }
    }
}

pub(crate) fn launch(path: &Path, timeout: Duration) -> AppResult<Session> {
    let started = Instant::now();
    let subject = Subject::read(path)?;
    system_files::system_folders()?;

    let library = match subject.library {
        true => Some(HostedDll::new(path)?),
        false => None,
    };
    let method = match subject.evades_debugger {
        true => Method::InjectedHandler,
        false => Method::Debugger,
    };

    let kind = subject.kind;
    let child = spawn::start(path, subject.library.then_some(kind))?;
    let deadline = started + timeout;
    let stopped = match method {
        Method::InjectedHandler => {
            stop_with_injected_handler(&child, library.as_ref(), kind, deadline)
        }
        Method::Debugger => Debuggee::new(&child, library.as_ref(), kind).run(deadline),
    };
    let stopped = stopped.map_err(|error| {
        AppError::new(format!(
            "{error}; the process was ended and nothing was dumped"
        ))
    })?;
    let library = library.and_then(|_| {
        Some(LoadedModule {
            name: path.file_name()?.to_string_lossy().into_owned(),
            path: path.to_owned(),
            base: stopped.span.start,
            size: stopped.span.len(),
        })
    });

    Ok(Session {
        child,
        library,
        stop: stopped.stop,
        basis: stopped.basis,
        method,
        elapsed: started.elapsed(),
    })
}

struct Subject {
    kind: PeKind,
    library: bool,
    evades_debugger: bool,
}

impl Subject {
    fn read(path: &Path) -> AppResult<Self> {
        let file = std::fs::read(path).map_err(|error| {
            AppError::new(format!("could not read {}: {error}", path.display()))
        })?;
        let image = pe::parse::parse_disk_image(&file).map_err(|_| {
            AppError::new("not a Windows program: launch mode starts .exe and .dll files only")
        })?;
        let model = image.model();

        let managed = model.directory(&file, CLR_DIRECTORY).is_some();
        if managed {
            return Err(AppError::new(
                "a .NET program: its code is compiled while it runs, so launch mode cannot stop it before it starts; start it yourself and use -p",
            ));
        }
        if model.is_low_alignment() {
            return Err(AppError::new(
                "the file's sections are aligned to less than a memory page, so launch mode cannot keep its code from running; start it yourself and use -p",
            ));
        }

        Ok(Self {
            kind: model.kind,
            library: model.is_dll,
            evades_debugger: crate::packers::checks_debugger_directly(&file),
        })
    }
}

struct PriorityLead {
    thread: HANDLE,
    priority: i32,
}

impl PriorityLead {
    fn over(child: &ChildProcess) -> Self {
        let thread = unsafe { GetCurrentThread() };
        let priority = unsafe { GetThreadPriority(thread) };
        let _ = unsafe { SetPriorityClass(child.process.raw(), BELOW_NORMAL_PRIORITY_CLASS) };
        let _ = unsafe { SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL) };
        Self { thread, priority }
    }
}

impl Drop for PriorityLead {
    fn drop(&mut self) {
        let _ = unsafe { SetThreadPriority(self.thread, THREAD_PRIORITY(self.priority)) };
    }
}

fn stop_with_injected_handler(
    child: &ChildProcess,
    library: Option<&HostedDll>,
    kind: PeKind,
    deadline: Instant,
) -> AppResult<Stopped> {
    let (handler, mut image) = handler_setup::run(child, library, kind, deadline)?;
    let _lead = PriorityLead::over(child);
    let stop = handler.wait_for_stop(child, &mut image, deadline)?;

    Ok(Stopped {
        stop,
        span: image.span,
        basis: image.basis,
    })
}

fn prepare(process: HANDLE, base: usize, library: bool) -> AppResult<Image> {
    let bytes = read_module(process, base)?;
    let layout = crate::packers::program_layout(&bytes, base)?;
    if layout.code.is_empty() {
        return Err(AppError::new(
            "the file has no section apart from the one it starts in",
        ));
    }

    let mut trap = Trap::new(base, &layout.code);
    trap.arm(process);

    Ok(Image {
        span: base..base + bytes.len(),
        entry: base + layout.entry,
        kind: layout.kind,
        fixer: layout.fixer.map(|rva| base + rva),
        library,
        basis: layout.basis,
        entry_stub_in_code: layout.entry_stub_in_code(),
        tls_directory: layout.tls_directory,
        trap,
    })
}

fn read_module(process: HANDLE, base: usize) -> AppResult<Vec<u8>> {
    let mut headers = [0u8; PAGE_SIZE];
    if !remote_memory::read(process, base, &mut headers) {
        return Err(AppError::new("could not read the program's headers"));
    }

    let size = pe::parse::parse_disk_image(&headers)?.model().image_size as usize;
    Ok(remote_memory::read_image(process, base, size))
}

struct HostedDll {
    identity: FileIdentity,
    mapped_as: Option<String>, // device path, none off a drive letter
}

impl HostedDll {
    fn new(path: &Path) -> AppResult<Self> {
        let file = std::fs::File::open(path).map_err(|error| {
            AppError::new(format!("could not open {}: {error}", path.display()))
        })?;
        let identity = FileIdentity::of(HANDLE(file.as_raw_handle()))
            .ok_or_else(|| AppError::new(format!("could not identify {}", path.display())))?;

        let mapped_as = std::path::absolute(path)
            .ok()
            .and_then(|full| DriveMap::read().to_device(full.to_str()?));

        Ok(Self {
            identity,
            mapped_as,
        })
    }

    fn is(&self, file: HANDLE, process: HANDLE, base: usize) -> bool {
        if !file.is_invalid() {
            return FileIdentity::of(file) == Some(self.identity);
        }

        let Some(wanted) = &self.mapped_as else {
            return false;
        };

        crate::process::mapped_file_name(process, base)
            .is_some_and(|path| path.eq_ignore_ascii_case(wanted)) // no file handle in the event
    }
}

fn late() -> AppError {
    AppError::new("the program's own code was already running when mempe caught it")
}

fn exited(code: u32, when: &str) -> AppError {
    AppError::new(format!(
        "the process ended with exit code 0x{code:X} {when}"
    ))
}

fn close(file: HANDLE) {
    if !file.is_invalid() {
        let _ = unsafe { CloseHandle(file) };
    }
}

fn next_event(event: &mut DEBUG_EVENT) -> AppResult<bool> {
    match unsafe { WaitForDebugEvent(event, EVENT_WAIT_MS) } {
        Ok(()) => Ok(true),
        Err(error) if error.code() == ERROR_SEM_TIMEOUT.to_hresult() => Ok(false),
        Err(error) => Err(windows_error("WaitForDebugEvent", error)),
    }
}

enum Flow<T> {
    Continue(NTSTATUS),
    Done(T),
}

trait Policy {
    type Outcome;

    fn on_event(&mut self, event: &DEBUG_EVENT) -> AppResult<Flow<Self::Outcome>>;

    fn on_quiet(&mut self) {}
}

fn pump<P: Policy>(
    policy: &mut P,
    deadline: Instant,
) -> AppResult<Option<(P::Outcome, DEBUG_EVENT)>> {
    while Instant::now() < deadline {
        let mut event = DEBUG_EVENT::default();
        if !next_event(&mut event)? {
            policy.on_quiet();
            continue;
        }

        match policy.on_event(&event)? {
            Flow::Done(outcome) => return Ok(Some((outcome, event))),
            Flow::Continue(status) => {
                unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
                    .map_err(|error| windows_error("ContinueDebugEvent", error))?;
            }
        }
    }

    Ok(None)
}

#[derive(Default)]
struct Threads(HashMap<u32, HANDLE>);

impl Threads {
    fn track(&mut self, event: &DEBUG_EVENT, own: bool) {
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT if own => {
                let thread = unsafe { event.u.CreateProcessInfo }.hThread;
                self.0.insert(event.dwThreadId, thread);
            }
            CREATE_THREAD_DEBUG_EVENT if own => {
                let thread = unsafe { event.u.CreateThread }.hThread;
                self.0.insert(event.dwThreadId, thread);
            }
            EXIT_THREAD_DEBUG_EVENT => {
                self.0.remove(&event.dwThreadId);
            }
            _ => {}
        }
    }

    fn known(&self, id: u32) -> AppResult<HANDLE> {
        self.0
            .get(&id)
            .copied()
            .ok_or_else(|| AppError::new("a thread the debugger never saw raised an exception"))
    }
}

#[cfg(not(target_pointer_width = "64"))]
compile_error!("launch mode reads 64-bit thread contexts, so mempe must be a 64-bit build");
