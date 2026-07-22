use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::mem::size_of;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, FILETIME, HANDLE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::{
    GetSystemTimePreciseAsFileTime, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, IsWow64Process2, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::{AppError, AppResult};

const MAX_PROCESSES: usize = 65_536;
const MAX_MODULES: usize = 4_096;
const MAX_MODULE_SNAPSHOT_TRIES: usize = 8;
const MAX_WATCH_POLLS: usize = 864_000;
const PROCESS_POLL_DELAY: Duration = Duration::from_millis(100);
const CAPTURE_DELAY_FILETIME: u64 = 10_000_000;
const MAX_PATH_CHARS: usize = 32_768;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct ProcessId(NonZeroU32);

impl ProcessId {
    pub(crate) fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<NonZeroU32> for ProcessId {
    fn from(value: NonZeroU32) -> Self {
        Self(value)
    }
}

pub(crate) enum TargetArchitecture {
    X86,
    X64,
}

impl Display for TargetArchitecture {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => formatter.write_str("x86"),
            Self::X64 => formatter.write_str("x64"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ModuleInfo {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) base: usize,
    pub(crate) size: usize,
}

pub(crate) struct TargetProcess {
    pub(crate) pid: ProcessId,
    pub(crate) name: String,
    pub(crate) architecture: TargetArchitecture,
    pub(crate) created: u64,
    pub(crate) main_module: ModuleInfo,
    pub(crate) modules: Vec<ModuleInfo>,
}

pub(crate) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub(crate) fn open(pid: ProcessId, rights: PROCESS_ACCESS_RIGHTS) -> AppResult<Self> {
        // SAFETY: The PID and access mask are values, handle inheritance is disabled, and the
        // returned owned handle is closed by Drop.
        let handle = unsafe { OpenProcess(rights, false, pid.get()) }
            .map_err(|error| windows_error("OpenProcess", error))?;
        Ok(Self(handle))
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OwnedHandle owns a valid Windows handle and closes it only once.
        let result = unsafe { CloseHandle(self.0) };
        debug_assert!(result.is_ok());
    }
}

struct ProcessEntry {
    pid: ProcessId,
    name: String,
}

pub(crate) fn query(pid: ProcessId) -> AppResult<TargetProcess> {
    let handle = OwnedHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let path = get_path(&handle)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::new("target image name is not valid Unicode"))?
        .to_owned();
    let architecture = get_architecture(&handle)?;
    let created = get_creation_time(&handle)?;
    let modules = get_modules(pid)?;
    let main_module = find_main_module(&path, &modules)?;

    Ok(TargetProcess {
        pid,
        name,
        architecture,
        created,
        main_module,
        modules,
    })
}

pub(crate) fn watch(name: &str) -> AppResult<TargetProcess> {
    if name.is_empty() {
        return Err(AppError::new("watch name cannot be empty"));
    }
    let mut baseline = matching_pids(name, &list_processes()?);

    for _poll in 0..MAX_WATCH_POLLS {
        let entries = list_processes()?;
        let current = matching_pids(name, &entries);
        baseline.retain(|pid| current.contains(pid));
        if let Some(target) = find_new_target(&current, &baseline) {
            wait_until_capture_time(target.created);
            if let Ok(confirmed) = query(target.pid)
                && confirmed.created == target.created
            {
                return Ok(confirmed);
            }
            baseline.insert(target.pid);
        }
        thread::sleep(PROCESS_POLL_DELAY);
    }

    Err(AppError::new(
        "watch timed out after 24 hours without a new matching process",
    ))
}

fn list_processes() -> AppResult<Vec<ProcessEntry>> {
    let snapshot = process_snapshot()?;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: entry points to writable storage of the required size and snapshot is valid.
    unsafe { Process32FirstW(snapshot.raw(), &mut entry) }
        .map_err(|error| windows_error("Process32FirstW", error))?;

    let mut entries = Vec::with_capacity(256);
    for _index in 0..MAX_PROCESSES {
        if let Some(pid) = NonZeroU32::new(entry.th32ProcessID) {
            entries.push(ProcessEntry {
                pid: ProcessId(pid),
                name: wide_string(&entry.szExeFile),
            });
        }
        // SAFETY: entry remains writable and snapshot remains valid for this bounded walk.
        match unsafe { Process32NextW(snapshot.raw(), &mut entry) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return Ok(entries),
            Err(error) => return Err(windows_error("Process32NextW", error)),
        }
    }
    Err(AppError::new("too many processes were returned"))
}

fn process_snapshot() -> AppResult<OwnedHandle> {
    // SAFETY: The process ID is ignored for TH32CS_SNAPPROCESS and the returned handle is owned.
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|error| windows_error("CreateToolhelp32Snapshot(processes)", error))?;
    Ok(OwnedHandle(handle))
}

fn matching_pids(name: &str, entries: &[ProcessEntry]) -> HashSet<ProcessId> {
    entries
        .iter()
        .filter(|entry| entry.name.eq_ignore_ascii_case(name))
        .map(|entry| entry.pid)
        .collect()
}

fn find_new_target(
    current: &HashSet<ProcessId>,
    baseline: &HashSet<ProcessId>,
) -> Option<TargetProcess> {
    let mut candidates = Vec::with_capacity(current.len().min(16));
    for pid in current.difference(baseline).take(MAX_PROCESSES) {
        if let Ok(target) = query(*pid) {
            candidates.push(target);
        }
    }
    candidates.sort_by_key(|target| (target.created, target.pid.get()));
    candidates.into_iter().next()
}

fn wait_until_capture_time(created: u64) {
    let deadline = created.saturating_add(CAPTURE_DELAY_FILETIME);
    // SAFETY: GetSystemTimePreciseAsFileTime has no pointer parameters or preconditions.
    let now = filetime_value(unsafe { GetSystemTimePreciseAsFileTime() });
    let remaining = deadline.saturating_sub(now);
    if remaining > 0 {
        thread::sleep(Duration::from_nanos(remaining.saturating_mul(100)));
    }
}

fn get_path(handle: &OwnedHandle) -> AppResult<PathBuf> {
    let mut buffer = vec![0u16; MAX_PATH_CHARS];
    let mut length = u32::try_from(buffer.len())
        .map_err(|_| AppError::new("process path buffer does not fit the Windows API"))?;
    // SAFETY: buffer is writable for length UTF-16 code units and length points to valid storage.
    unsafe {
        QueryFullProcessImageNameW(
            handle.raw(),
            Default::default(),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|error| windows_error("QueryFullProcessImageNameW", error))?;
    let used = usize::try_from(length)
        .map_err(|_| AppError::new("process path length does not fit memory"))?;
    let path = String::from_utf16(
        buffer
            .get(..used)
            .ok_or_else(|| AppError::new("Windows returned an invalid process path length"))?,
    )
    .map_err(|_| AppError::new("process path contains invalid UTF-16"))?;
    Ok(PathBuf::from(path))
}

fn get_architecture(handle: &OwnedHandle) -> AppResult<TargetArchitecture> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: Both output pointers refer to initialized writable values for the call duration.
    unsafe {
        IsWow64Process2(
            handle.raw(),
            &mut process_machine,
            Some(&mut native_machine),
        )
    }
    .map_err(|error| windows_error("IsWow64Process2", error))?;

    let machine = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    };
    if machine == IMAGE_FILE_MACHINE_I386 {
        return Ok(TargetArchitecture::X86);
    }
    if machine == IMAGE_FILE_MACHINE_AMD64 {
        return Ok(TargetArchitecture::X64);
    }
    Err(AppError::new(format!(
        "unsupported target machine: 0x{:04X}",
        machine.0
    )))
}

fn get_creation_time(handle: &OwnedHandle) -> AppResult<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: All FILETIME pointers refer to writable values for the call duration.
    unsafe {
        GetProcessTimes(
            handle.raw(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|error| windows_error("GetProcessTimes", error))?;
    Ok(filetime_value(created))
}

fn get_modules(pid: ProcessId) -> AppResult<Vec<ModuleInfo>> {
    let snapshot = module_snapshot(pid)?;
    let mut entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: entry points to writable storage of the required size and snapshot is valid.
    unsafe { Module32FirstW(snapshot.raw(), &mut entry) }
        .map_err(|error| windows_error("Module32FirstW", error))?;

    let mut modules = Vec::with_capacity(64);
    for _index in 0..MAX_MODULES {
        modules.push(module_from_entry(&entry));
        // SAFETY: entry remains writable and snapshot remains valid for this bounded walk.
        match unsafe { Module32NextW(snapshot.raw(), &mut entry) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return Ok(modules),
            Err(error) => return Err(windows_error("Module32NextW", error)),
        }
    }
    Err(AppError::new("too many modules were returned"))
}

fn module_snapshot(pid: ProcessId) -> AppResult<OwnedHandle> {
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    for _attempt in 0..MAX_MODULE_SNAPSHOT_TRIES {
        // SAFETY: pid is valid and the returned snapshot handle is owned on success.
        match unsafe { CreateToolhelp32Snapshot(flags, pid.get()) } {
            Ok(handle) => return Ok(OwnedHandle(handle)),
            Err(error) if error.code() == ERROR_BAD_LENGTH.to_hresult() => {
                thread::yield_now();
            }
            Err(error) => {
                return Err(windows_error("CreateToolhelp32Snapshot(modules)", error));
            }
        }
    }
    Err(AppError::new(
        "could not get a stable module list after eight tries",
    ))
}

fn module_from_entry(entry: &MODULEENTRY32W) -> ModuleInfo {
    ModuleInfo {
        name: wide_string(&entry.szModule),
        path: PathBuf::from(wide_string(&entry.szExePath)),
        base: entry.modBaseAddr as usize,
        size: entry.modBaseSize as usize,
    }
}

fn find_main_module(path: &Path, modules: &[ModuleInfo]) -> AppResult<ModuleInfo> {
    modules
        .iter()
        .find(|module| paths_equal(&module.path, path))
        .or_else(|| modules.first())
        .cloned()
        .ok_or_else(|| AppError::new("target has no modules"))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn wide_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn windows_error(action: &str, error: windows::core::Error) -> AppError {
    AppError::new(format!("{action} failed: {error}"))
}
