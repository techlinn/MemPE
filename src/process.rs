use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::mem::size_of;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, FILETIME, HANDLE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
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
    GetCurrentProcess, GetProcessTimes, IsWow64Process2, OpenProcess, OpenProcessToken,
    PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};

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
    pub(crate) path: PathBuf,
    pub(crate) architecture: TargetArchitecture,
    pub(crate) created: u64,
    pub(crate) main_module: Option<ModuleInfo>,
    pub(crate) modules: Vec<ModuleInfo>,
    pub(crate) module_listing_denied: bool,
}

pub(crate) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub(crate) fn open(pid: ProcessId, rights: PROCESS_ACCESS_RIGHTS) -> AppResult<Self> {
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
        let result = unsafe { CloseHandle(self.0) };
        debug_assert!(result.is_ok());
    }
}

pub(crate) fn enable_debug_privilege() {
    let mut raw_token = HANDLE::default();
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut raw_token) };
    if opened.is_err() {
        return;
    }
    let token = OwnedHandle(raw_token);
    let mut luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid) }.is_err() {
        return;
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let _ = unsafe { AdjustTokenPrivileges(token.raw(), false, Some(&privileges), 0, None, None) };
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
    let listing = get_modules(pid).map_err(|error| explain_denied_access(pid, error));
    let module_listing_denied = listing.is_err();
    let modules = listing.unwrap_or_default();
    let main_module = match modules.is_empty() {
        true => None,
        false => Some(find_main_module(&path, &modules)?),
    };

    Ok(TargetProcess {
        pid,
        name,
        path,
        architecture,
        created,
        main_module,
        modules,
        module_listing_denied,
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
        match unsafe { Process32NextW(snapshot.raw(), &mut entry) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return Ok(entries),
            Err(error) => return Err(windows_error("Process32NextW", error)),
        }
    }
    Err(AppError::new("too many processes were returned"))
}

fn process_snapshot() -> AppResult<OwnedHandle> {
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
    current
        .difference(baseline)
        .take(MAX_PROCESSES)
        .filter_map(|pid| query(*pid).ok())
        .min_by_key(|target| (target.created, target.pid.get()))
}

fn wait_until_capture_time(created: u64) {
    let deadline = created.saturating_add(CAPTURE_DELAY_FILETIME);
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
    unsafe { Module32FirstW(snapshot.raw(), &mut entry) }
        .map_err(|error| windows_error("Module32FirstW", error))?;

    let mut modules = Vec::with_capacity(64);
    for _index in 0..MAX_MODULES {
        modules.push(module_from_entry(&entry));
        match unsafe { Module32NextW(snapshot.raw(), &mut entry) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return Ok(modules),
            Err(error) => return Err(windows_error("Module32NextW", error)),
        }
    }
    Err(AppError::new("too many modules were returned"))
}

fn explain_denied_access(pid: ProcessId, error: AppError) -> AppError {
    if OwnedHandle::open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).is_ok() {
        return error;
    }
    AppError::new(
        "the target refuses memory access; run mempe from an elevated terminal, and note that a \
         protected process can deny access even to an administrator",
    )
}

fn module_snapshot(pid: ProcessId) -> AppResult<OwnedHandle> {
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    for _attempt in 0..MAX_MODULE_SNAPSHOT_TRIES {
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
    if modules.is_empty() {
        return Err(AppError::new("target has no modules"));
    }
    if let Some(module) = modules
        .iter()
        .find(|module| paths_equal(&module.path, path))
        .or_else(|| find_by_basename(path, modules))
    {
        return Ok(module.clone());
    }
    Err(AppError::new(format!(
        "no loaded module matches the target image {}; refusing to guess which of the {} mapped \
         modules is the main image",
        path.display(),
        modules.len()
    )))
}

fn find_by_basename<'a>(path: &Path, modules: &'a [ModuleInfo]) -> Option<&'a ModuleInfo> {
    let wanted = path.file_name()?.to_str()?;
    let mut matches = modules.iter().filter(|module| {
        module
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ModuleInfo, find_main_module};

    fn module(name: &str, dir: &str) -> ModuleInfo {
        ModuleInfo {
            name: name.to_owned(),
            path: PathBuf::from(dir).join(name),
            base: 0x1000,
            size: 0x1000,
        }
    }

    #[test]
    fn matches_the_exact_reported_path() -> Result<(), Box<dyn std::error::Error>> {
        let target = PathBuf::from(r"C:\apps\a.exe");
        let modules = vec![module("a.exe", r"C:\other"), module("a.exe", r"C:\apps")];

        let found = find_main_module(&target, &modules)?;

        assert_eq!(found.path, PathBuf::from(r"C:\apps\a.exe"));
        Ok(())
    }

    #[test]
    fn falls_back_to_a_unique_basename_match() -> Result<(), Box<dyn std::error::Error>> {
        let target = PathBuf::from(r"C:\renamed\a.exe");
        let modules = vec![
            module("a.exe", r"C:\original"),
            module("b.dll", r"C:\original"),
        ];

        let found = find_main_module(&target, &modules)?;

        assert_eq!(found.name, "a.exe");
        Ok(())
    }

    #[test]
    fn refuses_to_guess_between_two_modules_with_the_same_basename() {
        let target = PathBuf::from(r"C:\renamed\a.exe");
        let modules = vec![module("a.exe", r"C:\one"), module("a.exe", r"C:\two")];

        assert!(find_main_module(&target, &modules).is_err());
    }

    #[test]
    fn refuses_to_guess_when_nothing_matches() {
        let target = PathBuf::from(r"C:\renamed\a.exe");
        let modules = vec![module("unrelated.dll", r"C:\one")];

        assert!(find_main_module(&target, &modules).is_err());
    }

    #[test]
    fn refuses_an_empty_module_list() {
        let target = PathBuf::from(r"C:\renamed\a.exe");

        assert!(find_main_module(&target, &[]).is_err());
    }
}
