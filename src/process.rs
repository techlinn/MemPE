use std::collections::HashSet;
use std::ffi::OsString;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::mem::size_of;
use std::num::NonZeroU32;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, ERROR_INVALID_PARAMETER,
    ERROR_NO_MORE_FILES, ERROR_NOT_ALL_ASSIGNED, FILETIME, GetLastError, HANDLE, LUID, MAX_PATH,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, GetLogicalDrives, QueryDosDeviceW,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows::Win32::System::ProcessStatus::K32GetMappedFileNameW;
use windows::Win32::System::SystemInformation::{
    GetSystemDirectoryW, GetSystemTimePreciseAsFileTime, GetSystemWow64DirectoryW,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, IsWow64Process2, OpenProcess, OpenProcessToken,
    PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::pe::PeKind;
use crate::{AppError, AppResult, windows_error};

const MAX_PROCESSES: usize = 65_536;
const MAX_MODULES: usize = 4_096;
const MAX_MODULE_SNAPSHOT_TRIES: usize = 8;
const WATCH_LIMIT: Duration = Duration::from_secs(24 * 60 * 60);
const PROCESS_POLL_DELAY: Duration = Duration::from_millis(100);
const CAPTURE_DELAY_FILETIME: u64 = 10_000_000;
pub(crate) const MAX_PATH_CHARS: usize = 32_768;
pub(crate) const MAX_REGIONS: usize = 1 << 20;
pub(crate) const ACCESS_MASK: u32 = 0xFF; // low byte is access, rest modifiers

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
pub(crate) struct LoadedModule {
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
    pub(crate) main_module: Option<LoadedModule>,
    pub(crate) modules: Vec<LoadedModule>,
    pub(crate) module_listing_error: Option<AppError>,
    pub(crate) image_base: Option<usize>,
    pub(crate) main_module_unlisted: bool,
}

pub(crate) struct OwnedHandle(HANDLE);

impl TargetProcess {
    pub(crate) fn open(&self, rights: PROCESS_ACCESS_RIGHTS) -> AppResult<OwnedHandle> {
        let handle = OwnedHandle::open(self.pid, rights)?;
        if get_creation_time(&handle)? != self.created {
            return Err(AppError::new(format!(
                "{} has exited and PID {} now belongs to another process",
                self.name,
                self.pid.get()
            )));
        }
        Ok(handle)
    }
}

impl OwnedHandle {
    pub(crate) fn open(pid: ProcessId, rights: PROCESS_ACCESS_RIGHTS) -> AppResult<Self> {
        let handle = unsafe { OpenProcess(rights, false, pid.get()) }.map_err(|error| {
            if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
                let advice = match DEBUG_PRIVILEGE.get() {
                    Some(true) => "the process is protected, even from an administrator",
                    _ => "run mempe as administrator",
                };
                return AppError::new(format!("OpenProcess failed: {error}; {advice}"));
            }
            if error.code() == ERROR_INVALID_PARAMETER.to_hresult() {
                return AppError::new(format!("no process with PID {} is running", pid.get()));
            }
            windows_error("OpenProcess", error)
        })?;
        Ok(Self(handle))
    }

    pub(crate) fn adopt(handle: HANDLE) -> Self {
        Self(handle)
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

static DEBUG_PRIVILEGE: OnceLock<bool> = OnceLock::new();

pub(crate) fn enable_debug_privilege() {
    DEBUG_PRIVILEGE.get_or_init(debug_privilege_granted);
}

fn debug_privilege_granted() -> bool {
    let mut raw_token = HANDLE::default();
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut raw_token) };
    if opened.is_err() {
        return false;
    }

    let token = OwnedHandle(raw_token);
    let mut luid = LUID::default();

    if unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid) }.is_err() {
        return false;
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let adjusted =
        unsafe { AdjustTokenPrivileges(token.raw(), false, Some(&privileges), 0, None, None) };
    adjusted.is_ok() && unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED // succeeds without granting when not elevated
}

struct ProcessEntry {
    pid: ProcessId,
    name: String,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        information: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

const BASIC_INFORMATION: u32 = 0; // peb address is the second field
const WOW64_INFORMATION: u32 = 26; // 32-bit peb, zero when native
const PEB_IMAGE_BASE_64: usize = 0x10;
const PEB_IMAGE_BASE_32: usize = 0x08;

fn peb_image_base(pid: ProcessId) -> Option<usize> {
    let process =
        OwnedHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ).ok()?;
    let ask = |class: u32, answer: &mut [usize]| {
        let length = u32::try_from(size_of_val(answer)).ok()?;
        let status = unsafe {
            NtQueryInformationProcess(
                process.raw(),
                class,
                answer.as_mut_ptr().cast(),
                length,
                std::ptr::null_mut(),
            )
        };
        (status >= 0).then_some(())
    };

    let mut wow64 = [0usize; 1];
    ask(WOW64_INFORMATION, &mut wow64)?;
    if wow64[0] != 0 {
        let mut base = [0u8; 4];
        let field = wow64[0].checked_add(PEB_IMAGE_BASE_32)?;
        return read_memory(process.raw(), field, &mut base)
            .then(|| u32::from_le_bytes(base) as usize);
    }

    let mut basic = [0usize; 6];
    ask(BASIC_INFORMATION, &mut basic)?;
    let mut base = [0u8; 8];
    read_memory(
        process.raw(),
        basic[1].checked_add(PEB_IMAGE_BASE_64)?,
        &mut base,
    )
    .then(|| u64::from_le_bytes(base) as usize)
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
    let (modules, module_listing_error) = match listing {
        Ok(modules) => (modules, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let main_module = find_main_module(&path, &modules);
    let main_module_unlisted = main_module.is_none() && !modules.is_empty();

    Ok(TargetProcess {
        pid,
        name,
        path,
        architecture,
        created,
        main_module,
        modules,
        module_listing_error,
        image_base: peb_image_base(pid),
        main_module_unlisted,
    })
}

pub(crate) enum WatchNotice {
    Unreachable {
        pid: ProcessId,
        error: AppError,
    },
    ExitedBeforeCapture {
        pid: ProcessId,
    },
    SeveralMatched {
        chosen: ProcessId,
        others: Vec<ProcessId>,
    },
}

impl Display for WatchNotice {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { pid, error } => write!(
                formatter,
                "process {} matches but cannot be queried ({error}); it is tried again while it runs",
                pid.get()
            ),
            Self::ExitedBeforeCapture { pid } => write!(
                formatter,
                "process {} matched but exited before it could be captured, still waiting",
                pid.get()
            ),
            Self::SeveralMatched { chosen, others } => {
                let listed = others
                    .iter()
                    .map(|pid| pid.get().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    formatter,
                    "several new processes match; dumping the oldest, PID {}, and not PID {listed}; pass a PID to dump another",
                    chosen.get()
                )
            }
        }
    }
}

pub(crate) fn watch(name: &str, notify: &mut dyn FnMut(WatchNotice)) -> AppResult<TargetProcess> {
    let mut baseline = matching_pids(name, &list_processes()?);
    let mut reported = HashSet::new();
    let polls = WATCH_LIMIT.as_millis() / PROCESS_POLL_DELAY.as_millis();

    for _poll in 0..polls {
        let entries = list_processes()?;
        let current = matching_pids(name, &entries);
        baseline.retain(|pid| current.contains(pid));
        reported.retain(|pid| current.contains(pid));

        let (targets, unreachable) = query_new_targets(&current, &baseline);
        for (pid, error) in unreachable {
            if reported.insert(pid) {
                notify(WatchNotice::Unreachable { pid, error });
            }
        }

        if let Some(target) = oldest(targets) {
            wait_until_capture_time(target.created);

            match query(target.pid) {
                Ok(confirmed) if confirmed.created == target.created => {
                    let others = other_new_matches(name, &baseline, confirmed.pid)?;

                    if !others.is_empty() {
                        notify(WatchNotice::SeveralMatched {
                            chosen: confirmed.pid,
                            others,
                        });
                    }

                    return Ok(confirmed);
                }
                Ok(_) => notify(WatchNotice::ExitedBeforeCapture { pid: target.pid }),
                Err(error) if reported.insert(target.pid) => {
                    let pid = target.pid;
                    notify(WatchNotice::Unreachable { pid, error });
                }
                Err(_) => {}
            }
        }

        thread::sleep(PROCESS_POLL_DELAY);
    }

    Err(AppError::new(format!(
        "watch timed out after {} hours without a new matching process",
        WATCH_LIMIT.as_secs() / 3600
    )))
}

fn other_new_matches(
    name: &str,
    baseline: &HashSet<ProcessId>,
    chosen: ProcessId,
) -> AppResult<Vec<ProcessId>> {
    let current = matching_pids(name, &list_processes()?);
    let mut others = current
        .difference(baseline)
        .copied()
        .filter(|pid| *pid != chosen)
        .collect::<Vec<_>>();
    others.sort_unstable_by_key(|pid| pid.get());

    Ok(others)
}

fn oldest(targets: Vec<TargetProcess>) -> Option<TargetProcess> {
    targets
        .into_iter()
        .min_by_key(|target| (target.created, target.pid.get()))
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

fn query_new_targets(
    current: &HashSet<ProcessId>,
    baseline: &HashSet<ProcessId>,
) -> (Vec<TargetProcess>, Vec<(ProcessId, AppError)>) {
    let mut targets = Vec::new();
    let mut unreachable = Vec::new();
    for pid in current.difference(baseline) {
        match query(*pid) {
            Ok(target) => targets.push(target),
            Err(error) => unreachable.push((*pid, error)),
        }
    }

    (targets, unreachable)
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
    let path = buffer
        .get(..used)
        .ok_or_else(|| AppError::new("Windows returned an invalid process path length"))?;

    Ok(PathBuf::from(OsString::from_wide(path))) // not every ntfs name is valid utf-16
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

fn get_modules(pid: ProcessId) -> AppResult<Vec<LoadedModule>> {
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
    let rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    let denied = unsafe { OpenProcess(rights, false, pid.get()) }
        .map(OwnedHandle)
        .is_err_and(|refusal| refusal.code() == ERROR_ACCESS_DENIED.to_hresult());

    if !denied {
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

    Err(AppError::new(format!(
        "could not get a stable module list after {MAX_MODULE_SNAPSHOT_TRIES} tries"
    )))
}

fn module_from_entry(entry: &MODULEENTRY32W) -> LoadedModule {
    LoadedModule {
        name: wide_string(&entry.szModule),
        path: PathBuf::from(wide_string(&entry.szExePath)),
        base: entry.modBaseAddr as usize,
        size: entry.modBaseSize as usize,
    }
}

fn find_main_module(path: &Path, modules: &[LoadedModule]) -> Option<LoadedModule> {
    modules
        .iter()
        .find(|module| paths_equal(&module.path, path))
        .or_else(|| find_by_basename(path, modules))
        .cloned()
}

fn find_by_basename<'a>(path: &Path, modules: &'a [LoadedModule]) -> Option<&'a LoadedModule> {
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    volume: u32,
    index: u64,
}

impl FileIdentity {
    pub(crate) fn of(file: HANDLE) -> Option<Self> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(file, &mut info) }.ok()?;

        Some(Self {
            volume: info.dwVolumeSerialNumber,
            index: u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
        })
    }

    pub(crate) fn of_path(path: &Path) -> Option<Self> {
        let file = std::fs::File::open(path).ok()?;
        Self::of(HANDLE(file.as_raw_handle()))
    }
}

pub(crate) fn mapped_file_name(process: HANDLE, base: usize) -> Option<String> {
    let mut buffer = vec![0u16; MAX_PATH_CHARS];
    let length = unsafe { K32GetMappedFileNameW(process, base as *const c_void, &mut buffer) };
    let used = usize::try_from(length).ok()?;
    let path = String::from_utf16_lossy(buffer.get(..used)?);
    (!path.is_empty()).then_some(path)
}

pub(crate) fn read_memory(handle: HANDLE, address: usize, destination: &mut [u8]) -> bool {
    if destination.is_empty() {
        return true;
    }

    let mut read = 0usize;
    let result = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            destination.as_mut_ptr().cast(),
            destination.len(),
            Some(&mut read),
        )
    };

    result.is_ok() && read == destination.len()
}

#[derive(Clone, Copy, Hash)]
pub(crate) struct MemoryRegion {
    pub(crate) base: usize,
    pub(crate) allocation_base: usize,
    pub(crate) size: usize,
    pub(crate) state: u32,
    pub(crate) protect: u32,
    pub(crate) kind: u32,
}

impl MemoryRegion {
    pub(crate) fn end(&self) -> usize {
        self.base.saturating_add(self.size)
    }
}

pub(crate) fn query_region(process: HANDLE, address: usize) -> Option<MemoryRegion> {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    let length = size_of::<MEMORY_BASIC_INFORMATION>();
    let filled =
        unsafe { VirtualQueryEx(process, Some(address as *const c_void), &mut info, length) };

    (filled == length).then_some(MemoryRegion {
        base: info.BaseAddress as usize,
        allocation_base: info.AllocationBase as usize,
        size: info.RegionSize,
        state: info.State.0,
        protect: info.Protect.0,
        kind: info.Type.0,
    })
}

pub(crate) fn walk_regions(process: HANDLE, from: usize) -> impl Iterator<Item = MemoryRegion> {
    std::iter::successors(query_region(process, from), move |region| {
        query_region(process, region.end())
    })
    .take(MAX_REGIONS)
}

pub(crate) struct DriveMap(Vec<(String, String)>); // device, then drive

impl DriveMap {
    pub(crate) fn read() -> Self {
        let mask = unsafe { GetLogicalDrives() };
        let mut drives = Vec::new();
        for letter in b'A'..=b'Z' {
            if mask & (1u32 << (letter - b'A')) == 0 {
                continue;
            }

            let name = [u16::from(letter), u16::from(b':'), 0];
            let mut target = vec![0u16; MAX_PATH_CHARS];
            let length =
                unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(target.as_mut_slice())) };
            let device = wide_string(&target);

            if length != 0 && !device.is_empty() {
                drives.push((device, format!("{}:", char::from(letter))));
            }
        }

        Self(drives)
    }

    pub(crate) fn to_dos(&self, device: &str) -> Option<String> {
        self.0.iter().find_map(|(prefix, drive)| {
            let rest = device.strip_prefix(prefix.as_str())?;
            rest.starts_with('\\').then(|| format!("{drive}{rest}"))
        })
    }

    pub(crate) fn to_device(&self, path: &str) -> Option<String> {
        self.0.iter().find_map(|(device, drive)| {
            let (head, rest) = path.split_at_checked(drive.len())?;
            (head.eq_ignore_ascii_case(drive) && rest.starts_with('\\'))
                .then(|| format!("{device}{rest}"))
        })
    }
}

pub(crate) fn system_folder(kind: PeKind) -> Option<PathBuf> {
    let mut buffer = [0u16; MAX_PATH as usize]; // GetSystemWow64DirectoryW fails on a 32768 buffer
    let length = match kind {
        PeKind::Pe32Plus => unsafe { GetSystemDirectoryW(Some(&mut buffer)) },
        PeKind::Pe32 => unsafe { GetSystemWow64DirectoryW(Some(&mut buffer)) },
    } as usize;

    let folder = buffer.get(..length).filter(|_| length != 0)?;
    Some(PathBuf::from(OsString::from_wide(folder)))
}
