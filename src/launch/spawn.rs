use std::collections::HashSet;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::ERROR_ELEVATION_REQUIRED;
use windows::Win32::System::Diagnostics::Debug::{
    DebugActiveProcessStop, DebugSetProcessKillOnExit,
};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, DEBUG_ONLY_THIS_PROCESS, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenThread, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW, SuspendThread, THREAD_SUSPEND_RESUME,
    TerminateProcess, UpdateProcThreadAttribute,
};
use windows::core::{PCWSTR, PWSTR};

use crate::pe::PeKind;
use crate::process::{OwnedHandle, system_folder, threads};
use crate::windows_error;
use crate::{AppError, AppResult};

const MITIGATION_DEP_ENABLE: u64 = 0x01; // x86 without dep runs non-exec pages
const NO_DEBUG_HEAP_VARIABLE: &str = "_NO_DEBUG_HEAP";
const MAX_FREEZE_PASSES: usize = 64;
pub(super) const SUSPEND_FAILED: u32 = u32::MAX;
const DLL_HOST: &str = "rundll32.exe";
const FIRST_EXPORT: &str = ",#1";

pub(super) struct ChildProcess {
    pub(super) process: OwnedHandle,
    pub(super) pid: u32,
    _job: OwnedHandle,
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = unsafe { TerminateProcess(self.process.raw(), 0) };
        let _ = unsafe { DebugActiveProcessStop(self.pid) };
    }
}

impl ChildProcess {
    pub(super) fn freeze(&self) -> AppResult<()> {
        let mut frozen = HashSet::new();

        for _pass in 0..MAX_FREEZE_PASSES {
            let fresh: Vec<u32> = threads(self.pid)?
                .into_iter()
                .filter(|thread| !frozen.contains(thread))
                .collect();
            if fresh.is_empty() && !frozen.is_empty() {
                return Ok(());
            }
            if fresh.is_empty() {
                break;
            }

            for id in fresh {
                let suspended = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, id) }
                    .map(OwnedHandle::adopt)
                    .is_ok_and(|thread| unsafe { SuspendThread(thread.raw()) } != SUSPEND_FAILED);
                if !suspended && threads(self.pid)?.contains(&id) {
                    return Err(not_frozen());
                }

                frozen.insert(id); // or it exited meanwhile
            }
        }

        Err(not_frozen())
    }
}

fn not_frozen() -> AppError {
    AppError::new(
        "the program reached its entry point, but not all of its threads could be suspended, so it was not safe to dump",
    )
}

pub(super) fn start(path: &Path, library: Option<PeKind>) -> AppResult<ChildProcess> {
    unsafe { std::env::set_var(NO_DEBUG_HEAP_VARIABLE, "1") }; // mempe has started no other thread yet

    let job = job()?;
    let info = match library {
        Some(kind) => create_process(&host(kind)?, Some(path), &job)?,
        None => create_process(path, None, &job)?,
    };
    let thread = OwnedHandle::adopt(info.hThread);
    let child = ChildProcess {
        process: OwnedHandle::adopt(info.hProcess),
        pid: info.dwProcessId,
        _job: job,
    };

    unsafe { DebugSetProcessKillOnExit(true) }
        .map_err(|error| windows_error("DebugSetProcessKillOnExit", error))?;
    unsafe { ResumeThread(thread.raw()) };
    Ok(child)
}

fn host(kind: PeKind) -> AppResult<PathBuf> {
    let folder = system_folder(kind)
        .ok_or_else(|| AppError::new("could not find the windows folder to host the dll"))?;

    Ok(folder.join(DLL_HOST))
}

fn create_process(
    path: &Path,
    library: Option<&Path>,
    job: &OwnedHandle,
) -> AppResult<PROCESS_INFORMATION> {
    let application = wide(path.as_os_str().encode_wide());
    let quoted = |path: &Path| {
        std::iter::once(u16::from(b'"'))
            .chain(path.as_os_str().encode_wide())
            .chain(std::iter::once(u16::from(b'"')))
            .collect::<Vec<u16>>()
    };
    let argument = library.map(|library| {
        let mut argument = vec![u16::from(b' ')];
        argument.extend(quoted(library));
        argument.extend(FIRST_EXPORT.encode_utf16()); // rundll32 needs an export, never reached
        argument
    });
    let mut command = wide(quoted(path).into_iter().chain(argument.unwrap_or_default()));
    let folder = library
        .unwrap_or(path)
        .parent()
        .map(|folder| wide(folder.as_os_str().encode_wide()));
    let folder = folder
        .as_ref()
        .filter(|folder| folder.len() > 1)
        .map_or(PCWSTR::null(), |folder| PCWSTR(folder.as_ptr()));

    let mut attributes = ProcThreadAttributes::new(2)?;
    let policy = MITIGATION_DEP_ENABLE;
    let jobs = [job.raw()];
    attributes.set(
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        (&raw const policy).cast(),
        size_of::<u64>(),
    )?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_JOB_LIST,
        jobs.as_ptr().cast(),
        size_of_val(&jobs),
    )?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.list();
    let mut info = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            None,
            folder,
            &startup.StartupInfo,
            &mut info,
        )
    }
    .map_err(|error| {
        if error.code() == ERROR_ELEVATION_REQUIRED.to_hresult() {
            return AppError::new(
                "the program asks for administrator rights; run mempe from an elevated terminal",
            );
        }
        windows_error("CreateProcessW", error)
    })?;

    Ok(info)
}

fn job() -> AppResult<OwnedHandle> {
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map(OwnedHandle::adopt)
        .map_err(|error| windows_error("CreateJobObjectW", error))?;

    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;

    unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|error| windows_error("SetInformationJobObject", error))?;

    Ok(job)
}

fn wide(text: impl Iterator<Item = u16>) -> Vec<u16> {
    text.chain(std::iter::once(0)).collect()
}

struct ProcThreadAttributes(Vec<u8>);

impl ProcThreadAttributes {
    fn new(count: u32) -> AppResult<Self> {
        let mut size = 0;
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut size) };

        let mut buffer = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &mut size) }
            .map_err(|error| windows_error("InitializeProcThreadAttributeList", error))?;
        Ok(Self(buffer))
    }

    // value must outlive CreateProcessW
    fn set(
        &mut self,
        attribute: u32,
        value: *const std::ffi::c_void,
        size: usize,
    ) -> AppResult<()> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list(),
                0,
                attribute as usize,
                Some(value),
                size,
                None,
                None,
            )
        }
        .map_err(|error| windows_error("UpdateProcThreadAttribute", error))
    }

    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.0.as_mut_ptr().cast())
    }
}

impl Drop for ProcThreadAttributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}
