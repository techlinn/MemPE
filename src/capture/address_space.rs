use std::ffi::c_void;
use std::mem::size_of;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    HPSS, PSS_CAPTURE_VA_CLONE, PSS_CREATE_BREAKAWAY, PSS_CREATE_BREAKAWAY_OPTIONAL,
    PSS_CREATE_USE_VM_ALLOCATIONS, PSS_QUERY_VA_CLONE_INFORMATION, PSS_VA_CLONE_INFORMATION,
    PssCaptureSnapshot, PssFreeSnapshot, PssQuerySnapshot,
};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READONLY, VirtualProtectEx};
use windows::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use super::AcquisitionMode;
use super::{MemoryRegion, list_regions};
use crate::process::read_memory;
use crate::process::{OwnedHandle, TargetProcess};
use crate::{AppError, AppResult, win32_status};

pub(super) struct Snapshot {
    handle: HPSS,
    clone: HANDLE,
}

pub(super) enum AddressSpace {
    Snapshot(Snapshot),
    Live(OwnedHandle),
}

pub(super) struct OpenedAddressSpace {
    pub(super) space: AddressSpace,
    pub(super) mode: AcquisitionMode,
    pub(super) setup_elapsed: Duration,
    pub(super) fallback_reason: Option<String>,
}

impl Snapshot {
    fn capture(target: &TargetProcess) -> AppResult<(Self, Duration)> {
        let process = target
            .open(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)?;

        let flags = PSS_CAPTURE_VA_CLONE
            | PSS_CREATE_BREAKAWAY
            | PSS_CREATE_BREAKAWAY_OPTIONAL
            | PSS_CREATE_USE_VM_ALLOCATIONS;
        let buffer_length = u32::try_from(size_of::<PSS_VA_CLONE_INFORMATION>())
            .map_err(|_| AppError::new("PSS clone information size does not fit u32"))?;

        let started = Instant::now();
        let mut handle = HPSS::default();
        let status = unsafe { PssCaptureSnapshot(process.raw(), flags, None, &mut handle) };

        if status != ERROR_SUCCESS.0 {
            return Err(win32_status("PssCaptureSnapshot", status));
        }

        let elapsed = started.elapsed();
        let mut snapshot = Self {
            handle,
            clone: HANDLE::default(),
        };

        let mut clone = PSS_VA_CLONE_INFORMATION::default();
        let query_status = unsafe {
            PssQuerySnapshot(
                handle,
                PSS_QUERY_VA_CLONE_INFORMATION,
                (&raw mut clone).cast(),
                buffer_length,
            )
        };

        if query_status != ERROR_SUCCESS.0 {
            return Err(win32_status("PssQuerySnapshot", query_status));
        }

        if clone.VaCloneHandle.is_invalid() {
            return Err(AppError::new("PSS returned an invalid VA clone handle"));
        }

        snapshot.clone = clone.VaCloneHandle;
        Ok((snapshot, elapsed))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let status = unsafe { PssFreeSnapshot(GetCurrentProcess(), self.handle) };
        debug_assert_eq!(status, ERROR_SUCCESS.0);
    }
}

impl AddressSpace {
    pub(super) fn acquire(target: &TargetProcess) -> AppResult<OpenedAddressSpace> {
        match Snapshot::capture(target) {
            Ok((snapshot, setup_elapsed)) => Ok(OpenedAddressSpace {
                space: Self::Snapshot(snapshot),
                mode: AcquisitionMode::PssClone,
                setup_elapsed,
                fallback_reason: None,
            }),
            Err(snapshot_error) => {
                let started = Instant::now();
                let space = Self::open_live(target)?;
                Ok(OpenedAddressSpace {
                    space,
                    mode: AcquisitionMode::LiveRead,
                    setup_elapsed: started.elapsed(),
                    fallback_reason: Some(snapshot_error.to_string()),
                })
            }
        }
    }

    pub(super) fn open_live(target: &TargetProcess) -> AppResult<Self> {
        target
            .open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
            .map(Self::Live)
    }

    pub(super) fn handle(&self) -> HANDLE {
        match self {
            Self::Snapshot(snapshot) => snapshot.clone,
            Self::Live(process) => process.raw(),
        }
    }

    pub(super) fn make_readable(&self, address: usize, size: usize) -> bool {
        let Self::Snapshot(snapshot) = self else {
            return false;
        };

        let mut before = PAGE_PROTECTION_FLAGS::default();
        unsafe {
            VirtualProtectEx(
                snapshot.clone,
                address as *const c_void,
                size,
                PAGE_READONLY,
                &mut before,
            )
        }
        .is_ok()
    }

    pub(super) fn regions(&self) -> AppResult<Vec<MemoryRegion>> {
        list_regions(self.handle())
    }

    pub(super) fn read_exact(&self, address: usize, destination: &mut [u8]) -> bool {
        read_memory(self.handle(), address, destination)
    }
}
