use std::sync::OnceLock;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::MEM_IMAGE;

use crate::pe::{NTDLL, PeKind};
use crate::process::{DriveMap, mapped_file_name, query_region, system_folder, walk_regions};
use crate::{AppError, AppResult};

const KERNEL32: &str = "kernel32.dll";

// device paths, as mapped files are named
pub(super) struct SystemFolders {
    native: String,
    wow64: String,
}

static SYSTEM_FOLDERS: OnceLock<Option<SystemFolders>> = OnceLock::new();

impl SystemFolders {
    fn find() -> Option<Self> {
        let drives = DriveMap::read();
        let device = |kind| drives.to_device(system_folder(kind)?.to_str()?);

        Some(Self {
            native: device(PeKind::Pe32Plus)?,
            wow64: device(PeKind::Pe32)?,
        })
    }

    fn known() -> Option<&'static Self> {
        SYSTEM_FOLDERS.get_or_init(Self::find).as_ref()
    }

    fn of(&self, kind: PeKind) -> &str {
        match kind {
            PeKind::Pe32Plus => &self.native,
            PeKind::Pe32 => &self.wow64,
        }
    }

    fn holds(&self, path: &str, files: &[&str]) -> bool {
        [&self.native, &self.wow64]
            .into_iter()
            .any(|folder| is_file_in(folder, path, files))
    }
}

pub(super) fn system_folders() -> AppResult<&'static SystemFolders> {
    SystemFolders::known().ok_or_else(|| {
        AppError::new(
            "could not find the windows system folders, so windows' own code cannot be told from the program's",
        )
    })
}

pub(super) fn find_ntdll(process: HANDLE, kind: PeKind) -> Option<usize> {
    let folder = SystemFolders::known()?.of(kind);

    walk_regions(process, 0)
        .find(|found| {
            found.kind == MEM_IMAGE.0
                && found.base == found.allocation_base
                && mapped_file_name(process, found.base)
                    .is_some_and(|path| is_file_in(folder, &path, &[NTDLL]))
        })
        .map(|found| found.base)
}

pub(super) fn is_native_ntdll(process: HANDLE, base: usize) -> bool {
    let Some(folders) = SystemFolders::known() else {
        return false;
    };

    mapped_file_name(process, base)
        .is_some_and(|path| is_file_in(folders.of(PeKind::Pe32Plus), &path, &[NTDLL]))
}

pub(super) fn in_ntdll(process: HANDLE, address: usize) -> bool {
    in_system_file(process, address, &[NTDLL])
}

pub(super) fn in_start_module(process: HANDLE, address: usize) -> bool {
    in_system_file(process, address, &[NTDLL, KERNEL32])
}

fn in_system_file(process: HANDLE, address: usize, files: &[&str]) -> bool {
    let Some(folders) = SystemFolders::known() else {
        return false;
    };

    query_region(process, address).is_some_and(|found| {
        found.kind == MEM_IMAGE.0
            && mapped_file_name(process, found.allocation_base)
                .is_some_and(|path| folders.holds(&path, files))
    })
}

fn is_file_in(folder: &str, path: &str, files: &[&str]) -> bool {
    let Some((head, tail)) = path.split_at_checked(folder.len()) else {
        return false;
    };
    let Some(file) = tail.strip_prefix('\\') else {
        return false;
    };

    head.eq_ignore_ascii_case(folder) && files.iter().any(|name| file.eq_ignore_ascii_case(name))
}
