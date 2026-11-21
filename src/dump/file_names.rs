use std::path::{Path, PathBuf};

use crate::capture::CapturedImage;
use crate::process::TargetProcess;

pub(super) fn image_name(target: &TargetProcess, image: &CapturedImage) -> String {
    match (&image.name, image.is_main) {
        (_, true) => target.name.clone(),
        (Some(name), false) => name.clone(),
        (None, false) => unnamed_module(image.base),
    }
}

pub(super) fn embedded_label(target: &TargetProcess, image: &CapturedImage) -> String {
    let name = image_name(target, image);
    let stem = Path::new(&name).file_stem().and_then(|stem| stem.to_str());

    stem.unwrap_or(&name).to_owned()
}

pub(super) fn output_name(target: &TargetProcess, image: &CapturedImage, is_dll: bool) -> String {
    let extension = if is_dll { "dll" } else { "exe" };
    with_extension(&image_name(target, image), extension)
}

fn unnamed_module(base: usize) -> String {
    format!("module-{base:016X}")
}

pub(super) fn with_suffix(name: &str, tag: &str) -> String {
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(name);

    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => format!("{stem}{tag}.{extension}"),
        None => format!("{stem}{tag}"),
    }
}

fn with_extension(name: &str, extension: &str) -> String {
    let mut path = PathBuf::from(name);
    if path.extension().is_none() {
        path.set_extension(extension); // .pyd, .ocx, .cpl, .mui keep theirs
    }
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("dump.{extension}"))
}
