use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use super::file_names::with_suffix;
use crate::{AppError, AppResult};

const OUTPUT_DIRECTORY: &str = "mempe";
const MAX_NAME_CHARS: usize = 180;
const MAX_NAME_ATTEMPTS: u32 = 100_000;
const MAX_TEMP_ATTEMPTS: usize = 1_024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CollisionPolicy {
    Overwrite,
    Rename,
}

pub(crate) struct OutputFolder {
    directory: PathBuf,
    policy: CollisionPolicy,
    used: HashSet<String>,
    created: bool,
}

impl Drop for OutputFolder {
    fn drop(&mut self) {
        if self.created {
            let _ignored = fs::remove_dir(&self.directory); // fails unless empty
        }
    }
}

pub(crate) struct OutputFile<T> {
    pub(crate) preferred_name: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) context: T,
}

pub(crate) struct WrittenFile<T> {
    pub(crate) path: PathBuf,
    pub(crate) context: T,
}

struct TempFile {
    path: PathBuf,
    saved: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.saved {
            let _ignored = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn prepare(folder: Option<PathBuf>) -> AppResult<Option<OutputFolder>> {
    let directory = match folder {
        Some(folder) => folder,
        None => std::env::current_dir()
            .map_err(|error| AppError::new(format!("cannot get the current folder: {error}")))?
            .join(OUTPUT_DIRECTORY),
    };
    let shown = directory.display();
    if directory.exists() && !directory.is_dir() {
        return Err(AppError::new(format!(
            "{shown} exists but is not a directory"
        )));
    }

    let unreadable =
        |error| AppError::new(format!("cannot read the output folder {shown}: {error}"));
    let has_entries = match directory.is_dir() {
        true => directory
            .read_dir()
            .map_err(unreadable)?
            .next()
            .transpose()
            .map_err(unreadable)?
            .is_some(),
        false => false,
    };

    let policy = if has_entries {
        match collision_policy(&directory)? {
            Some(policy) => policy,
            None => return Ok(None),
        }
    } else {
        CollisionPolicy::Rename
    };

    let created = !directory.is_dir();
    fs::create_dir_all(&directory).map_err(|error| {
        AppError::new(format!("cannot create the output folder {shown}: {error}"))
    })?;
    let output = OutputFolder {
        directory,
        policy,
        used: HashSet::new(),
        created,
    };

    let (probe, _file) = output.create_temporary()?;
    let _ignored = fs::remove_file(probe);

    Ok(Some(output))
}

impl OutputFolder {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn write<T>(&mut self, file: OutputFile<T>) -> AppResult<WrittenFile<T>> {
        let name = clean_name(&file.preferred_name)?;
        let final_path = self.unique_destination(&name)?;
        let (path, mut handle) = self.create_temporary()?;
        let mut staged = TempFile { path, saved: false };

        handle
            .write_all(&file.bytes)
            .and_then(|_| handle.flush())
            .map_err(|error| AppError::new(format!("cannot write {name}: {error}")))?;
        drop(handle);

        if final_path.is_dir() {
            return Err(AppError::new(format!("{name} is a folder there already")));
        }
        if final_path.exists() && self.policy == CollisionPolicy::Overwrite {
            fs::remove_file(&final_path)
                .map_err(|error| AppError::new(format!("cannot replace {name}: {error}")))?;
        }

        fs::rename(&staged.path, &final_path)
            .map_err(|error| AppError::new(format!("cannot save {name}: {error}")))?;
        staged.saved = true;

        Ok(WrittenFile {
            path: final_path,
            context: file.context,
        })
    }

    fn unique_destination(&mut self, name: &str) -> AppResult<PathBuf> {
        for suffix in 1..=MAX_NAME_ATTEMPTS {
            let candidate = if suffix == 1 {
                name.to_owned()
            } else {
                with_suffix(name, &format!("_{suffix}"))
            };

            let key = candidate.to_lowercase(); // ntfs folds more than ascii
            let path = self.directory.join(&candidate);
            let occupied_by_disk = self.policy == CollisionPolicy::Rename && path.exists();

            if !occupied_by_disk && self.used.insert(key) {
                return Ok(path);
            }
        }

        Err(AppError::new("could not find a free output file name"))
    }

    fn create_temporary(&self) -> AppResult<(PathBuf, File)> {
        let own_pid = std::process::id();

        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let name = format!(".mempe-{own_pid}-{attempt}.tmp");
            let path = self.directory.join(name);

            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(AppError::new(format!(
                        "cannot create a file in {}: {error}",
                        self.directory.display()
                    )));
                }
            }
        }

        Err(AppError::new(format!(
            "could not make a temporary file after {MAX_TEMP_ATTEMPTS} tries"
        )))
    }
}

fn collision_policy(directory: &Path) -> AppResult<Option<CollisionPolicy>> {
    if !std::io::stdin().is_terminal() {
        return Ok(Some(CollisionPolicy::Rename));
    }

    println!("{} already contains files.", directory.display());
    ask(
        "[O]verwrite matching files, [R]ename conflicts, or [C]ancel? [R]: ",
        |answer| match answer {
            "" | "r" | "rename" => Some(Some(CollisionPolicy::Rename)),
            "o" | "overwrite" => Some(Some(CollisionPolicy::Overwrite)),
            "c" | "cancel" => Some(None),
            _ => None,
        },
    )
}

pub(crate) fn wants_fresh_copies(changes: &[(String, usize)]) -> AppResult<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(true);
    }

    for (name, changed) in changes {
        println!("{name} changed {changed} bytes of its data since it started.");
    }

    let copies = match changes.len() {
        1 => "a copy",
        _ => "copies",
    };
    ask(
        &format!(
            "Also save {copies} with the starting data put back, which is more likely to run on its own? [Y/n]: "
        ),
        |answer| match answer {
            "" | "y" | "yes" => Some(true),
            "n" | "no" => Some(false),
            _ => None,
        },
    )
}

fn ask<T>(question: &str, choice: impl Fn(&str) -> Option<T>) -> AppResult<T> {
    loop {
        print!("{question}");
        std::io::stdout()
            .flush()
            .map_err(|error| AppError::new(format!("cannot show the question: {error}")))?;

        let mut line = String::new();
        let read = std::io::stdin()
            .read_line(&mut line)
            .map_err(|error| AppError::new(format!("cannot read the answer: {error}")))?;

        if read == 0 {
            return Err(AppError::new("the input ended before an answer was given"));
        }
        if let Some(answer) = choice(line.trim().to_ascii_lowercase().as_str()) {
            return Ok(answer);
        }
        println!("That is not one of the choices.");
    }
}

fn clean_name(name: &str) -> AppResult<String> {
    let basename = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::new("output file name is not valid text"))?;
    let replaced = basename
        .chars()
        .map(|character| {
            if character.is_control() || "<>:\"/\\|?*".contains(character) {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();

    let mut cleaned = shortened(&replaced);
    while cleaned.ends_with([' ', '.']) {
        cleaned.pop();
    }

    if cleaned.is_empty() {
        return Err(AppError::new("output file name is empty"));
    }

    if is_reserved_windows_name(&cleaned) {
        cleaned.insert(0, '_');
    }

    Ok(cleaned)
}

fn shortened(name: &str) -> String {
    let length = name.chars().count();
    if length <= MAX_NAME_CHARS {
        return name.to_owned();
    }

    let extension = name
        .rfind('.')
        .and_then(|dot| name.get(dot..))
        .filter(|extension| extension.chars().count() < MAX_NAME_CHARS)
        .unwrap_or_default();
    let kept = MAX_NAME_CHARS.saturating_sub(extension.chars().count());

    name.chars().take(kept).chain(extension.chars()).collect()
}

fn is_reserved_windows_name(name: &str) -> bool {
    // a device name ends at the first dot, whatever follows
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .and_then(|number| number.parse::<u8>().ok())
            .is_some_and(|number| (1..=9).contains(&number))
}
