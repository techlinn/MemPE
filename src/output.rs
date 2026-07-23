use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use crate::{AppError, AppResult};

const OUTPUT_DIRECTORY: &str = "mempe";
const MAX_NAME_CHARS: usize = 180;
const MAX_NAME_ATTEMPTS: u32 = 100_000;
const MAX_PROMPT_BYTES: usize = 16;
const MAX_TEMP_ATTEMPTS: usize = 1_024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CollisionPolicy {
    Overwrite,
    Rename,
}

pub(crate) struct OutputPlan {
    directory: PathBuf,
    policy: CollisionPolicy,
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
    final_path: PathBuf,
    saved: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.saved {
            let _ignored = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn prepare() -> AppResult<Option<OutputPlan>> {
    let directory = std::env::current_dir()
        .map_err(|error| AppError::new(format!("cannot get the current folder: {error}")))?
        .join(OUTPUT_DIRECTORY);
    if directory.exists() && !directory.is_dir() {
        return Err(AppError::new(format!(
            "{} exists but is not a directory",
            directory.display()
        )));
    }
    let has_entries = if directory.is_dir() {
        directory
            .read_dir()
            .map_err(|error| AppError::new(format!("cannot read mempe: {error}")))?
            .next()
            .transpose()
            .map_err(|error| AppError::new(format!("cannot read mempe: {error}")))?
            .is_some()
    } else {
        false
    };
    let policy = if has_entries {
        match collision_policy()? {
            Some(policy) => policy,
            None => return Ok(None),
        }
    } else {
        CollisionPolicy::Rename
    };
    fs::create_dir_all(&directory)
        .map_err(|error| AppError::new(format!("cannot create mempe: {error}")))?;
    Ok(Some(OutputPlan { directory, policy }))
}

impl OutputPlan {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn write_all<T>(&self, files: Vec<OutputFile<T>>) -> AppResult<Vec<WrittenFile<T>>> {
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let destinations = self.destinations(&files)?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(files.len())
            .map_err(|_| AppError::new("not enough memory for temporary files"))?;
        for (index, (file, destination)) in files.into_iter().zip(destinations).enumerate() {
            let (path, mut handle) = self.create_temporary(index)?;
            let temp_file = TempFile {
                path,
                final_path: destination,
                saved: false,
            };
            handle
                .write_all(&file.bytes)
                .and_then(|_| handle.flush())
                .map_err(|error| {
                    AppError::new(format!(
                        "cannot stage {}: {error}",
                        temp_file.final_path.display()
                    ))
                })?;
            staged.push((temp_file, file.context));
        }

        let mut written = Vec::with_capacity(staged.len());
        for (mut file, context) in staged {
            if file.final_path.exists() {
                if file.final_path.is_dir() {
                    return Err(AppError::new(format!(
                        "cannot replace directory {}",
                        file.final_path.display()
                    )));
                }
                if self.policy == CollisionPolicy::Overwrite {
                    fs::remove_file(&file.final_path).map_err(|error| {
                        AppError::new(format!(
                            "cannot replace {}: {error}",
                            file.final_path.display()
                        ))
                    })?;
                }
            }
            fs::rename(&file.path, &file.final_path).map_err(|error| {
                AppError::new(format!(
                    "cannot save {}: {error}",
                    file.final_path.display()
                ))
            })?;
            file.saved = true;
            written.push(WrittenFile {
                path: file.final_path.clone(),
                context,
            });
        }
        Ok(written)
    }

    fn destinations<T>(&self, files: &[OutputFile<T>]) -> AppResult<Vec<PathBuf>> {
        let mut used = HashSet::with_capacity(files.len());
        let mut destinations = Vec::with_capacity(files.len());
        for file in files {
            let name = clean_name(&file.preferred_name)?;
            let destination = self.unique_destination(&name, &mut used)?;
            destinations.push(destination);
        }
        Ok(destinations)
    }

    fn unique_destination(&self, name: &str, used: &mut HashSet<String>) -> AppResult<PathBuf> {
        for suffix in 1..=MAX_NAME_ATTEMPTS {
            let candidate = if suffix == 1 {
                name.to_owned()
            } else {
                suffixed_name(name, suffix)
            };
            let key = candidate.to_ascii_lowercase();
            let path = self.directory.join(&candidate);
            let occupied_by_disk = self.policy == CollisionPolicy::Rename && path.exists();
            if !occupied_by_disk && used.insert(key) {
                return Ok(path);
            }
        }
        Err(AppError::new("could not find a free output file name"))
    }

    fn create_temporary(&self, index: usize) -> AppResult<(PathBuf, File)> {
        let own_pid = std::process::id();
        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let name = format!(".mempe-{own_pid}-{index}-{attempt}.tmp");
            let path = self.directory.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(AppError::new(format!(
                        "cannot create a temporary file in mempe: {error}"
                    )));
                }
            }
        }
        Err(AppError::new(
            "could not make a temporary file after 1024 tries",
        ))
    }
}

fn collision_policy() -> AppResult<Option<CollisionPolicy>> {
    if !std::io::stdin().is_terminal() {
        return Ok(Some(CollisionPolicy::Rename));
    }
    print!(
        "mempe already contains files.\n[O]verwrite matching files, [R]ename conflicts, or [C]ancel? [R]: "
    );
    std::io::stdout()
        .flush()
        .map_err(|error| AppError::new(format!("cannot show the file prompt: {error}")))?;
    let input = read_prompt()?;
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "r" | "rename" => Ok(Some(CollisionPolicy::Rename)),
        "o" | "overwrite" => Ok(Some(CollisionPolicy::Overwrite)),
        "c" | "cancel" => Ok(None),
        _ => Err(AppError::new(
            "collision choice must be overwrite, rename, or cancel",
        )),
    }
}

fn read_prompt() -> AppResult<String> {
    let mut input = Vec::with_capacity(MAX_PROMPT_BYTES);
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin().lock();
    for _index in 0..MAX_PROMPT_BYTES {
        let read = stdin
            .read(&mut byte)
            .map_err(|error| AppError::new(format!("cannot read collision choice: {error}")))?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            input.push(byte[0]);
        }
    }
    String::from_utf8(input).map_err(|_| AppError::new("collision choice is not valid UTF-8"))
}

fn clean_name(name: &str) -> AppResult<String> {
    let basename = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::new("output file name is not valid text"))?;
    let mut cleaned = basename
        .chars()
        .take(MAX_NAME_CHARS)
        .map(|character| {
            if character.is_control() || "<>:\"/\\|?*".contains(character) {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
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

fn is_reserved_windows_name(name: &str) -> bool {
    let stem = Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .and_then(|number| number.parse::<u8>().ok())
            .is_some_and(|number| (1..=9).contains(&number))
}

fn suffixed_name(name: &str, suffix: u32) -> String {
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    match path.extension().and_then(|value| value.to_str()) {
        Some(extension) => format!("{stem}_{suffix}.{extension}"),
        None => format!("{stem}_{suffix}"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{CollisionPolicy, OutputFile, OutputPlan, clean_name, suffixed_name};

    #[test]
    fn cleans_windows_names() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(clean_name("C:\\bad<name>.dll")?, "bad_name_.dll");
        assert_eq!(clean_name("CON.dll")?, "_CON.dll");
        Ok(())
    }

    #[test]
    fn suffix_stays_before_extension() {
        assert_eq!(suffixed_name("kernel32.dll", 2), "kernel32_2.dll");
        assert_eq!(suffixed_name("module", 3), "module_3");
    }

    #[test]
    fn preserves_context_through_writes() -> Result<(), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory =
            std::env::temp_dir().join(format!("mempe-output-test-{}-{unique}", std::process::id()));
        fs::create_dir(&directory)?;
        let plan = OutputPlan {
            directory: directory.clone(),
            policy: CollisionPolicy::Rename,
        };
        let files = vec![
            OutputFile {
                preferred_name: "first.exe".to_owned(),
                bytes: vec![1],
                context: 41u32,
            },
            OutputFile {
                preferred_name: "second.dll".to_owned(),
                bytes: vec![2],
                context: 42u32,
            },
        ];

        let written = plan.write_all(files)?;

        assert_eq!(written.len(), 2);
        assert_eq!(written[0].context, 41);
        assert_eq!(written[1].context, 42);
        assert_eq!(fs::read(&written[0].path)?, [1]);
        assert_eq!(fs::read(&written[1].path)?, [2]);
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
