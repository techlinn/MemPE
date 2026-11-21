use std::fmt::{Display, Formatter};

pub(crate) type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AppError(String);

impl AppError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

pub(crate) fn windows_error(action: &str, error: windows::core::Error) -> AppError {
    AppError::new(format!("{action} failed: {error}"))
}

pub(crate) fn win32_status(action: &str, status: u32) -> AppError {
    let detail = std::io::Error::from_raw_os_error(status as i32);
    AppError::new(format!("{action} failed: {detail} (error {status})"))
}
