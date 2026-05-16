use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl AppError {
    pub fn status_code(&self) -> u16 {
        match self {
            AppError::Internal(_)   => 500,
            AppError::NotFound(_)   => 404,
            AppError::BadRequest(_) => 400,
        }
    }
}
