use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnonError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Auth error: {0}")]
    Auth(String),
    #[error("Database error: {0}")]
    Db(String),
}