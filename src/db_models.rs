use bincode::{Decode, Encode};
use chrono::{DateTime, Utc};
use std::path::PathBuf;

pub const MAGIC: &[u8; 7] = b"AEGISDB";
pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

#[derive(Encode, Decode, Debug, Clone)]
pub struct Account {
    pub account_id: String,
    pub username: String,
    pub password_b64: String,
    pub pwd_salt_b64: String,
    pub pwd_nonce_b64: String,

    #[bincode(with_serde)]
    pub created_at: DateTime<Utc>,

    pub tags: Vec<String>,
    pub category: Option<String>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            username: String::new(),
            password_b64: String::new(),
            pwd_salt_b64: String::new(),
            pwd_nonce_b64: String::new(),
            created_at: Utc::now(),
            tags: Vec::new(),
            category: None,
        }
    }
}

#[derive(Encode, Decode, Debug, Default, Clone)]
pub struct Database {
    pub accounts: Vec<Account>,
}

#[derive(Encode, Decode, Clone, Default)]
pub struct RecentEntry {
    pub db_path: PathBuf,
    pub keyfile_path: Option<PathBuf>,
}

#[derive(Encode, Decode, Default, Clone)]
pub struct AppConfig {
    pub recents: Vec<RecentEntry>,
}
