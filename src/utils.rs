use std::fs;
use std::path::PathBuf;
use std::thread;

use anyhow::{Result, anyhow};
use arboard::Clipboard;
use bincode::{config, decode_from_slice, encode_to_vec};
use directories::ProjectDirs;
use log::info;
use rand::{Rng, rng};

use crate::db_models::{AppConfig, RecentEntry};

// --- Config Helpers ---

fn config_path() -> Result<PathBuf> {
    let proj =
        ProjectDirs::from("com", "Aegis", "Aegis").ok_or_else(|| anyhow!("no config dir"))?;
    let dir = proj.config_dir();
    fs::create_dir_all(dir).ok();
    Ok(dir.join("config.json"))
}

pub fn load_config() -> AppConfig {
    if let Ok(path) = config_path() {
        if let Ok(bytes) = fs::read(path) {
            // FIX: Use bincode instead of serde_json
            let config = config::standard();
            if let Ok((cfg, _)) = decode_from_slice::<AppConfig, _>(&bytes, config) {
                return cfg;
            }
        }
    }
    AppConfig::default()
}

pub fn save_config(cfg: &AppConfig) {
    if let Ok(path) = config_path() {
        // FIX: Use bincode instead of serde_json
        let config = config::standard();
        if let Ok(bytes) = encode_to_vec(cfg, config) {
            let _ = fs::write(path, bytes);
        }
    }
}

// --- Recent Entries Helper ---

pub fn update_recent(recents: &mut Vec<RecentEntry>, path: PathBuf, keyfile: Option<PathBuf>) {
    recents.retain(|e| e.db_path != path);
    recents.insert(
        0,
        RecentEntry {
            db_path: path,
            keyfile_path: keyfile,
        },
    );
    if recents.len() > 10 {
        recents.truncate(10);
    }
}

// --- Password Helpers ---

pub fn generate_password(len: usize) -> String {
    const CHARS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?,.";
    let mut rng = rng();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.random_range(0..CHARS.len());
        out.push(CHARS[idx] as char);
    }
    out
}

/// basic scoring 0..6
pub fn password_strength(pw: &str) -> u8 {
    let mut score = 0u8;
    if pw.len() >= 8 {
        score += 1;
    }
    if pw.len() >= 12 {
        score += 1;
    }
    if pw.chars().any(|c| c.is_lowercase()) {
        score += 1;
    }
    if pw.chars().any(|c| c.is_uppercase()) {
        score += 1;
    }
    if pw.chars().any(|c| c.is_numeric()) {
        score += 1;
    }
    if pw.chars().any(|c| !c.is_alphanumeric()) {
        score += 1;
    }
    score
}

// --- Clipboard Helpers ---

/// copy to clipboard
fn copy_to_clipboard(s: &str) -> Result<()> {
    let mut clip = Clipboard::new().map_err(|e| anyhow!("clipboard init: {}", e))?;
    clip.set_text(s.to_string())
        .map_err(|e| anyhow!("clipboard set: {}", e))?;
    Ok(())
}

/// copy and auto-clear clipboard after `seconds`
pub fn copy_to_clipboard_timed(s: &str, seconds: u64) -> Result<()> {
    copy_to_clipboard(s)?;
    info!("password copied to clipboard (will clear in {}s)", seconds);
    // spawn thread to clear clipboard after seconds
    let s_owned = s.to_string();
    thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
        if let Ok(mut cb) = Clipboard::new() {
            // best-effort: clear contents
            let _ = cb.set_text(String::new());
        } else {
            // nothing we can do
            let _ = s_owned; // keep variable maybe for debug if needed
        }
    });
    Ok(())
}
