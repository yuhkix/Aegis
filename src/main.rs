use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use bincode::{deserialize, serialize};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use rand::{Rng, RngCore};
use rpassword::read_password;
use serde::{Deserialize, Serialize};

use arboard::Clipboard;
use eframe::egui;

/// file format constants
const MAGIC: &[u8; 7] = b"AEGISDB";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// account with per-field encryption for password
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Account {
    account_id: String,
    username: String,
    password_b64: String,
    pwd_salt_b64: String,
    pwd_nonce_b64: String,

    created_at: DateTime<Utc>,

    tags: Vec<String>,
    category: Option<String>,
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

/// database envelope (we still encrypt entire serialized DB to add an outer envelope)
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Database {
    accounts: Vec<Account>,
}

#[derive(Parser)]
#[command(name = "aegis")]
#[command(about = "Password DB with per-field encryption, tags, search and eframe GUI")]
struct Cli {
    /// path to database file
    #[arg(short, long, default_value = "aegis.bin")]
    file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        #[arg(short, long)]
        account_id: Option<String>,
        #[arg(short, long)]
        tags: Option<String>,
        #[arg(short, long)]
        category: Option<String>,
    },
    List {
        #[arg(short, long)]
        tag: Option<String>,
        #[arg(short, long)]
        category: Option<String>,
        #[arg(short, long)]
        search: Option<String>,
    },
    Get {
        account_id: String,
        #[arg(short, long)]
        copy: bool,
    },
    Remove {
        account_id: String,
    },
    Gen {
        #[arg(short, long, default_value_t = 16)]
        length: usize,
        #[arg(short, long)]
        copy: bool,
    },
    Changemaster,
    Gui,
}

/// derive a 32 byte key via argon2 (master + salt)
fn derive_key(master: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(master.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("KDF failure: {}", e))?;
    Ok(out)
}

/// encrypt the entire DB with a file-level salt + nonce envelope
fn encrypt_db(db: &Database, master: &str) -> Result<Vec<u8>> {
    // use bincode for compactness
    let serialized = serialize(db).context("serializing db with bincode")?;

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let key_bytes = derive_key(master, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_obj = XNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_obj, serialized.as_ref())
        .map_err(|e| anyhow!("file encryption failed: {}", e))?;

    // layout: MAGIC | VER | SALT_LEN | salt | NONCE_LEN | nonce | ciphertext
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.push(NONCE_LEN as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// eecrypt file envelope and return database
fn decrypt_db_file(bytes: &[u8], master: &str) -> Result<Database> {
    if bytes.len() < MAGIC.len() + 7 {
        anyhow::bail!("file too small or corrupt");
    }
    if &bytes[0..MAGIC.len()] != MAGIC {
        anyhow::bail!("not a AEGISDB file (magic mismatch)");
    }

    let mut idx = MAGIC.len();
    let ver = bytes[idx];
    idx += 1;
    if ver != VERSION {
        anyhow::bail!("unsupported version: {}", ver);
    }
    // rest remains the same
    let salt_len = bytes[idx] as usize;
    idx += 1;
    if idx + salt_len > bytes.len() {
        anyhow::bail!("corrupt salt");
    }
    let salt = &bytes[idx..idx + salt_len];
    idx += salt_len;
    let nonce_len = bytes[idx] as usize;
    idx += 1;
    if idx + nonce_len > bytes.len() {
        anyhow::bail!("corrupt nonce");
    }
    let nonce = &bytes[idx..idx + nonce_len];
    idx += nonce_len;
    let ciphertext = &bytes[idx..];

    let key_bytes = derive_key(master, salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_obj = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce_obj, ciphertext.as_ref())
        .map_err(|e| anyhow!("file decryption failed: {}", e))?;
    let db: Database = deserialize(&plaintext).context("deserialize bincode")?;
    Ok(db)
}

fn read_db(path: &PathBuf, master: &str) -> Result<Database> {
    let mut f = File::open(path).context("open db file")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    decrypt_db_file(&buf, master)
}

fn write_db(path: &PathBuf, db: &Database, master: &str) -> Result<()> {
    let encrypted = encrypt_db(db, master)?;
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .context("open db file for write")?;
    f.write_all(&encrypted)?;
    Ok(())
}

fn prompt_master(confirm: bool) -> String {
    loop {
        eprint!("Master password: ");
        let p = read_password().expect("Failed to read password");
        if p.is_empty() {
            println!("password cannot be empty");
            continue;
        }
        if confirm {
            eprint!("Confirm master password: ");
            let p2 = read_password().expect("Failed to read password");
            if p != p2 {
                println!("Passwords do not match, try again.");
                continue;
            }
        }
        return p;
    }
}

fn prompt(prompt_text: &str) -> String {
    use std::io::{Write, stdin, stdout};
    let mut s = String::new();
    print!("{}: ", prompt_text);
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("input failed");
    s.trim().to_string()
}

fn generate_password(len: usize) -> String {
    const CHARS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?,.";
    let mut rng = rand::rng();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.random_range(0..CHARS.len());
        out.push(CHARS[idx] as char);
    }
    out
}

/// basic scoring 0..6
fn password_strength(pw: &str) -> u8 {
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

/// copy to clipboard
fn copy_to_clipboard(s: &str) -> Result<()> {
    let mut clip = Clipboard::new().map_err(|e| anyhow!("clipboard init: {}", e))?;
    clip.set_text(s.to_string())
        .map_err(|e| anyhow!("clipboard set: {}", e))?;
    Ok(())
}

/// copy and auto-clear clipboard after `seconds`
fn copy_to_clipboard_timed(s: &str, seconds: u64) -> Result<()> {
    copy_to_clipboard(s)?;
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

/// encrypt a plaintext password with per account salt+nonce (returns base64 triple)
fn encrypt_password_field(
    master: &str,
    account_id: &str,
    plaintext: &str,
) -> Result<(String, String, String)> {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let key_bytes = derive_key(&format!("{}:{}", master, account_id), &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_obj = XNonce::from_slice(&nonce);

    let ct = cipher
        .encrypt(nonce_obj, plaintext.as_bytes())
        .map_err(|e| anyhow!("field encryption failed: {}", e))?;
    Ok((
        general_purpose::STANDARD.encode(ct),
        general_purpose::STANDARD.encode(salt),
        general_purpose::STANDARD.encode(nonce),
    ))
}

/// decrypt per account password field
fn decrypt_password_field(
    master: &str,
    account_id: &str,
    ct_b64: &str,
    salt_b64: &str,
    nonce_b64: &str,
) -> Result<String> {
    let ct = general_purpose::STANDARD
        .decode(ct_b64)
        .map_err(|e| anyhow!("ct b64: {}", e))?;
    let salt = general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|e| anyhow!("salt b64: {}", e))?;
    let nonce = general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|e| anyhow!("nonce b64: {}", e))?;

    let key_bytes = derive_key(&format!("{}:{}", master, account_id), &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_obj = XNonce::from_slice(&nonce);

    let pt = cipher
        .decrypt(nonce_obj, ct.as_ref())
        .map_err(|e| anyhow!("field decryption failed: {}", e))?;
    String::from_utf8(pt).map_err(|e| anyhow!("utf8 decode: {}", e))
}

/// find mutable account by id (explicit lifetime)
#[allow(dead_code)]
fn find_account_mut<'a>(db: &'a mut Database, id: &str) -> Option<&'a mut Account> {
    db.accounts.iter_mut().find(|a| a.account_id == id)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => {
            if cli.file.exists() {
                return Err(anyhow!("file already exists: {}", cli.file.display()));
            }
            println!("Creating new password database: {}", cli.file.display());
            let master = prompt_master(true);
            let db = Database::default();
            write_db(&cli.file, &db, &master)?;
            println!("Created and encrypted database.");
        }

        Commands::Add { account_id, .. } => {
            if !cli.file.exists() {
                return Err(anyhow!("database file not found. run --file <path> init"));
            }
            let master = prompt_master(false);
            let mut db = read_db(&cli.file, &master)?;

            let accid = account_id.clone().unwrap_or_else(|| prompt("Account ID"));
            let username = prompt("Username / Email");

            eprint!("Password (leave empty to generate): ");
            let mut pw = read_password().unwrap_or_default();
            if pw.trim().is_empty() {
                let generated = generate_password(16);
                println!("Generated password: {}", generated);
                pw = generated;
            }

            let (cipher_b64, salt_b64, nonce_b64) = encrypt_password_field(&master, &accid, &pw)?;
            let tags = prompt("Tags (comma separated, leave empty for none)");
            let tags_vec = if tags.trim().is_empty() {
                vec![]
            } else {
                tags.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            let category = prompt("Category (optional, leave empty)");
            let category = if category.trim().is_empty() {
                None
            } else {
                Some(category)
            };

            let acc = Account {
                account_id: accid,
                username,
                password_b64: cipher_b64,
                pwd_salt_b64: salt_b64,
                pwd_nonce_b64: nonce_b64,
                created_at: Utc::now(),
                tags: tags_vec,
                category,
            };

            db.accounts.push(acc);
            write_db(&cli.file, &db, &master)?;
            println!("Account added.");
        }

        Commands::List {
            tag,
            category,
            search,
        } => {
            if !cli.file.exists() {
                return Err(anyhow!("database file not found. run init first"));
            }
            let master = prompt_master(false);
            let db = read_db(&cli.file, &master)?;

            println!("Accounts ({}):", db.accounts.len());
            for a in db.accounts.iter().filter(|a| {
                if let Some(t) = tag {
                    if !a.tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                        return false;
                    }
                }
                if let Some(c) = category {
                    if a.category.as_ref().map(|s| s.to_lowercase()) != Some(c.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(s) = search {
                    let s_l = s.to_lowercase();
                    if !a.account_id.to_lowercase().contains(&s_l)
                        && !a.username.to_lowercase().contains(&s_l)
                    {
                        return false;
                    }
                }
                true
            }) {
                println!(
                    "- {} (username: {}) [tags: {}] [category: {}]",
                    a.account_id,
                    a.username,
                    if a.tags.is_empty() {
                        "-".into()
                    } else {
                        a.tags.join(", ")
                    },
                    a.category.clone().unwrap_or_else(|| "-".into())
                );
            }
        }

        Commands::Get { account_id, copy } => {
            if !cli.file.exists() {
                return Err(anyhow!("database file not found."));
            }
            let master = prompt_master(false);
            let db = read_db(&cli.file, &master)?;
            if let Some(a) = db.accounts.iter().find(|x| &x.account_id == account_id) {
                let pw = decrypt_password_field(
                    &master,
                    &a.account_id,
                    &a.password_b64,
                    &a.pwd_salt_b64,
                    &a.pwd_nonce_b64,
                )?;
                println!("Account: {}", a.account_id);
                println!("Username: {}", a.username);
                println!(
                    "Password: {}",
                    if *copy { "(copied to clipboard)" } else { &pw }
                );
                println!(
                    "Tags: {}",
                    if a.tags.is_empty() {
                        "-".into()
                    } else {
                        a.tags.join(", ")
                    }
                );
                println!(
                    "Category: {}",
                    a.category.clone().unwrap_or_else(|| "-".into())
                );
                println!("Created: {}", a.created_at);
                let score = password_strength(&pw);
                println!("Strength: {}/6", score);
                if *copy {
                    copy_to_clipboard_timed(&pw, 10)?;
                    println!("Password copied to clipboard (will clear after 10s).");
                }
            } else {
                println!("not found");
            }
        }

        Commands::Remove { account_id } => {
            if !cli.file.exists() {
                return Err(anyhow!("database file not found."));
            }
            let master = prompt_master(false);
            let mut db = read_db(&cli.file, &master)?;
            let before = db.accounts.len();
            db.accounts.retain(|x| &x.account_id != account_id);
            if db.accounts.len() == before {
                println!("no account removed (not found)");
            } else {
                write_db(&cli.file, &db, &master)?;
                println!("removed");
            }
        }

        Commands::Gen { length, copy } => {
            let pw = generate_password(*length);
            let score = password_strength(&pw);
            println!("Generated: {}", pw);
            println!("Strength: {}/6", score);
            if *copy {
                copy_to_clipboard_timed(&pw, 10)?;
                println!("Password copied to clipboard (will clear after 10s).");
            }
        }

        Commands::Changemaster => {
            if !cli.file.exists() {
                return Err(anyhow!("database file not found."));
            }
            println!("You will be asked for the current master, then the new one.");
            let old = prompt_master(false);
            let db = read_db(&cli.file, &old)?; // verify old master
            println!("Enter new master password:");
            let new = prompt_master(true);

            // re-encrypt every per account field with the new master (atomic in-memory)
            let mut new_db = db.clone();
            for acc in new_db.accounts.iter_mut() {
                // decrypt with old master
                let dec = decrypt_password_field(
                    &old,
                    &acc.account_id,
                    &acc.password_b64,
                    &acc.pwd_salt_b64,
                    &acc.pwd_nonce_b64,
                )?;
                // re-encrypt with new master
                let (cipher_b64, salt_b64, nonce_b64) =
                    encrypt_password_field(&new, &acc.account_id, &dec)?;
                acc.password_b64 = cipher_b64;
                acc.pwd_salt_b64 = salt_b64;
                acc.pwd_nonce_b64 = nonce_b64;
            }

            // write DB envelope encrypted under new master
            write_db(&cli.file, &new_db, &new)?;
            println!("Master password changed.");
        }

        Commands::Gui => {
            if !cli.file.exists() {
                return Err(anyhow!("database file not found."));
            }
            let master = prompt_master(false);
            let db = read_db(&cli.file, &master)?;

            #[derive(Default)]
            struct GuiState {
                accounts: Vec<Account>,
                master: String,
                db_path: PathBuf,
                // ui state
                filter: String,
                tag_filter: String,
                category_filter: String,
                selected: Option<usize>,
                adding: bool,
                editing_idx: Option<usize>,
                // temporary fields for add/edit
                tmp_account_id: String,
                tmp_username: String,
                tmp_password: String,
                tmp_tags: String,
                tmp_category: String,
                last_msg: String,
            }

            impl eframe::App for GuiState {
                fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.text_edit_singleline(&mut self.filter);
                            if ui.button("Clear").clicked() {
                                self.filter.clear();
                            }
                            ui.separator();
                            ui.label("Tag:");
                            ui.text_edit_singleline(&mut self.tag_filter);
                            ui.label("Category:");
                            ui.text_edit_singleline(&mut self.category_filter);
                        });

                        ui.separator();

                        ui.horizontal(|ui| {
                            if ui.button("Add").clicked() {
                                self.adding = true;
                                self.tmp_account_id.clear();
                                self.tmp_username.clear();
                                self.tmp_password.clear();
                                self.tmp_tags.clear();
                                self.tmp_category.clear();
                                self.editing_idx = None;
                            }
                            if ui.button("Save").clicked() {
                                match save_db_from_state(&self.accounts, &self.master, &self.db_path) {
                                    Ok(_) => self.last_msg = "Saved DB to disk".into(),
                                    Err(e) => self.last_msg = format!("Save error: {}", e),
                                }
                            }
                            if ui.button("Reload").clicked() {
                                match read_db(&self.db_path, &self.master) {
                                    Ok(db) => {
                                        self.accounts = db.accounts;
                                        self.last_msg = "Reloaded.".into();
                                    }
                                    Err(e) => self.last_msg = format!("Reload error: {}", e),
                                }
                            }

                            if ui.button("Change Master").clicked() {
                                let new_master = prompt_master(true);
                                let mut any_err = None::<String>;
                                for acc in self.accounts.iter_mut() {
                                    match decrypt_password_field(
                                        &self.master,
                                        &acc.account_id,
                                        &acc.password_b64,
                                        &acc.pwd_salt_b64,
                                        &acc.pwd_nonce_b64,
                                    ) {
                                        Ok(dec) => match encrypt_password_field(&new_master, &acc.account_id, &dec) {
                                            Ok((ct, s, n)) => {
                                                acc.password_b64 = ct;
                                                acc.pwd_salt_b64 = s;
                                                acc.pwd_nonce_b64 = n;
                                            }
                                            Err(e) => {
                                                any_err = Some(format!("encrypt error for {}: {}", acc.account_id, e));
                                                break;
                                            }
                                        },
                                        Err(e) => {
                                            any_err = Some(format!("decrypt error for {}: {}", acc.account_id, e));
                                            break;
                                        }
                                    }
                                }
                                if let Some(err) = any_err {
                                    self.last_msg = format!("Change master failed: {}", err);
                                } else {
                                    self.master = new_master;
                                    let save_res = save_db_from_state(&self.accounts, &self.master, &self.db_path);
                                    match save_res {
                                        Ok(_) => self.last_msg = "Master changed and re-encrypted.".into(),
                                        Err(e) => self.last_msg = format!("Re-encrypt save error: {}", e),
                                    }
                                }
                            }
                        });

                        ui.separator();

                        let mut to_remove: Option<usize> = None;

                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for idx in 0..self.accounts.len() {
                                let a = &self.accounts[idx];
                                let mut pass = true;
                                if !self.filter.trim().is_empty() {
                                    let f = self.filter.to_lowercase();
                                    if !a.account_id.to_lowercase().contains(&f) && !a.username.to_lowercase().contains(&f) {
                                        pass = false;
                                    }
                                }
                                if !self.tag_filter.trim().is_empty() {
                                    if !a.tags.iter().any(|t| t.eq_ignore_ascii_case(self.tag_filter.trim())) {
                                        pass = false;
                                    }
                                }
                                if !self.category_filter.trim().is_empty() {
                                    if a.category.as_ref().map(|s| s.to_lowercase()) != Some(self.category_filter.to_lowercase()) {
                                        pass = false;
                                    }
                                }
                                if !pass { continue; }

                                ui.horizontal(|ui| {
                                    if ui.selectable_label(self.selected == Some(idx), &a.account_id).clicked() {
                                        self.selected = Some(idx);
                                    }
                                    ui.label(&a.username);
                                    if ui.button("Copy pw").clicked() {
                                        match decrypt_password_field(&self.master, &a.account_id, &a.password_b64, &a.pwd_salt_b64, &a.pwd_nonce_b64) {
                                            Ok(pw) => {
                                                if let Err(e) = copy_to_clipboard_timed(&pw, 10) {
                                                    self.last_msg = format!("clipboard error: {}", e);
                                                } else {
                                                    self.last_msg = "password copied to clipboard (will clear in 10s)".into();
                                                }
                                            }
                                            Err(e) => {
                                                self.last_msg = format!("decrypt error: {}", e);
                                            }
                                        }
                                    }
                                    if ui.button("Edit").clicked() {
                                        self.editing_idx = Some(idx);
                                        self.tmp_account_id = a.account_id.clone();
                                        self.tmp_username = a.username.clone();
                                        match decrypt_password_field(&self.master, &a.account_id, &a.password_b64, &a.pwd_salt_b64, &a.pwd_nonce_b64) {
                                            Ok(pw) => self.tmp_password = pw,
                                            Err(_) => self.tmp_password = String::new(),
                                        }
                                        self.tmp_tags = a.tags.join(",");
                                        self.tmp_category = a.category.clone().unwrap_or_default();
                                    }
                                    if ui.button("Remove").clicked() {
                                        to_remove = Some(idx);
                                    }
                                });

                                ui.horizontal(|ui| {
                                    ui.label(format!("tags: {}", if a.tags.is_empty() { "-".into() } else { a.tags.join(", ") }));
                                    if let Some(c) = &a.category {
                                        ui.label(format!("category: {}", c));
                                    }
                                });

                                ui.separator();
                            }
                        });

                        // removal *after* loop ends to avoid borrow conflict
                        if let Some(idx) = to_remove {
                            self.accounts.remove(idx);
                            self.last_msg = "removed".into();
                        }


                        ui.separator();

                        if self.adding || self.editing_idx.is_some() {
                            ui.collapsing(if self.adding { "Add account" } else { "Edit account" }, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Account ID:");
                                    ui.text_edit_singleline(&mut self.tmp_account_id);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Username:");
                                    ui.text_edit_singleline(&mut self.tmp_username);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Password:");
                                    ui.text_edit_singleline(&mut self.tmp_password);
                                    if ui.button("Generate").clicked() {
                                        self.tmp_password = generate_password(16);
                                    }
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Tags (comma separated):");
                                    ui.text_edit_singleline(&mut self.tmp_tags);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Category:");
                                    ui.text_edit_singleline(&mut self.tmp_category);
                                });

                                ui.horizontal(|ui| {
                                    if ui.button("Save Entry").clicked() {
                                        let tags_vec = if self.tmp_tags.trim().is_empty() {
                                            vec![]
                                        } else {
                                            self.tmp_tags.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
                                        };
                                        let cat = if self.tmp_category.trim().is_empty() { None } else { Some(self.tmp_category.clone()) };

                                        // if editing, replace existing
                                        if let Some(edit_idx) = self.editing_idx {
                                            // encrypt tmp_password and replace fields
                                            match encrypt_password_field(&self.master, &self.tmp_account_id, &self.tmp_password) {
                                                Ok((ct, s, n)) => {
                                                    if edit_idx < self.accounts.len() {
                                                        self.accounts[edit_idx].account_id = self.tmp_account_id.clone();
                                                        self.accounts[edit_idx].username = self.tmp_username.clone();
                                                        self.accounts[edit_idx].password_b64 = ct;
                                                        self.accounts[edit_idx].pwd_salt_b64 = s;
                                                        self.accounts[edit_idx].pwd_nonce_b64 = n;
                                                        self.accounts[edit_idx].tags = tags_vec;
                                                        self.accounts[edit_idx].category = cat;
                                                        self.last_msg = "edited entry".into();
                                                        self.editing_idx = None;
                                                        self.adding = false;
                                                    }
                                                }
                                                Err(e) => self.last_msg = format!("encrypt error: {}", e),
                                            }
                                        } else {
                                            // new account
                                            match encrypt_password_field(&self.master, &self.tmp_account_id, &self.tmp_password) {
                                                Ok((ct, s, n)) => {
                                                    let acc = Account {
                                                        account_id: self.tmp_account_id.clone(),
                                                        username: self.tmp_username.clone(),
                                                        password_b64: ct,
                                                        pwd_salt_b64: s,
                                                        pwd_nonce_b64: n,
                                                        created_at: Utc::now(),
                                                        tags: tags_vec,
                                                        category: cat,
                                                    };
                                                    self.accounts.push(acc);
                                                    self.last_msg = "added entry".into();
                                                    self.adding = false;
                                                    self.editing_idx = None;
                                                }
                                                Err(e) => self.last_msg = format!("encrypt error: {}", e),
                                            }
                                        }
                                    }
                                    if ui.button("Cancel").clicked() {
                                        self.adding = false;
                                        self.editing_idx = None;
                                    }
                                });
                            });
                        }

                        ui.separator();
                        ui.label(format!("Status: {}", self.last_msg));
                    });
                }
            }

            // helper to save in GUI (write envelope)
            fn save_db_from_state(
                accounts: &Vec<Account>,
                master: &str,
                path: &PathBuf,
            ) -> Result<()> {
                let db = Database {
                    accounts: accounts.clone(),
                };
                // use the same encrypt_db + write logic as CLI
                let encrypted = encrypt_db(&db, master)?;
                let mut f = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)
                    .context("open db file for write")?;
                f.write_all(&encrypted)?;
                Ok(())
            }

            // prepare initial GuiState
            let state = GuiState {
                accounts: db.accounts.clone(),
                master: master.clone(),
                db_path: cli.file.clone(),
                filter: String::new(),
                tag_filter: String::new(),
                category_filter: String::new(),
                selected: None,
                adding: false,
                editing_idx: None,
                tmp_account_id: String::new(),
                tmp_username: String::new(),
                tmp_password: String::new(),
                tmp_tags: String::new(),
                tmp_category: String::new(),
                last_msg: String::new(),
            };

            let options = eframe::NativeOptions::default();
            eframe::run_native("Aegis", options, Box::new(|_cc| Ok(Box::new(state))))
                .expect("Failed to run GUI");
        }
    }

    Ok(())
}
