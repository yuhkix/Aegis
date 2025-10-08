use std::path::PathBuf;

use anyhow::{Result, anyhow};
use eframe::egui;
use eframe::egui::TopBottomPanel;
use log::{error, info};
use rfd::FileDialog;

mod crypto;
mod db_models;
mod utils;

use crypto::{decrypt_password_field, effective_master, encrypt_password_field, read_db, write_db};
use db_models::{Account, AppConfig, Database};
use utils::{
    copy_to_clipboard_timed, generate_password, load_config, password_strength, save_config,
    update_recent,
};

fn main() -> Result<()> {
    let _ = env_logger::Builder::from_default_env().try_init();
    info!("Starting Aegis GUI");

    #[derive(Default)]
    struct GuiState {
        accounts: Vec<Account>,
        master: String,
        keyfile_path: Option<PathBuf>,
        db_path: Option<PathBuf>,
        filter: String,
        tag_filter: String,
        category_filter: String,
        selected: Option<usize>,
        adding: bool,
        editing_idx: Option<usize>,
        tmp_account_id: String,
        tmp_username: String,
        tmp_password: String,
        tmp_tags: String,
        tmp_category: String,
        last_msg: String,
        show_master_change: bool,
        new_master: String,
        new_master_confirm: String,
        change_keyfile_path: Option<PathBuf>,
        show_change_pw: bool,
        show_change_pw_confirm: bool,
        show_master_for_open: bool,
        master_for_open: String,
        open_keyfile_path: Option<PathBuf>,
        show_open_pw: bool,
        pending_open_path: Option<PathBuf>,
        pending_create_path: Option<PathBuf>,
        create_master: String,
        create_master_confirm: String,
        create_keyfile_path: Option<PathBuf>,
        show_create_pw: bool,
        show_create_pw_confirm: bool,
        recent_entries: Vec<db_models::RecentEntry>,
    }

    impl eframe::App for GuiState {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            let db_is_loaded = self.db_path.is_some();

            // --- Top menu bar (Always shown but options change) ---
            TopBottomPanel::top("top_menu").show(ctx, |ui| {
                egui::MenuBar::new().ui(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("New Database...").clicked() {
                            ui.close();
                            if let Some(path) = FileDialog::new()
                                .add_filter("Aegis DB", &["bin"])
                                .set_file_name("aegis.bin")
                                .save_file()
                            {
                                self.pending_create_path = Some(path);
                                self.create_master.clear();
                                self.create_master_confirm.clear();
                                self.create_keyfile_path = None;
                                self.show_create_pw = false;
                                self.show_create_pw_confirm = false;
                            }
                        }
                        if ui.button("Open Database...").clicked() {
                            ui.close();
                            if let Some(path) = FileDialog::new()
                                .add_filter("Aegis DB", &["bin"])
                                .pick_file()
                            {
                                self.pending_open_path = Some(path);
                                self.master_for_open.clear();
                                self.show_master_for_open = true;
                                self.open_keyfile_path = None;
                                self.show_open_pw = false;
                            }
                        }
                        if db_is_loaded {
                            if ui.button("Save").clicked() {
                                ui.close();
                                let eff = match effective_master(&self.master, &self.keyfile_path) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        self.last_msg = format!("Keyfile error: {}", e);
                                        String::new()
                                    }
                                };
                                if eff.is_empty() { /* error already reported */
                                } else {
                                    match save_db_from_state(&self.accounts, &eff, &self.db_path) {
                                        Ok(_) => self.last_msg = "Saved DB to disk".into(),
                                        Err(e) => self.last_msg = format!("Save error: {}", e),
                                    }
                                }
                            }
                            if ui.button("Save As...").clicked() {
                                ui.close();
                                if let Some(path) = FileDialog::new()
                                    .add_filter("Aegis DB", &["bin"])
                                    .save_file()
                                {
                                    info!("Save As path: {}", path.display());
                                    self.db_path = Some(path);
                                    let eff =
                                        match effective_master(&self.master, &self.keyfile_path) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                self.last_msg = format!("Keyfile error: {}", e);
                                                String::new()
                                            }
                                        };
                                    if !eff.is_empty() {
                                        match save_db_from_state(
                                            &self.accounts,
                                            &eff,
                                            &self.db_path,
                                        ) {
                                            Ok(_) => {
                                                self.last_msg = "Saved DB (as)".into();
                                                info!("Saved As to {:?}", self.db_path);
                                            }
                                            Err(e) => {
                                                error!("Save As error: {}", e);
                                                self.last_msg = format!("Save error: {}", e);
                                            }
                                        }
                                        if let Some(p) = &self.db_path {
                                            update_recent(
                                                &mut self.recent_entries,
                                                p.clone(),
                                                self.keyfile_path.clone(),
                                            );
                                            save_config(&AppConfig {
                                                recents: self.recent_entries.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                            if ui.button("Change Master...").clicked() {
                                ui.close();
                                self.new_master.clear();
                                self.new_master_confirm.clear();
                                self.show_master_change = true;
                                self.change_keyfile_path = self.keyfile_path.clone();
                                self.show_change_pw = false;
                                self.show_change_pw_confirm = false;
                            }
                        }
                        if ui.button("Exit").clicked() {
                            ui.close();
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                });
            });

            // --- Main Content ---
            egui::CentralPanel::default().show(ctx, |ui| {

                // --- Recent sidebar or Empty space (only shown if DB not loaded) ---
                if !db_is_loaded {
                    // Only show the recent sidebar if the database is NOT loaded AND
                    // no other dialogs (like master password entry) are currently active.
                    // This ensures the sidebar doesn't clutter the view during active dialogs.
                    if !self.show_master_for_open && self.pending_create_path.is_none() {
                        egui::SidePanel::left("recent_sidebar")
                            .resizable(false)
                            .default_width(220.0)
                            .show_separator_line(true)
                            .show(ctx, |ui| {
                                ui.heading("Recent");
                                if self.recent_entries.is_empty() {
                                    ui.label("No recent databases");
                                } else {
                                    egui::ScrollArea::vertical().show(ui, |ui| {
                                        for entry in self.recent_entries.clone() {
                                            let p = entry.db_path.clone();
                                            let label = p
                                                .file_name()
                                                .and_then(|s| s.to_str())
                                                .unwrap_or("(unnamed)");
                                            if ui.button(label).clicked() {
                                                self.pending_open_path = Some(p.clone());
                                                self.master_for_open.clear();
                                                self.show_master_for_open = true;
                                                self.open_keyfile_path = entry.keyfile_path.clone();
                                                self.show_open_pw = false;
                                            }
                                            ui.label(egui::RichText::new(p.display().to_string()).small());
                                            ui.separator();
                                        }
                                    });

                                    if ui.button("Clear recent").clicked() {
                                        self.recent_entries.clear();
                                        save_config(&AppConfig {
                                            recents: self.recent_entries.clone(),
                                        });
                                    }
                                }
                            });
                    }
                }

                // --- Onboarding / Main Application Logic ---
                if !db_is_loaded {
                    // Onboarding/Welcome screen - Only show if NO database is loaded AND NO dialog is open.
                    if !self.show_master_for_open && self.pending_create_path.is_none() {
                        ui.vertical_centered(|ui| {
                            ui.heading("Aegis");
                            ui.label("Create a new database or open an existing one.");
                            if ui.button("Create New Database").clicked() {
                                if let Some(path) = FileDialog::new()
                                    .add_filter("Aegis DB", &["bin"])
                                    .set_file_name("aegis.bin")
                                    .save_file()
                                {
                                            info!("Selected path for new database: {}", path.display());
                                    self.pending_create_path = Some(path);
                                    self.create_master.clear();
                                    self.create_master_confirm.clear();
                                    self.create_keyfile_path = None;
                                }
                            }
                            if ui.button("Open Existing Database").clicked() {
                                if let Some(path) = FileDialog::new()
                                    .add_filter("Aegis DB", &["bin"])
                                    .pick_file()
                                {
                                            info!("Selected database to open: {}", path.display());
                                    self.pending_open_path = Some(path);
                                    self.master_for_open.clear();
                                    self.show_master_for_open = true;
                                    self.open_keyfile_path = None;
                                }
                            }
                        });
                    }
                } else {
                    // Main application screen (DB loaded) - Hide all search/filter elements
                    // if editing or adding an account, to keep the UI clean.
                    if self.adding || self.editing_idx.is_some() {
                        // Only show the add/edit collapsing panel
                    } else {
                        // Show search/filter controls when viewing the list
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
                                let eff = match effective_master(&self.master, &self.keyfile_path) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        self.last_msg = format!("Keyfile error: {}", e);
                                        String::new()
                                    }
                                };
                                if !eff.is_empty() {
                                    match save_db_from_state(&self.accounts, &eff, &self.db_path) {
                                        Ok(_) => { self.last_msg = "Saved DB to disk".into(); info!("Saved DB to {:?}", self.db_path); },
                                        Err(e) => { error!("Save error: {}", e); self.last_msg = format!("Save error: {}", e); },
                                    }
                                }
                            }
                            if ui.button("Reload").clicked() {
                                if let Some(path) = &self.db_path {
                                    let eff = match effective_master(&self.master, &self.keyfile_path) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            self.last_msg = format!("Keyfile error: {}", e);
                                            String::new()
                                        }
                                    };
                                    if !eff.is_empty() {
                                        match read_db(path, &eff) {
                                            Ok(db) => {
                                                self.accounts = db.accounts;
                                                self.last_msg = "Reloaded.".into();
                                            }
                                            Err(e) => self.last_msg = format!("Reload error: {}", e),
                                        }
                                    }
                                } else {
                                    self.last_msg = "No database selected".into();
                                }
                            }

                            if ui.button("Change Master").clicked() {
                                self.new_master.clear();
                                self.new_master_confirm.clear();
                                self.show_master_change = true;
                            }
                        });

                        ui.separator();
                    }

                    let mut to_remove: Option<usize> = None;

                    // Account List (only shown if not adding/editing)
                    if !self.adding && self.editing_idx.is_none() {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for idx in 0..self.accounts.len() {
                                let a = &self.accounts[idx];
                                let mut pass = true;
                                if !self.filter.trim().is_empty() {
                                    let f = self.filter.to_lowercase();
                                    if !a.account_id.to_lowercase().contains(&f)
                                        && !a.username.to_lowercase().contains(&f)
                                    {
                                        pass = false;
                                    }
                                }
                                if !self.tag_filter.trim().is_empty() {
                                    if !a
                                        .tags
                                        .iter()
                                        .any(|t| t.eq_ignore_ascii_case(self.tag_filter.trim()))
                                    {
                                        pass = false;
                                    }
                                }
                                if !self.category_filter.trim().is_empty() {
                                    if a.category.as_ref().map(|s| s.to_lowercase())
                                        != Some(self.category_filter.to_lowercase())
                                    {
                                        pass = false;
                                    }
                                }
                                if !pass {
                                    continue;
                                }

                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(self.selected == Some(idx), &a.account_id)
                                        .clicked()
                                    {
                                        self.selected = Some(idx);
                                    }
                                    ui.label(&a.username);
                                    if ui.button("Copy pw").clicked() {
                                        let eff = match effective_master(&self.master, &self.keyfile_path) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                self.last_msg = format!("Keyfile error: {}", e);
                                                String::new()
                                            }
                                        };
                                        match if eff.is_empty() {
                                            Err(anyhow!("Keyfile error"))
                                        } else {
                                            decrypt_password_field(
                                                &eff,
                                                &a.account_id,
                                                &a.password_b64,
                                                &a.pwd_salt_b64,
                                                &a.pwd_nonce_b64,
                                            )
                                        } {
                                            Ok(pw) => {
                                                if let Err(e) = copy_to_clipboard_timed(&pw, 10) {
                                                    self.last_msg = format!("clipboard error: {}", e);
                                                } else {
                                                    self.last_msg =
                                                        "password copied to clipboard (will clear in 10s)"
                                                            .into();
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
                                        let eff = match effective_master(&self.master, &self.keyfile_path) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                self.last_msg = format!("Keyfile error: {}", e);
                                                String::new()
                                            }
                                        };
                                        match if eff.is_empty() {
                                            Err(anyhow!("Keyfile error"))
                                        } else {
                                            decrypt_password_field(
                                                &eff,
                                                &a.account_id,
                                                &a.password_b64,
                                                &a.pwd_salt_b64,
                                                &a.pwd_nonce_b64,
                                            )
                                        } {
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
                                    ui.label(format!(
                                        "tags: {}",
                                        if a.tags.is_empty() {
                                            "-".into()
                                        } else {
                                            a.tags.join(", ")
                                        }
                                    ));
                                    if let Some(c) = &a.category {
                                        ui.label(format!("category: {}", c));
                                    }
                                });

                                ui.separator();
                            }
                        });
                    }

                    // removal *after* loop ends to avoid borrow conflict
                    if let Some(idx) = to_remove {
                        self.accounts.remove(idx);
                        self.last_msg = "removed".into();
                    }

                    // Add/Edit Panel
                    if self.adding || self.editing_idx.is_some() {
                        ui.collapsing(
                            if self.adding {
                                "Add account"
                            } else {
                                "Edit account"
                            },
                            |ui| {
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
                                            self.tmp_tags
                                                .split(',')
                                                .map(|s| s.trim().to_string())
                                                .filter(|s| !s.is_empty())
                                                .collect()
                                        };
                                        let cat = if self.tmp_category.trim().is_empty() {
                                            None
                                        } else {
                                            Some(self.tmp_category.clone())
                                        };

                                        // if editing, replace existing
                                        if let Some(edit_idx) = self.editing_idx {
                                            // encrypt tmp_password and replace fields
                                            let eff = match effective_master(
                                                &self.master,
                                                &self.keyfile_path,
                                            ) {
                                                Ok(m) => m,
                                                Err(e) => {
                                                    self.last_msg = format!("Keyfile error: {}", e);
                                                    String::new()
                                                }
                                            };
                                            match if eff.is_empty() {
                                                Err(anyhow!("Keyfile error"))
                                            } else {
                                                encrypt_password_field(
                                                    &eff,
                                                    &self.tmp_account_id,
                                                    &self.tmp_password,
                                                )
                                            } {
                                                Ok((ct, s, n)) => {
                                                    if edit_idx < self.accounts.len() {
                                                        self.accounts[edit_idx].account_id =
                                                            self.tmp_account_id.clone();
                                                        self.accounts[edit_idx].username =
                                                            self.tmp_username.clone();
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
                                                Err(e) => {
                                                    self.last_msg = format!("encrypt error: {}", e)
                                                }
                                            }
                                        } else {
                                            // new account
                                            let eff = match effective_master(
                                                &self.master,
                                                &self.keyfile_path,
                                            ) {
                                                Ok(m) => m,
                                                Err(e) => {
                                                    self.last_msg = format!("Keyfile error: {}", e);
                                                    String::new()
                                                }
                                            };
                                            match if eff.is_empty() {
                                                Err(anyhow!("Keyfile error"))
                                            } else {
                                                encrypt_password_field(
                                                    &eff,
                                                    &self.tmp_account_id,
                                                    &self.tmp_password,
                                                )
                                            } {
                                                Ok((ct, s, n)) => {
                                                    let acc = Account {
                                                        account_id: self.tmp_account_id.clone(),
                                                        username: self.tmp_username.clone(),
                                                        password_b64: ct,
                                                        pwd_salt_b64: s,
                                                        pwd_nonce_b64: n,
                                                        created_at: chrono::Utc::now(),
                                                        tags: tags_vec,
                                                        category: cat,
                                                    };
                                                    self.accounts.push(acc);
                                                    self.last_msg = "added entry".into();
                                                    self.adding = false;
                                                    self.editing_idx = None;
                                                }
                                                Err(e) => {
                                                    self.last_msg = format!("encrypt error: {}", e)
                                                }
                                            }
                                        }
                                    }
                                    if ui.button("Cancel").clicked() {
                                        self.adding = false;
                                        self.editing_idx = None;
                                    }
                                });
                            },
                        );
                    }
                }

                // --- Dialogs (always shown over content) ---
                // The dialogs are kept in main.rs but their state variables prevent the
                // main UI (onboarding or DB loaded view) from showing non-essential elements.

                if self.show_master_change {
                    egui::Window::new("Change Master Password")
                        .collapsible(false)
                        .show(ctx, |ui| {
                            ui.label("Enter new master password (twice):");
                            ui.horizontal(|ui| {
                                let te = egui::TextEdit::singleline(&mut self.new_master)
                                    .password(!self.show_change_pw);
                                ui.add(te);
                                if ui
                                    .button(if self.show_change_pw { "Hide" } else { "Show" })
                                    .clicked()
                                {
                                    self.show_change_pw = !self.show_change_pw;
                                }
                            });
                            ui.horizontal(|ui| {
                                let te = egui::TextEdit::singleline(&mut self.new_master_confirm)
                                    .password(!self.show_change_pw_confirm);
                                ui.add(te);
                                if ui
                                    .button(if self.show_change_pw_confirm {
                                        "Hide"
                                    } else {
                                        "Show"
                                    })
                                    .clicked()
                                {
                                    self.show_change_pw_confirm = !self.show_change_pw_confirm;
                                }
                            });
                            // strength meter
                            let score = password_strength(&self.new_master) as f32 / 6.0;
                            ui.add(
                                egui::ProgressBar::new(score)
                                    .text(format!("Strength: {}/6", (score * 6.0).round() as i32)),
                            );
                            // optional keyfile
                            ui.horizontal(|ui| {
                                ui.label("Keyfile (optional):");
                                let key_label = self
                                    .change_keyfile_path
                                    .as_ref()
                                    .map(|p| {
                                        p.file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("(invalid)")
                                    })
                                    .unwrap_or("(none)");
                                ui.label(key_label);
                                if ui.button("Select...").clicked() {
                                    if let Some(p) = FileDialog::new().pick_file() {
                                        self.change_keyfile_path = Some(p);
                                    }
                                }
                                if self.change_keyfile_path.is_some()
                                    && ui.button("Clear").clicked()
                                {
                                    self.change_keyfile_path = None;
                                }
                            });
                            if ui.button("Apply").clicked() {
                                if self.new_master.is_empty()
                                    || self.new_master != self.new_master_confirm
                                {
                                    self.last_msg = "Passwords empty or do not match".into();
                                } else {
                                    let mut any_err = None::<String>;
                                    let current_eff =
                                        match effective_master(&self.master, &self.keyfile_path) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                self.last_msg = format!("Keyfile error: {}", e);
                                                String::new()
                                            }
                                        };
                                    let new_eff = match effective_master(
                                        &self.new_master,
                                        &self.change_keyfile_path,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            self.last_msg = format!("Keyfile error: {}", e);
                                            String::new()
                                        }
                                    };
                                    if !current_eff.is_empty() && !new_eff.is_empty() {
                                        for acc in self.accounts.iter_mut() {
                                            match decrypt_password_field(
                                                &current_eff,
                                                &acc.account_id,
                                                &acc.password_b64,
                                                &acc.pwd_salt_b64,
                                                &acc.pwd_nonce_b64,
                                            ) {
                                                Ok(dec) => match encrypt_password_field(
                                                    &new_eff,
                                                    &acc.account_id,
                                                    &dec,
                                                ) {
                                                    Ok((ct, s, n)) => {
                                                        acc.password_b64 = ct;
                                                        acc.pwd_salt_b64 = s;
                                                        acc.pwd_nonce_b64 = n;
                                                    }
                                                    Err(e) => {
                                                        any_err = Some(format!(
                                                            "encrypt error for {}: {}",
                                                            acc.account_id, e
                                                        ));
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    any_err = Some(format!(
                                                        "decrypt error for {}: {}",
                                                        acc.account_id, e
                                                    ));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    if let Some(err) = any_err {
                                        self.last_msg = format!("Change master failed: {}", err);
                                    } else {
                                        self.master = self.new_master.clone();
                                        self.keyfile_path = self.change_keyfile_path.clone();
                                        let eff = match effective_master(
                                            &self.master,
                                            &self.keyfile_path,
                                        ) {
                                            Ok(m) => m,
                                            Err(e) => {
                                                self.last_msg = format!("Keyfile error: {}", e);
                                                String::new()
                                            }
                                        };
                                        let save_res = if eff.is_empty() {
                                            Err(anyhow!("Keyfile error"))
                                        } else {
                                            save_db_from_state(&self.accounts, &eff, &self.db_path)
                                        };
                                        match save_res {
                                            Ok(_) => {
                                                self.last_msg =
                                                    "Master changed and re-encrypted.".into()
                                            }
                                            Err(e) => {
                                                self.last_msg =
                                                    format!("Re-encrypt save error: {}", e)
                                            }
                                        }
                                        self.show_master_change = false;
                                    }
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                self.show_master_change = false;
                            }
                        });
                }

                if self.show_master_for_open {
                    egui::Window::new("Enter Master Password")
                        .collapsible(false)
                        .show(ctx, |ui| {
                            ui.label("Master password for selected database:");
                            ui.horizontal(|ui| {
                                let te = egui::TextEdit::singleline(&mut self.master_for_open)
                                    .password(!self.show_open_pw);
                                ui.add(te);
                                if ui
                                    .button(if self.show_open_pw { "Hide" } else { "Show" })
                                    .clicked()
                                {
                                    self.show_open_pw = !self.show_open_pw;
                                }
                            });
                            // strength meter (for user feedback only)
                            let score = password_strength(&self.master_for_open) as f32 / 6.0;
                            ui.add(
                                egui::ProgressBar::new(score)
                                    .text(format!("Strength: {}/6", (score * 6.0).round() as i32)),
                            );
                            // keyfile picker
                            ui.horizontal(|ui| {
                                ui.label("Keyfile (optional):");
                                let key_label = self
                                    .open_keyfile_path
                                    .as_ref()
                                    .map(|p| {
                                        p.file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("(invalid)")
                                    })
                                    .unwrap_or("(none)");
                                ui.label(key_label);
                                if ui.button("Select...").clicked() {
                                    if let Some(p) = FileDialog::new().pick_file() {
                                        self.open_keyfile_path = Some(p);
                                    }
                                }
                                if self.open_keyfile_path.is_some() && ui.button("Clear").clicked()
                                {
                                    self.open_keyfile_path = None;
                                }
                            });
                            if ui.button("Open").clicked() {
                                if let Some(path) = self.pending_open_path.clone() {
                                    let eff = match effective_master(
                                        &self.master_for_open,
                                        &self.open_keyfile_path,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            error!("Keyfile error: {}", e);
                                            self.last_msg = format!("Keyfile error: {}", e);
                                            String::new()
                                        }
                                    };
                                    match if eff.is_empty() {
                                        Err(anyhow!("Keyfile error"))
                                    } else {
                                        read_db(&path, &eff)
                                    } {
                                        Ok(db) => {
                                            self.accounts = db.accounts;
                                            self.master = self.master_for_open.clone();
                                            self.keyfile_path = self.open_keyfile_path.clone();
                                            self.db_path = Some(path);
                                            self.last_msg = "Database opened.".into();
                                            info!("Opened DB: {:?}", self.db_path);
                                            self.show_master_for_open = false;
                                            if let Some(p) = &self.db_path {
                                                update_recent(
                                                    &mut self.recent_entries,
                                                    p.clone(),
                                                    self.keyfile_path.clone(),
                                                );
                                                save_config(&AppConfig {
                                                    recents: self.recent_entries.clone(),
                                                });
                                            }
                                            // Clear the pending open path once opened successfully
                                            self.pending_open_path = None;
                                        }
                                        Err(e) => {
                                            error!("Open error: {}", e);
                                            self.last_msg = format!("Open error: {}", e);
                                        }
                                    }
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                self.show_master_for_open = false;
                            }
                        });
                }

                if let Some(path) = self.pending_create_path.clone() {
                    egui::Window::new("Create New Database")
                        .collapsible(false)
                        .show(ctx, |ui| {
                            ui.label(format!("Path: {}", path.display()));
                            ui.label("Set master password (twice):");
                            ui.horizontal(|ui| {
                                let te = egui::TextEdit::singleline(&mut self.create_master)
                                    .password(!self.show_create_pw);
                                ui.add(te);
                                if ui
                                    .button(if self.show_create_pw { "Hide" } else { "Show" })
                                    .clicked()
                                {
                                    self.show_create_pw = !self.show_create_pw;
                                }
                            });
                            ui.horizontal(|ui| {
                                let te =
                                    egui::TextEdit::singleline(&mut self.create_master_confirm)
                                        .password(!self.show_create_pw_confirm);
                                ui.add(te);
                                if ui
                                    .button(if self.show_create_pw_confirm {
                                        "Hide"
                                    } else {
                                        "Show"
                                    })
                                    .clicked()
                                {
                                    self.show_create_pw_confirm = !self.show_create_pw_confirm;
                                }
                            });
                            let score = password_strength(&self.create_master) as f32 / 6.0;
                            ui.add(
                                egui::ProgressBar::new(score)
                                    .text(format!("Strength: {}/6", (score * 6.0).round() as i32)),
                            );
                            // optional keyfile
                            ui.horizontal(|ui| {
                                ui.label("Keyfile (optional):");
                                let key_label = self
                                    .create_keyfile_path
                                    .as_ref()
                                    .map(|p| {
                                        p.file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("(invalid)")
                                    })
                                    .unwrap_or("(none)");
                                ui.label(key_label);
                                if ui.button("Select...").clicked() {
                                    if let Some(p) = FileDialog::new().pick_file() {
                                        self.create_keyfile_path = Some(p);
                                    }
                                }
                                if self.create_keyfile_path.is_some()
                                    && ui.button("Clear").clicked()
                                {
                                    self.create_keyfile_path = None;
                                }
                            });
                            if ui.button("Create").clicked() {
                                if self.create_master.is_empty()
                                    || self.create_master != self.create_master_confirm
                                {
                                    self.last_msg = "Passwords empty or do not match".into();
                                } else {
                                    let db = Database::default();
                                    let eff = match effective_master(
                                        &self.create_master,
                                        &self.create_keyfile_path,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => { error!("Keyfile error: {}", e); self.last_msg = format!("Keyfile error: {}", e); String::new() }
                                    };
                                    match if eff.is_empty() {
                                        Err(anyhow!("Keyfile error"))
                                    } else {
                                        write_db(&path, &db, &eff)
                                    } {
                                        Ok(_) => {
                                            self.accounts = db.accounts;
                                            self.master = self.create_master.clone();
                                            self.keyfile_path = self.create_keyfile_path.clone();
                                            self.db_path = Some(path.clone());
                                            self.last_msg = "Database created.".into(); info!("Created DB: {:?}", self.db_path);
                                            self.pending_create_path = None;
                                            if let Some(p) = &self.db_path {
                                                update_recent(
                                                    &mut self.recent_entries,
                                                    p.clone(),
                                                    self.keyfile_path.clone(),
                                                );
                                                save_config(&AppConfig {
                                                    recents: self.recent_entries.clone(),
                                                });
                                            }
                                        }
                                        Err(e) => { error!("Create error: {}", e); self.last_msg = format!("Create error: {}", e) },
                                    }
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                self.pending_create_path = None;
                            }
                        });
                }

                // Status bar at the bottom
                ui.separator();
                ui.label(format!("Status: {}", self.last_msg));
            });
        }
    }

    fn save_db_from_state(
        accounts: &Vec<Account>,
        master: &str,
        path: &Option<PathBuf>,
    ) -> Result<()> {
        let db = Database {
            accounts: accounts.clone(),
        };
        let target = path
            .as_ref()
            .ok_or_else(|| anyhow!("no database path selected"))?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        write_db(target, &db, master)
    }

    let cfg = load_config();
    let initial_accounts = Vec::new();
    let initial_master = String::new();
    let recent_entries = cfg.recents;
    let state = GuiState {
        accounts: initial_accounts,
        master: initial_master,
        keyfile_path: None,
        db_path: None,
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
        show_master_change: false,
        new_master: String::new(),
        new_master_confirm: String::new(),
        change_keyfile_path: None,
        show_change_pw: false,
        show_change_pw_confirm: false,
        show_master_for_open: false,
        master_for_open: String::new(),
        open_keyfile_path: None,
        show_open_pw: false,
        pending_open_path: None,
        pending_create_path: None,
        create_master: String::new(),
        create_master_confirm: String::new(),
        create_keyfile_path: None,
        show_create_pw: false,
        show_create_pw_confirm: false,
        recent_entries,
    };

    let options = eframe::NativeOptions::default();
    eframe::run_native("Aegis", options, Box::new(|_cc| Ok(Box::new(state))))
        .expect("Failed to run GUI");

    Ok(())
}
