# 🛡️ Aegis - Encrypted Password Database

Aegis is a **fast, secure, and cross-platform** password database utility written entirely in **Rust**. It offers both a minimal **CLI** for power users and a **beautiful, native GUI**.

Leveraging modern, robust cryptography and compact binary storage, Aegis ensures your sensitive information remains **private, local, and secure**. Your passwords never leave your machine.

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![UI](https://img.shields.io/badge/UI-egui-lightgrey.svg)
![Encryption](https://img.shields.io/badge/encryption-XChaCha20--Poly1305-green.svg)

## ✨ Key Features

### 🔒 **Advanced Security**
* **Modern AEAD Encryption:** Uses **XChaCha20-Poly1305** for strong, authenticated encryption of all account data.
* **Key Derivation:** Master password protected via industry-standard **Argon2id** key derivation function.
* **Unique Keys:** Per-account random salts and nonces for enhanced security.
* **Rotation:** Seamlessly re-encrypts the entire database when the master password is changed.

### 💾 **Data Integrity**
* **Compact Binary Storage:** Databases are stored efficiently in a custom `.bin` file format using `bincode` (no slow JSON).
* **Format Verification:** Custom magic header (`AEGISDB`) ensures file integrity and correct format detection.

### 🖥️ **Cross-Platform Interface**
* **CLI + GUI:** Choose between a powerful, minimal command-line interface or an intuitive graphical experience.
* **Native GUI:** Beautiful, responsive interface built with [`egui`](https://github.com/emilk/egui) and [`eframe`](https://github.com/emilk/eframe).

### 🛠️ **Productivity Tools**
* **Password Generator:** Automatic creation of strong, randomized passwords.
* **Strength Scoring:** Real-time feedback on password quality.
* **Secure Clipboard:** Integrates a secure clipboard that **auto-clears** the copied password after a short, fixed duration (e.g., 10 seconds).
* **Organization:** Easily add **tags** and **categories** to accounts for better management, searching, and filtering.

## 📸 GUI Preview

- later

## 🔐 Security Model & Stack

### Encryption Principles

| Component | Algorithm / Library |
|-----------|---------------------|
| `Key Derivation` | Argon2id |
| `AEAD Encryption` | XChaCha20-Poly1305 |
| `Password Hashing` | Argon2 (for new generated passwords) |
| `Encoding` | Base64 + bincode binary serialization |
| `Clipboard` | Temporary, auto-clearing after ≈10 seconds |

### Database Structure
Each database file (`.bin`) contains the following top-level fields:

| Field | Description |
|-------|-------------|
| `magic` | File identifier: `AEGISDB` |
| `salt` | Argon2 KDF salt |
| `nonce` | AEAD encryption nonce |
| `accounts[]` | List of accounts (all internal fields are individually encrypted) |

## 🧰 Tech Stack

Aegis is built with the following outstanding Rust crates:

| Area | Library |
|------|---------|
| **CLI** | `clap` |
| **GUI** | `eframe` + `egui` |
| **Serialization** | `bincode`, `serde` |
| **Encryption** | `chacha20poly1305`, `argon2`, `base64` |
| **Randomness** | `rand`, `rand_core` |
| **Time** | `chrono` |
| **Clipboard** | `arboard` |

### 🧩 Roadmap

Aegis is under active development. Planned features include:

* Complete GUI editor & viewer functionality.
* Per-field encryption for maximum security isolation.
* Cloud sync capability (optional, with strictly local encryption).
* Encrypted JSON export/import functionality.

### 💬 Author
Developed by **Yuhki**

_Built with passion, paranoia, and Rust._

“A strong lock is useless if you give away the key.”
