use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use bincode::{config, decode_from_slice, encode_to_vec};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rng};
use sha2::{Digest, Sha256};

use crate::db_models::{Database, MAGIC, NONCE_LEN, SALT_LEN, VERSION};

fn derive_key(master: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(master.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("KDF failure: {}", e))?;
    Ok(out)
}

pub fn encrypt_db(db: &Database, master: &str) -> Result<Vec<u8>> {
    let config = config::standard();
    let serialized = encode_to_vec(db, config).context("serializing db with bincode")?;

    let mut salt = [0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);

    let key_bytes = derive_key(master, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce_obj = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce_obj, serialized.as_ref())
        .map_err(|e| anyhow!("file encryption failed: {}", e))?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.push(NONCE_LEN as u8);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

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
    let config = config::standard();
    let (db, _len): (Database, usize) =
        decode_from_slice(&plaintext, config).context("deserializing db with bincode")?;
    Ok(db)
}

pub fn read_db(path: &PathBuf, master: &str) -> Result<Database> {
    let mut f = File::open(path).context("open db file")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    decrypt_db_file(&buf, master)
}

pub fn write_db(path: &PathBuf, db: &Database, master: &str) -> Result<()> {
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

pub fn effective_master(master: &str, maybe_keyfile: &Option<PathBuf>) -> Result<String> {
    if let Some(p) = maybe_keyfile {
        let bytes = std::fs::read(p).with_context(|| format!("read keyfile: {}", p.display()))?;
        let digest = Sha256::digest(&bytes);
        let tag = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&digest[..]);
        Ok(format!("{}:keyfile:{}", master, tag))
    } else {
        Ok(master.to_string())
    }
}

pub fn encrypt_password_field(
    master: &str,
    account_id: &str,
    plaintext: &str,
) -> Result<(String, String, String)> {
    let mut salt = [0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);

    let key_bytes = derive_key(&format!("{}:{}", master, account_id), &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce);
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

pub fn decrypt_password_field(
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
