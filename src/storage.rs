use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub static_public_key_b64: String,
    pub custom_name: Option<String>,
    pub is_verified: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredMessage {
    pub peer_id: String, // target or sender
    pub from: String,    // "Me", "System", or NodeID
    pub content: String,
    pub is_system: bool,
    pub ttl: Option<u64>,
    pub timestamp_secs: u64,
}

pub fn derive_storage_key(private_key_bytes: &[u8]) -> [u8; 32] {
    let mut storage_key = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(b"patronus-storage-salt-v1"), private_key_bytes);
    hk.expand(b"patronus-storage-key-v1", &mut storage_key).expect("HKDF expand failed");
    storage_key
}

fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Invalid key: {}", e))?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let aad = b"patronus-storage-aad-v1";
    let payload = Payload {
        msg: plaintext,
        aad: &aad[..],
    };
    let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| anyhow!("Encryption failed: {}", e))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_data(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 + 16 {
        return Err(anyhow!("Encrypted data too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Invalid key: {}", e))?;
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let aad = b"patronus-storage-aad-v1";
    let payload = Payload {
        msg: ciphertext,
        aad: &aad[..],
    };
    cipher.decrypt(nonce, payload).map_err(|e| anyhow!("Decryption failed: {}", e))
}

pub fn save_peers(config_dir: &Path, key: &[u8; 32], peers: &HashMap<String, PeerInfo>) -> Result<()> {
    let json_bytes = serde_json::to_vec(peers)?;
    let encrypted = encrypt_data(key, &json_bytes)?;
    let filepath = config_dir.join("peers.enc");
    fs::write(filepath, encrypted)?;
    Ok(())
}

pub fn load_peers(config_dir: &Path, key: &[u8; 32]) -> Result<HashMap<String, PeerInfo>> {
    let filepath = config_dir.join("peers.enc");
    if !filepath.exists() {
        return Ok(HashMap::new());
    }
    let encrypted = fs::read(filepath)?;
    let decrypted = decrypt_data(key, &encrypted)?;
    let peers = serde_json::from_slice(&decrypted)?;
    Ok(peers)
}

pub fn save_history(config_dir: &Path, key: &[u8; 32], history: &[StoredMessage]) -> Result<()> {
    let json_bytes = serde_json::to_vec(history)?;
    let encrypted = encrypt_data(key, &json_bytes)?;
    let filepath = config_dir.join("history.enc");
    fs::write(filepath, encrypted)?;
    Ok(())
}

pub fn load_history(config_dir: &Path, key: &[u8; 32]) -> Result<Vec<StoredMessage>> {
    let filepath = config_dir.join("history.enc");
    if !filepath.exists() {
        return Ok(Vec::new());
    }
    let encrypted = fs::read(filepath)?;
    let decrypted = decrypt_data(key, &encrypted)?;
    let history = serde_json::from_slice(&decrypted)?;
    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = [0x55u8; 32];
        let data = b"Expecto Patronum! LAN messaging is cool.";
        let encrypted = encrypt_data(&key, data).unwrap();
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_peers_save_load() {
        let test_dir = std::path::PathBuf::from("target/test_save_load");
        let _ = std::fs::create_dir_all(&test_dir);
        let key = [0xAAu8; 32];
        let mut peers = HashMap::new();
        peers.insert("AliceNode".to_string(), PeerInfo {
            static_public_key_b64: "a-public-key".to_string(),
            custom_name: Some("Alie".to_string()),
            is_verified: true,
        });

        save_peers(&test_dir, &key, &peers).unwrap();
        let loaded = load_peers(&test_dir, &key).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get("AliceNode").unwrap().custom_name.as_deref(), Some("Alie"));
        assert!(loaded.get("AliceNode").unwrap().is_verified);

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn test_history_save_load() {
        let test_dir = std::path::PathBuf::from("target/test_history_save_load");
        let _ = std::fs::create_dir_all(&test_dir);
        let key = [0x55u8; 32];
        let history = vec![
            StoredMessage {
                peer_id: "BobNode".to_string(),
                from: "Me".to_string(),
                content: "Hello Bob!".to_string(),
                is_system: false,
                ttl: Some(3600),
                timestamp_secs: 123456789,
            },
            StoredMessage {
                peer_id: "BobNode".to_string(),
                from: "BobNode".to_string(),
                content: "Hi!".to_string(),
                is_system: false,
                ttl: None,
                timestamp_secs: 123456790,
            },
        ];

        save_history(&test_dir, &key, &history).unwrap();
        let loaded = load_history(&test_dir, &key).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].peer_id, "BobNode");
        assert_eq!(loaded[0].from, "Me");
        assert_eq!(loaded[0].content, "Hello Bob!");
        assert_eq!(loaded[0].ttl, Some(3600));
        assert_eq!(loaded[1].content, "Hi!");
        assert_eq!(loaded[1].ttl, None);

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
