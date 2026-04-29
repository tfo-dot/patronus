use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use serde_json::Value;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use hkdf::Hkdf;

pub struct CryptoState {
    secret: Option<EphemeralSecret>,
    pub local_public: PublicKey,
    session: Option<Session>,
}

struct Session {
    cipher: Aes256Gcm,
}

impl CryptoState {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            local_public,
            session: None,
        }
    }

    pub fn complete_handshake(&mut self, peer_public: &PublicKey) -> String {
        let secret = self
            .secret
            .take()
            .expect("handshake already completed");

        let shared: SharedSecret = secret.diffie_hellman(peer_public);

        // Protocol 4.2: Key Material Extraction
        // Salt: b"patronus-protocol-v1"
        let hk = Hkdf::<Sha256>::new(Some(b"patronus-protocol-v1"), shared.as_bytes());
        
        // K_enc (Encryption Key): b"session-encryption", 32 bytes
        let mut okm_enc = [0u8; 32];
        hk.expand(b"session-encryption", &mut okm_enc).expect("32 bytes");
        let cipher = Aes256Gcm::new_from_slice(&okm_enc).expect("32-byte key");

        // K_id (Identity Key): b"identity-projection", 3 bytes
        let mut okm_id = [0u8; 3];
        hk.expand(b"identity-projection", &mut okm_id).expect("3 bytes");

        let code = compute_security_code(&okm_id);

        self.session = Some(Session {
            cipher,
        });

        code
    }

    pub fn is_ready(&self) -> bool {
        self.session.is_some()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let session = self.session.as_ref().expect("handshake not completed");
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = session
            .cipher
            .encrypt(nonce, plaintext)
            .expect("encryption failed");

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let session = self.session.as_ref().ok_or("handshake not completed")?;
        if data.len() < 12 {
            return Err("ciphertext too short");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        session
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "decryption failed")
    }
}

fn compute_security_code(k_id: &[u8; 3]) -> String {
    let wordlists_raw = include_str!("../assets/wordlists.json");
    let wordlists: Value = serde_json::from_str(wordlists_raw).expect("valid json");
    
    let adjectives = wordlists["adjectives"].as_array().expect("adjectives array");
    let colors = wordlists["colors"].as_array().expect("colors array");
    let spirits = wordlists["spirits"].as_array().expect("spirits array");

    let w0 = adjectives[k_id[0] as usize].as_str().unwrap();
    let w1 = colors[k_id[1] as usize].as_str().unwrap();
    let w2 = spirits[k_id[2] as usize].as_str().unwrap();

    format!("{} {} {}", capitalize(w0), capitalize(w1), capitalize(w2))
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let mut host = CryptoState::new();
        let mut peer = CryptoState::new();

        let peer_pub = peer.local_public;
        let host_pub = host.local_public;

        let code_h = host.complete_handshake(&peer_pub);
        let code_p = peer.complete_handshake(&host_pub);
        assert_eq!(code_h, code_p, "security codes must match");

        let plaintext = b"test message";
        let encrypted = host.encrypt(plaintext);
        let decrypted = peer.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}