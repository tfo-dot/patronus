use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use bip39::Language;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

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

        let key = Sha256::digest(shared.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");

        let code = compute_security_code(&self.local_public, peer_public);

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

fn compute_security_code(a: &PublicKey, b: &PublicKey) -> String {
    let wordlist = Language::English.word_list();

    let (first, second) = if a.as_bytes() < b.as_bytes() {
        (a.as_bytes(), b.as_bytes())
    } else {
        (b.as_bytes(), a.as_bytes())
    };

    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    (0..5)
        .map(|i| {
            let idx = u16::from_be_bytes([hash[i * 2], hash[i * 2 + 1]]) as usize % 2048;
            wordlist[idx]
        })
        .collect::<Vec<_>>()
        .join(" ")
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