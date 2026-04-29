use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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

    pub fn complete_handshake(
        &mut self,
        peer_public: &PublicKey,
        peer_static_pk: &[u8; 32],
        peer_signature: &[u8],
    ) -> Result<String, &'static str> {
        // verify ephemeral key is bound to peer's static identity
        if !verify_ephemeral(peer_public.as_bytes(), peer_signature, peer_static_pk) {
            return Err("invalid handshake signature");
        }

        let secret = self
            .secret
            .take()
            .ok_or("handshake already completed")?;

        let shared: SharedSecret = secret.diffie_hellman(peer_public);

        // Protocol 4.2: Key Material Extraction
        // Salt: b"patronus-protocol-v1"
        let hk = Hkdf::<Sha256>::new(Some(b"patronus-protocol-v1"), shared.as_bytes());

        // K_enc (Encryption Key): b "session-encryption", 32 bytes
        let mut okm_enc = [0u8; 32];
        hk.expand(b"session-encryption", &mut okm_enc).expect("32 bytes");
        let cipher = Aes256Gcm::new_from_slice(&okm_enc).expect("32-byte key");

        // K_id (Identity Key): b "identity-projection", 3 bytes
        let mut okm_id = [0u8; 3];
        hk.expand(b"identity-projection", &mut okm_id).expect("3 bytes");

        let code = compute_security_code(&okm_id);

        self.session = Some(Session {
            cipher,
        });

        Ok(code)
    }

    pub fn is_ready(&self) -> bool {
        self.session.is_some()
    }

    pub fn encrypt(&self, plaintext: &[u8], topic_id: &[u8; 32]) -> Vec<u8> {
        let session = self.session.as_ref().expect("handshake not completed");
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = Vec::with_capacity(12 + 32);
        aad.extend_from_slice(b"patronus/1.0");
        aad.extend_from_slice(topic_id);

        let ciphertext = session
            .cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .expect("encryption failed");

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, data: &[u8], topic_id: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let session = self.session.as_ref().ok_or("handshake not completed")?;
        if data.len() < 12 {
            return Err("ciphertext too short");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut aad = Vec::with_capacity(12 + 32);
        aad.extend_from_slice(b"patronus/1.0");
        aad.extend_from_slice(topic_id);

        session
            .cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| "decryption failed")
    }
}

// sign ephemeral key with static identity
pub fn sign_ephemeral(ephemeral_pk: &PublicKey, signing_key: &SigningKey) -> Vec<u8> {
    let mut msg = b"patronus-handshake-v1".to_vec();
    msg.extend_from_slice(ephemeral_pk.as_bytes());
    signing_key.sign(&msg).to_bytes().to_vec()
}

// node id is hex(sha256(static pk)) per protocol 1.2
pub fn node_id_from(static_pk: &[u8; 32]) -> String {
    use sha2::Digest;
    Sha256::digest(static_pk).iter().map(|b| format!("{:02x}", b)).collect()
}

fn verify_ephemeral(ephemeral_pk: &[u8; 32], signature: &[u8], static_pk: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(static_pk) else { return false };
    let Ok(sig) = Signature::from_slice(signature) else { return false };
    let mut msg = b"patronus-handshake-v1".to_vec();
    msg.extend_from_slice(ephemeral_pk);
    vk.verify(&msg, &sig).is_ok()
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

        let host_sk = SigningKey::generate(&mut OsRng);
        let peer_sk = SigningKey::generate(&mut OsRng);

        let host_sig = sign_ephemeral(&host.local_public, &host_sk);
        let peer_sig = sign_ephemeral(&peer.local_public, &peer_sk);

        let peer_pub = peer.local_public;
        let host_pub = host.local_public;

        let code_h = host.complete_handshake(
            &peer_pub, &peer_sk.verifying_key().to_bytes(), &peer_sig,
        ).unwrap();
        let code_p = peer.complete_handshake(
            &host_pub, &host_sk.verifying_key().to_bytes(), &host_sig,
        ).unwrap();
        assert_eq!(code_h, code_p, "security codes must match");

        let plaintext = b"test message";
        let topic_id = [0xABu8; 32];
        let encrypted = host.encrypt(plaintext, &topic_id);
        let decrypted = peer.decrypt(&encrypted, &topic_id).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn reject_bad_signature() {
        let mut host = CryptoState::new();
        let peer = CryptoState::new();

        let wrong_sk = SigningKey::generate(&mut OsRng);
        let peer_sk = SigningKey::generate(&mut OsRng);

        // sign with wrong key
        let bad_sig = sign_ephemeral(&peer.local_public, &wrong_sk);

        let result = host.complete_handshake(
            &peer.local_public, &peer_sk.verifying_key().to_bytes(), &bad_sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_topic() {
        let mut host = CryptoState::new();
        let mut peer = CryptoState::new();

        let host_sk = SigningKey::generate(&mut OsRng);
        let peer_sk = SigningKey::generate(&mut OsRng);
        let host_sig = sign_ephemeral(&host.local_public, &host_sk);
        let peer_sig = sign_ephemeral(&peer.local_public, &peer_sk);

        let peer_pub = peer.local_public;
        let host_pub = host.local_public;

        host.complete_handshake(&peer_pub, &peer_sk.verifying_key().to_bytes(), &peer_sig).unwrap();
        peer.complete_handshake(&host_pub, &host_sk.verifying_key().to_bytes(), &host_sig).unwrap();

        let encrypted = host.encrypt(b"secret", &[0x01; 32]);
        assert!(peer.decrypt(&encrypted, &[0x02; 32]).is_err());
    }
}