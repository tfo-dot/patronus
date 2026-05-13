use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub struct CryptoState {
    static_key: SigningKey,
    ephemeral_secret: Option<EphemeralSecret>,
    pub local_ephemeral_public: PublicKey,
    session: Option<Session>,
}

struct Session {
    k_enc: [u8; 32],
    topic_id: [u8; 32],
    ratchet_send: u32,
    ratchet_recv: u32,
}

impl CryptoState {
    pub fn new(static_key: SigningKey) -> Self {
        let mut rng = OsRng;
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
        let local_ephemeral_public = PublicKey::from(&ephemeral_secret);
        Self {
            static_key,
            ephemeral_secret: Some(ephemeral_secret),
            local_ephemeral_public,
            session: None,
        }
    }

    pub fn static_public(&self) -> VerifyingKey {
        self.static_key.verifying_key()
    }

    pub fn sign_handshake(&self, ephemeral_public: &PublicKey) -> Signature {
        let mut data = Vec::new();
        data.extend_from_slice(b"patronus-handshake-v1");
        data.extend_from_slice(ephemeral_public.as_bytes());
        self.static_key.sign(&data)
    }

    pub fn verify_handshake(
        &self,
        peer_static_public: &VerifyingKey,
        peer_ephemeral_public: &PublicKey,
        signature: &Signature,
    ) -> bool {
        let mut data = Vec::new();
        data.extend_from_slice(b"patronus-handshake-v1");
        data.extend_from_slice(peer_ephemeral_public.as_bytes());
        peer_static_public.verify(&data, signature).is_ok()
    }

    pub fn complete_handshake(
        &mut self,
        peer_ephemeral_public: &PublicKey,
        peer_static_public: &VerifyingKey,
    ) -> Result<String, &'static str> {
        let secret = self
            .ephemeral_secret
            .take()
            .ok_or("handshake already completed")?;

        let shared: SharedSecret = secret.diffie_hellman(peer_ephemeral_public);

        // Protocol 4.2: Key Material Extraction
        // Salt: b"patronus-protocol-v1"
        let hk = Hkdf::<Sha256>::new(Some(b"patronus-protocol-v1"), shared.as_bytes());

        // K_enc (Encryption Key): b"session-encryption", 32 bytes
        let mut okm_enc = [0u8; 32];
        hk.expand(b"session-encryption", &mut okm_enc)
            .map_err(|_| "HKDF expand failed")?;

        // K_id (Identity Key): b"identity-projection", 3 bytes
        let mut okm_id = [0u8; 3];
        hk.expand(b"identity-projection", &mut okm_id)
            .map_err(|_| "HKDF expand failed")?;

        let code = compute_security_code(&okm_id);

        // Topic ID for AAD (could be derived or negotiated, protocol 6.4 says 32 bytes)
        let mut hasher = Sha256::new();
        let mut keys = [
            *self.static_public().as_bytes(),
            *peer_static_public.as_bytes(),
        ];
        keys.sort();
        hasher.update(keys[0]);
        hasher.update(keys[1]);
        let topic_id: [u8; 32] = hasher.finalize().into();

        self.session = Some(Session {
            k_enc: okm_enc,
            topic_id,
            ratchet_send: 0,
            ratchet_recv: 0,
        });

        Ok(code)
    }

    fn advance_key(k_enc: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, k_enc);
        let mut next_k_enc = [0u8; 32];
        hk.expand(b"time-turner-ratchet", &mut next_k_enc)
            .expect("HKDF expand failed");
        next_k_enc
    }

    fn compute_aad(topic_id: &[u8; 32]) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"patronus/1.0");
        aad.extend_from_slice(topic_id);
        aad
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, u32) {
        let session = self.session.as_mut().expect("handshake not completed");
        let aad = Self::compute_aad(&session.topic_id);

        // Advance ratchet
        session.ratchet_send += 1;
        session.k_enc = Self::advance_key(&session.k_enc);

        let cipher = Aes256Gcm::new_from_slice(&session.k_enc).expect("invalid key length");

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: &aad,
        };

        let ciphertext = cipher.encrypt(nonce, payload).expect("encryption failed");

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        (out, session.ratchet_send)
    }

    pub fn decrypt(&mut self, data: &[u8], remote_ratchet: u32) -> Result<Vec<u8>, &'static str> {
        let session = self.session.as_mut().ok_or("handshake not completed")?;

        if remote_ratchet <= session.ratchet_recv {
            return Err("stale or replayed ratchet index");
        }

        let steps = remote_ratchet - session.ratchet_recv;

        if steps > 50 {
            return Err("ratched index jumped too far ahead");
        }

        let mut temp_key = session.k_enc;
        for _ in 0..steps {
            temp_key = Self::advance_key(&temp_key)
        }

        let aad = Self::compute_aad(&session.topic_id);
        let cipher = Aes256Gcm::new_from_slice(&temp_key).map_err(|_| "invalid key length")?;

        if data.len() < 12 + 16 {
            // nonce + tag
            return Err("ciphertext too short");
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let decrypted = cipher
            .decrypt(nonce, payload)
            .map_err(|_| "decryption failed")?;

        session.k_enc = temp_key;
        session.ratchet_recv = remote_ratchet;

        Ok(decrypted)
    }
}

fn compute_security_code(k_id: &[u8; 3]) -> String {
    let wordlists_raw = include_str!("../assets/wordlists.json");
    let wordlists: Value = serde_json::from_str(wordlists_raw).expect("valid json");

    let adjectives = wordlists["adjectives"]
        .as_array()
        .expect("adjectives array");
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
