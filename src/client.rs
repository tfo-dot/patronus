use crate::crypto::CryptoState;
use anyhow::{Result, anyhow};
use data_encoding::BASE64;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::io::Cursor;
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::bytes::BufMut;
use x25519_dalek::PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakePacket {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pk: String,
    pub spk: String,
    pub sig: String,
    pub extensions: Vec<String>,
}

pub struct PatronusClient {
    pub crypto: CryptoState,
    pub peer_node_id: Option<String>,
    pub identity_phrase: Option<String>,
    pub selected_compression: Option<String>,
}

impl PatronusClient {
    pub fn new(static_key: SigningKey) -> Self {
        Self {
            crypto: CryptoState::new(static_key),
            peer_node_id: None,
            identity_phrase: None,
            selected_compression: None,
        }
    }

    pub async fn handshake<S>(&mut self, stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // 1. Prepare our handshake packet
        let ephemeral_pk = self.crypto.local_ephemeral_public;
        let sig = self.crypto.sign_handshake(&ephemeral_pk);
        let spk = self.crypto.static_public();

        let handshake = HandshakePacket {
            msg_type: "handshake".to_string(),
            pk: BASE64.encode(ephemeral_pk.as_bytes()),
            spk: BASE64.encode(spk.as_bytes()),
            sig: BASE64.encode(sig.to_bytes().as_slice()),
            extensions: vec!["compression:zstd".to_string()],
        };

        let handshake_json = serde_json::to_vec(&handshake)?;

        // Write handshake (6.1: 2-byte BE length + JSON)
        stream.write_u16(handshake_json.len() as u16).await?;
        stream.write_all(&handshake_json).await?;

        // Read peer handshake
        let peer_handshake_len = stream.read_u16().await?;
        let mut peer_handshake_buf = vec![0u8; peer_handshake_len as usize];
        stream.read_exact(&mut peer_handshake_buf).await?;

        let peer_handshake: HandshakePacket = serde_json::from_slice(&peer_handshake_buf)?;

        // Verify peer handshake
        let peer_ephemeral_pk_bytes = BASE64.decode(peer_handshake.pk.as_bytes())?;
        let peer_ephemeral_pk: [u8; 32] = peer_ephemeral_pk_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid peer ephemeral key"))?;
        let peer_ephemeral_pk = PublicKey::from(peer_ephemeral_pk);

        let peer_static_pk_bytes = BASE64.decode(peer_handshake.spk.as_bytes())?;
        let peer_static_pk = VerifyingKey::from_bytes(
            &peer_static_pk_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid peer static key"))?,
        )?;

        let peer_sig_bytes = BASE64.decode(peer_handshake.sig.as_bytes())?;
        let peer_sig = Signature::from_bytes(
            &peer_sig_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid peer signature"))?,
        );

        if !self
            .crypto
            .verify_handshake(&peer_static_pk, &peer_ephemeral_pk, &peer_sig)
        {
            return Err(anyhow!("Handshake signature verification failed"));
        }

        // Negotiation (7.5.2)
        self.selected_compression = peer_handshake
            .extensions
            .iter()
            .find(|ext| ext.starts_with("compression:zstd"))
            .map(|ext| ext.to_string());

        if self.selected_compression.is_none() {
            return Err(anyhow!("No common compression algorithm"));
        }

        // Complete handshake
        let phrase = self
            .crypto
            .complete_handshake(&peer_ephemeral_pk, &peer_static_pk)
            .map_err(|e| anyhow!(e))?;

        self.identity_phrase = Some(phrase);
        let peer_node_id = sha2::Sha256::digest(peer_static_pk.as_bytes());
        self.peer_node_id = Some(BASE64.encode(&peer_node_id));

        Ok(())
    }

    pub async fn send_app_message<S>(
        &self,
        stream: &mut S,
        json_content: &serde_json::Value,
    ) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let payload = serde_json::to_vec(json_content)?;
        let frame = self.encrypt_message(0x01, &payload)?; // 0x01: Application Message
        stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn receive_message<S>(&self, stream: &mut S) -> Result<(u8, Vec<u8>)>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        // 6.2: 2-byte length, 12-byte nonce, then length bytes (ciphertext+tag)
        let len = stream.read_u16().await?;
        let mut nonce = [0u8; 12];
        stream.read_exact(&mut nonce).await?;
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await?;

        let mut combined = Vec::with_capacity(12 + payload.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&payload);

        self.decrypt_message(&combined)
    }

    pub fn encrypt_message(&self, msg_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        // Section 6.3: Message Type (1 byte) + Payload
        let mut plaintext = Vec::with_capacity(1 + payload.len());
        plaintext.push(msg_type);
        plaintext.extend_from_slice(payload);

        // Section 7.5.2: Compression (zstd)
        let compressed = zstd::encode_all(Cursor::new(plaintext), 3)?;

        // Section 6.2: Encrypted Message Frame
        // 12 bytes nonce is prepended by crypto.encrypt
        let encrypted = self.crypto.encrypt(&compressed);

        // encrypted contains: nonce(12) + ciphertext(len) + tag(16)
        // Protocol 6.2 says:
        // 1. Frame Length: 2 bytes (Ciphertext + Tag)
        // 2. Nonce: 12 bytes
        // 3. Ciphertext
        // 4. Auth Tag

        let nonce = &encrypted[..12];
        let ciphertext_and_tag = &encrypted[12..];

        let mut frame = Vec::with_capacity(2 + 12 + ciphertext_and_tag.len());
        frame.put_u16(ciphertext_and_tag.len() as u16);
        frame.extend_from_slice(nonce);
        frame.extend_from_slice(ciphertext_and_tag);

        Ok(frame)
    }

    pub fn decrypt_message(&self, frame: &[u8]) -> Result<(u8, Vec<u8>)> {
        if frame.len() < 12 + 16 {
            return Err(anyhow!("Frame too short"));
        }

        let nonce = &frame[..12];
        let ciphertext_and_tag = &frame[12..];

        let mut data_to_decrypt = Vec::with_capacity(12 + ciphertext_and_tag.len());
        data_to_decrypt.extend_from_slice(nonce);
        data_to_decrypt.extend_from_slice(ciphertext_and_tag);

        let decrypted = self
            .crypto
            .decrypt(&data_to_decrypt)
            .map_err(|e| anyhow!(e))?;

        // Decompress
        let mut decompressed = Vec::new();
        zstd::Decoder::new(Cursor::new(decrypted))?.read_to_end(&mut decompressed)?;

        if decompressed.is_empty() {
            return Err(anyhow!("Empty payload after decompression"));
        }

        let msg_type = decompressed[0];
        let payload = decompressed[1..].to_vec();

        Ok((msg_type, payload))
    }
}
