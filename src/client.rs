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

pub const SUPPORTED_EXTENSIONS: &[&str] = &["compression:zstd", "ratchet:v1", "owl-post:v1"];

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakePacket {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pk: String,
    pub spk: String,
    pub sig: String,
    pub extensions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileOffer {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub file_name: String,
    pub size: u64,
    pub merkle_root: String,
}

pub struct PatronusClient {
    pub crypto: CryptoState,
    pub peer_node_id: Option<String>,
    pub identity_phrase: Option<String>,
    pub selected_compression: Option<String>,
    pub active_extensions: Vec<String>,
    pub peer_extensions: Vec<String>,
}

impl PatronusClient {
    pub fn new(static_key: SigningKey) -> Self {
        Self {
            crypto: CryptoState::new(static_key),
            peer_node_id: None,
            identity_phrase: None,
            selected_compression: None,
            active_extensions: Vec::new(),
            peer_extensions: Vec::new(),
        }
    }

    pub async fn handshake<S>(&mut self, stream: &mut S, is_initiator: bool) -> Result<()>
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
            extensions: SUPPORTED_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
        };

        let handshake_json = serde_json::to_vec(&handshake)?;

        // Write handshake (6.1: 2-byte BE length + JSON)
        if handshake_json.len() > u16::MAX as usize {
            return Err(anyhow!("Handshake packet too large"));
        }
        stream.write_u16(handshake_json.len() as u16).await?;
        stream.write_all(&handshake_json).await?;

        // Read peer handshake
        let peer_handshake_len = stream.read_u16().await?;
        let mut peer_handshake_buf = vec![0u8; peer_handshake_len as usize];
        stream.read_exact(&mut peer_handshake_buf).await?;

        let peer_handshake: HandshakePacket = serde_json::from_slice(&peer_handshake_buf)?;
        self.peer_extensions = peer_handshake.extensions.clone();

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

        // Negotiation (7.5.1 & 7.5.2)
        let my_extensions = &handshake.extensions;
        let peer_extensions = &peer_handshake.extensions;

        let (initiator_exts, responder_exts) = if is_initiator {
            (my_extensions, peer_extensions)
        } else {
            (peer_extensions, my_extensions)
        };

        // Find the first compression algorithm in initiator's list that is also in responder's list
        self.selected_compression = initiator_exts
            .iter()
            .filter(|ext| ext.starts_with("compression:"))
            .find(|ext| responder_exts.contains(ext))
            .cloned();

        if self.selected_compression.is_none() {
            return Err(anyhow!("Handshake Failed (0x01): No common compression algorithm"));
        }

        // Track all agreed extensions
        self.active_extensions = my_extensions
            .iter()
            .filter(|ext| peer_extensions.contains(ext))
            .cloned()
            .collect();

        // Complete handshake
        let phrase = self
            .crypto
            .complete_handshake(&peer_ephemeral_pk, &peer_static_pk, is_initiator)
            .map_err(|e| anyhow!(e))?;

        self.identity_phrase = Some(phrase);
        let peer_node_id = sha2::Sha256::digest(peer_static_pk.as_bytes());
        self.peer_node_id = Some(BASE64.encode(&peer_node_id));

        Ok(())
    }

    pub async fn send_app_message<S>(
        &mut self,
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

    pub async fn send_control_frame<S>(&mut self, stream: &mut S, payload: u8) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let frame = self.encrypt_message(0x02, &[payload])?;
        stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_file_offer<S>(&mut self, stream: &mut S, offer: &FileOffer) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let payload = serde_json::to_vec(offer)?;
        let frame = self.encrypt_message(0x01, &payload)?;
        stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_file_chunk<S>(&mut self, stream: &mut S, key: &[u8; 32], chunk: &[u8]) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        // 0x03: Extension Data
        let mut plaintext = Vec::with_capacity(1 + chunk.len());
        plaintext.push(0x03);
        plaintext.extend_from_slice(chunk);

        // Compression (optional for binary data, but protocol says we MUST use agreed alg)
        let compressed = match self.selected_compression.as_deref() {
            Some("compression:zstd") => zstd::encode_all(Cursor::new(plaintext), 3)?,
            _ => plaintext,
        };

        // Encrypt with file-specific key (NO RATCHET)
        let encrypted = self.crypto.encrypt_with_key(key, &compressed);

        // Frame: 2-byte length + 4-byte 0xFFFFFFFF (sentinel for no ratchet) + 12-byte nonce + payload
        let nonce = &encrypted[..12];
        let ciphertext_and_tag = &encrypted[12..];

        let mut frame = Vec::with_capacity(2 + 4 + 12 + ciphertext_and_tag.len());
        frame.put_u16(ciphertext_and_tag.len() as u16);
        frame.put_u32(0xFFFFFFFF); // Sentinel for "Not a Ratchet Message"
        frame.extend_from_slice(nonce);
        frame.extend_from_slice(ciphertext_and_tag);

        stream.write_all(&frame).await?;
        Ok(())
    }

    pub fn decrypt_file_chunk(&mut self, key: &[u8; 32], frame: &[u8]) -> Result<(u8, Vec<u8>)> {
        // frame contains: nonce(12) + ciphertext+tag
        let decrypted = self
            .crypto
            .decrypt_with_key(key, frame)
            .map_err(|e| anyhow!(e))?;

        let mut decompressed = Vec::new();
        match self.selected_compression.as_deref() {
            Some("compression:zstd") => {
                zstd::Decoder::new(Cursor::new(decrypted))?.read_to_end(&mut decompressed)?;
            }
            _ => decompressed = decrypted,
        }

        if decompressed.is_empty() {
            return Err(anyhow!("Empty payload after decompression"));
        }

        let msg_type = decompressed[0];
        let payload = decompressed[1..].to_vec();

        Ok((msg_type, payload))
    }

    pub async fn receive_message<S>(&mut self, stream: &mut S) -> Result<(u8, Vec<u8>, bool, u32)>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let len = stream.read_u16().await?;
        let ratchet_index = stream.read_u32().await?;
        let mut nonce = [0u8; 12];
        stream.read_exact(&mut nonce).await?;
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await?;

        let is_ratchet = ratchet_index != 0xFFFFFFFF;

        if is_ratchet {
            let mut combined = Vec::with_capacity(4 + 12 + payload.len());
            combined.put_u32(ratchet_index);
            combined.extend_from_slice(&nonce);
            combined.extend_from_slice(&payload);
            let (msg_type, data) = self.decrypt_message(&combined)?;
            Ok((msg_type, data, true, ratchet_index))
        } else {
            // It's a file chunk or other extension data, the caller must provide the key
            let mut combined = Vec::with_capacity(12 + payload.len());
            combined.extend_from_slice(&nonce);
            combined.extend_from_slice(&payload);
            Ok((0x03, combined, false, 0))
        }
    }

    pub fn encrypt_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        // Section 6.3: Message Type (1 byte) + Payload
        let mut plaintext = Vec::with_capacity(1 + payload.len());
        plaintext.push(msg_type);
        plaintext.extend_from_slice(payload);

        // Section 7.5.2: Compression
        let compressed = match self.selected_compression.as_deref() {
            Some("compression:zstd") => zstd::encode_all(Cursor::new(plaintext), 3)?,
            _ => plaintext, // Default to no compression if something is weird, though handshake should prevent this
        };

        // Section 6.2: Encrypted Message Frame + Section 7.1: Ratchet Index
        let (encrypted, ratchet_index) = self.crypto.encrypt(&compressed);

        // encrypted contains: nonce(12) + ciphertext(len) + tag(16)
        // New Frame format:
        // 1. Frame Length: 2 bytes (Ciphertext + Tag)
        // 2. Ratchet Index: 4 bytes
        // 3. Nonce: 12 bytes
        // 4. Ciphertext + Auth Tag

        let nonce = &encrypted[..12];
        let ciphertext_and_tag = &encrypted[12..];

        if ciphertext_and_tag.len() > u16::MAX as usize {
            return Err(anyhow!("Message too large to frame (max {} bytes)", u16::MAX));
        }
        let mut frame = Vec::with_capacity(2 + 4 + 12 + ciphertext_and_tag.len());
        frame.put_u16(ciphertext_and_tag.len() as u16);
        frame.put_u32(ratchet_index);
        frame.extend_from_slice(nonce);
        frame.extend_from_slice(ciphertext_and_tag);

        Ok(frame)
    }

    pub fn decrypt_message(&mut self, frame: &[u8]) -> Result<(u8, Vec<u8>)> {
        if frame.len() < 4 + 12 + 16 {
            return Err(anyhow!("Frame too short"));
        }

        let ratchet_index = u32::from_be_bytes(
            frame[..4]
                .try_into()
                .map_err(|_| anyhow!("Invalid ratchet index bytes"))?,
        );

        let nonce = &frame[4..16];
        let ciphertext_and_tag = &frame[16..];

        let mut data_to_decrypt = Vec::with_capacity(12 + ciphertext_and_tag.len());
        data_to_decrypt.extend_from_slice(nonce);
        data_to_decrypt.extend_from_slice(ciphertext_and_tag);

        let decrypted = self
            .crypto
            .decrypt(&data_to_decrypt, ratchet_index)
            .map_err(|e| anyhow!(e))?;

        // Decompress
        let mut decompressed = Vec::new();
        match self.selected_compression.as_deref() {
            Some("compression:zstd") => {
                zstd::Decoder::new(Cursor::new(decrypted))?.read_to_end(&mut decompressed)?;
            }
            _ => decompressed = decrypted,
        }

        if decompressed.is_empty() {
            return Err(anyhow!("Empty payload after decompression"));
        }

        let msg_type = decompressed[0];
        let payload = decompressed[1..].to_vec();

        Ok((msg_type, payload))
    }
}
