use crate::crypto::CryptoState;
use anyhow::{Result, anyhow};
use data_encoding::BASE64;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::io::Cursor;
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tokio_util::bytes::BufMut;
use x25519_dalek::PublicKey;

pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "compression:zstd",
    "ratchet:v1",
    "owl-post:v1",
    "vanishing_ink:v1",
];

pub const CTRL_PING: u8 = 0x01;
pub const CTRL_PONG: u8 = 0x02;
pub const CTRL_BYE: u8 = 0x03;

pub const KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
pub const KEEP_ALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone)]
pub enum OutboundMessage {
    Message { target: String, text: String, ttl: Option<u64> },
    TTLNotice { target: String, ttl: Option<u64> },
}

#[derive(Debug, Clone)]
pub enum UiEvent {
    Message {
        from: String,
        text: String,
        is_system: bool,
        ttl: Option<u64>,
        group: Option<String>,
    },
    HandshakeComplete(String),
    PeerUpdate {
        id: String,
        name: String,
        addr: String,
    },
    FileProgress {
        peer_id: String,
        file_name: String,
        total_size: u64,
        bytes_transferred: u64,
        is_sending: bool,
    },
}

pub fn sys_msg(text: impl Into<String>) -> UiEvent {
    UiEvent::Message {
        from: "System".to_string(),
        text: text.into(),
        is_system: true,
        ttl: None,
        group: None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakePacket {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pk: String,
    pub spk: String,
    pub sig: String,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    pub file_name: String,
    pub size: u64,
    pub merkle_root: String,
}

pub struct PatronusClient {
    pub crypto: CryptoState,
    pub peer_node_id: Option<String>,
    pub peer_static_pk: Option<String>,
    pub identity_phrase: Option<String>,
    pub selected_compression: Option<String>,
    pub active_extensions: Vec<String>,
    pub peer_extensions: Vec<String>,

    // Session / Connection State fields
    pub save_dir: std::path::PathBuf,
    pub receiving_file: Option<(tokio::fs::File, String, u64)>,
    pub receiving_key: Option<[u8; 32]>,
    pub receiving_bytes_seen: u64,
    pub pending_send_file: Option<(std::path::PathBuf, [u8; 32], String)>,
    pub active_send_file: Option<(tokio::fs::File, [u8; 32], u64, u64, String)>,
    pub pending_recv_offer: Option<FileOffer>,
    pub pending_pong: bool,
    pub last_ping: std::time::Instant,
    pub send_bye: bool,
}

impl PatronusClient {
    pub fn new(static_key: SigningKey, initial_save_dir: Option<String>) -> Self {
        let save_dir = initial_save_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("downloads"));

        Self {
            crypto: CryptoState::new(static_key),
            peer_node_id: None,
            peer_static_pk: None,
            identity_phrase: None,
            selected_compression: None,
            active_extensions: Vec::new(),
            peer_extensions: Vec::new(),
            save_dir,
            receiving_file: None,
            receiving_key: None,
            receiving_bytes_seen: 0,
            pending_send_file: None,
            active_send_file: None,
            pending_recv_offer: None,
            pending_pong: false,
            last_ping: std::time::Instant::now(),
            send_bye: true,
        }
    }

    pub async fn handshake<S>(
        &mut self,
        stream: &mut S,
        is_initiator: bool,
        trusted_peers: &std::collections::HashMap<String, crate::storage::PeerInfo>,
    ) -> Result<()>
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
            return Err(anyhow!(
                "Handshake Failed (0x01): No common compression algorithm"
            ));
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

        let peer_node_id_bytes = sha2::Sha256::digest(peer_static_pk.as_bytes());
        let peer_node_id_str = BASE64.encode(&peer_node_id_bytes);

        if let Some(existing) = trusted_peers.get(&peer_node_id_str) {
            let existing_pk_bytes = BASE64.decode(existing.static_public_key_b64.as_bytes())?;
            if existing_pk_bytes != peer_static_pk.as_bytes() {
                return Err(anyhow!("Security Violation (0x03): TOFU public key mismatch for peer {}", peer_node_id_str));
            }
        }

        self.identity_phrase = Some(phrase);
        self.peer_node_id = Some(peer_node_id_str);
        self.peer_static_pk = Some(BASE64.encode(peer_static_pk.as_bytes()));

        Ok(())
    }

    pub async fn tick_keep_alive<S>(&mut self, stream: &mut S, ui_tx: &mpsc::Sender<UiEvent>) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        if self.pending_pong && self.last_ping.elapsed() >= KEEP_ALIVE_TIMEOUT {
            let peer_id = self.peer_node_id.as_deref().unwrap_or("Unknown");
            let _ = ui_tx.send(sys_msg(format!("Connection timed out: {peer_id}"))).await;
            self.send_bye = false;
            return Err(anyhow!("Connection timed out"));
        }

        if !self.pending_pong {
            self.pending_pong = true;
            self.last_ping = std::time::Instant::now();
            self.send_control_frame(stream, CTRL_PING).await?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn handle_incoming<S>(&mut self, stream: &mut S, ui_tx: &mpsc::Sender<UiEvent>) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let res = self.receive_message(stream).await;
        let peer_id = self.peer_node_id.clone().unwrap_or_else(|| "Unknown".to_string());

        match res {
            Ok((0x01, payload, _, _)) => {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    let text = json["text"].as_str().ok_or_else(|| anyhow!("Invalid text field"))?;
                    let ttl = json["ttl"].as_u64();
                    let group = json["group"].as_str().map(|s| s.to_string());

                    let _ = ui_tx.send(UiEvent::Message {
                        from: peer_id,
                        text: text.to_string(),
                        is_system: false,
                        ttl,
                        group,
                    }).await;
                }
            }
            Ok((0x03, payload, true, _)) => {
                let json = serde_json::from_slice::<serde_json::Value>(&payload)?;

                if json.get("ttl_notice").is_some() {
                    let peer_ttl = json["ttl_notice"].as_u64();
                    let msg = match peer_ttl {
                        Some(s) => format!("Peer messages will disappear after {}", crate::tui::format_ttl(s)),
                        None => "Peer disabled message TTL".to_string(),
                    };
                    let _ = ui_tx.send(sys_msg(msg)).await;
                } else if let Some(offer_val) = json.get("file_offer") {
                    if let Ok(offer) = serde_json::from_value::<FileOffer>(offer_val.clone()) {
                        self.pending_recv_offer = Some(offer.clone());

                        let _ = ui_tx.send(sys_msg(format!("Received file offer: {} ({} bytes)", offer.file_name, offer.size))).await;
                        let _ = ui_tx.send(sys_msg("To accept, type: '/accept' or '/accept <path>'")).await;
                        let _ = ui_tx.send(sys_msg("To decline, type: '/decline'")).await;
                    }
                } else if let Some(accept_val) = json.get("file_accept") {
                    if let Some(_merkle_root) = accept_val.get("merkle_root").and_then(|v| v.as_str()) {
                        if let Some((path, file_key, file_name)) = self.pending_send_file.take() {
                            let start_offset = accept_val.get("start_offset").and_then(|v| v.as_u64()).unwrap_or(0);
                            let _ = ui_tx.send(sys_msg(format!("Peer accepted. Transmitting file: {file_name} starting at offset {start_offset}..."))).await;

                            match tokio::fs::File::open(&path).await {
                                Ok(mut file) => {
                                    let total_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                                    if start_offset > 0 {
                                        if let Err(e) = file.seek(std::io::SeekFrom::Start(start_offset)).await {
                                            let _ = ui_tx.send(sys_msg(format!("Failed to seek to offset {start_offset}: {e}"))).await;
                                            return Ok(());
                                        }
                                    }

                                    let mut chunk_buffer = vec![0u8; 16384]; // 16KB chunks
                                    let mut sent_bytes = 0;
                                    let mut error_occurred = false;

                                    while let Ok(n) = file.read(&mut chunk_buffer).await {
                                        if n == 0 { break; }

                                        if let Err(e) = self.send_file_chunk(stream, &file_key, &chunk_buffer[..n]).await {
                                            let _ = ui_tx.send(sys_msg(format!("Error sending file chunk: {e}"))).await;
                                            error_occurred = true;
                                            break;
                                        }

                                        sent_bytes += n as u64;
                                        let _ = ui_tx.try_send(UiEvent::FileProgress {
                                            peer_id: peer_id.clone(),
                                            file_name: file_name.clone(),
                                            total_size,
                                            bytes_transferred: start_offset + sent_bytes,
                                            is_sending: true,
                                        });
                                    }

                                    if !error_occurred {
                                        let _ = ui_tx.send(sys_msg(format!("Finished sending {file_name} ({} bytes)", start_offset + sent_bytes))).await;
                                    }
                                }
                                Err(e) => {
                                    let _ = ui_tx.send(sys_msg(format!("Failed to open file for sending: {e}"))).await;
                                }
                            }
                        }
                    }
                } else if let Some(decline_val) = json.get("file_decline") {
                    if let Some(_merkle_root) = decline_val.get("merkle_root").and_then(|v| v.as_str()) {
                        if let Some((_, _, file_name)) = self.pending_send_file.take() {
                            let _ = ui_tx.send(sys_msg(format!("Peer declined file transfer of: {file_name}"))).await;
                        }
                    }
                }
            }
            Ok((0x02, payload, _, _)) => {
                match payload.first().copied() {
                    Some(CTRL_PING) => {
                        self.send_control_frame(stream, CTRL_PONG).await?;
                    }
                    Some(CTRL_PONG) => {
                        self.pending_pong = false;
                    }
                    Some(CTRL_BYE) => {
                        self.send_bye = false;
                        return Err(anyhow!("Peer disconnected gracefully via CTRL_BYE"));
                    }
                    _ => {}
                }
            }
            Ok((0x03, payload, false, _)) => {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    if json.get("ttl_notice").is_some() {
                        let msg = match json["ttl_notice"].as_u64() {
                            Some(s) => format!("Peer messages will disappear after {}", crate::tui::format_ttl(s)),
                            None => "Peer disabled message TTL".to_string(),
                        };
                        let _ = ui_tx.send(sys_msg(msg)).await;
                    } else {
                        let _ = ui_tx.send(sys_msg(format!(
                            "Got unknown extension packet data: `{}...`",
                            json.to_string().chars().take(16).collect::<String>()
                        ))).await;
                    }
                } else if let (Some((mut file, name, size)), Some(key)) = (self.receiving_file.take(), self.receiving_key) {
                    match self.decrypt_file_chunk(&key, &payload) {
                        Ok((0x03, chunk)) => {
                            file.write_all(&chunk).await?;
                            self.receiving_bytes_seen += chunk.len() as u64;
                            let current_seen = self.receiving_bytes_seen;

                            let _ = ui_tx.try_send(UiEvent::FileProgress {
                                peer_id: peer_id.clone(),
                                file_name: name.clone(),
                                total_size: size,
                                bytes_transferred: current_seen,
                                is_sending: false,
                            });

                            if current_seen >= size {
                                let _ = ui_tx.send(sys_msg(format!("File transfer complete: {name}"))).await;
                                self.receiving_file = None;
                                self.receiving_key = None;
                            } else {
                                self.receiving_file = Some((file, name, size));
                            }
                        }
                        _ => {
                            let _ = ui_tx.send(sys_msg("Failed to decrypt file chunk")).await;
                            return Err(anyhow!("Failed to decrypt file chunk"));
                        }
                    }
                }
            }
            Ok((msg_type, _, _, _)) => {
                let _ = ui_tx.send(sys_msg(format!("Unknown message type: 0x{msg_type:02x}"))).await;
                return Err(anyhow!("Unknown message type: 0x{msg_type:02x}"));
            }
            Err(e) => {
                self.send_bye = false;
                return Err(e);
            }
        }
        Ok(())
    }

    pub async fn handle_incoming_frame<W>(
        &mut self,
        frame_bytes: &[u8],
        writer: &mut W,
        ui_tx: &mpsc::Sender<UiEvent>,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let peer_id = self.peer_node_id.clone().unwrap_or_else(|| "Unknown".to_string());

        if frame_bytes.len() < 18 {
            return Err(anyhow!("Frame too short"));
        }
        let len = u16::from_be_bytes(frame_bytes[0..2].try_into()?);
        let ratchet_index = u32::from_be_bytes(frame_bytes[2..6].try_into()?);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&frame_bytes[6..18]);
        let payload = &frame_bytes[18..];

        if payload.len() != len as usize {
            return Err(anyhow!("Payload length mismatch"));
        }

        let is_ratchet = ratchet_index != 0xFFFFFFFF;

        let res = if is_ratchet {
            let mut combined = Vec::with_capacity(4 + 12 + payload.len());
            combined.put_u32(ratchet_index);
            combined.extend_from_slice(&nonce);
            combined.extend_from_slice(payload);
            let (msg_type, data) = self.decrypt_message(&combined)?;
            Ok((msg_type, data, true, ratchet_index))
        } else {
            // It's a file chunk or other extension data, the caller must provide the key
            let mut combined = Vec::with_capacity(12 + payload.len());
            combined.extend_from_slice(&nonce);
            combined.extend_from_slice(payload);
            Ok((0x03, combined, false, 0))
        };

        match res {
            Ok((0x01, payload, _, _)) => {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    let text = json["text"].as_str().ok_or_else(|| anyhow!("Invalid text field"))?;
                    let ttl = json["ttl"].as_u64();
                    let group = json["group"].as_str().map(|s| s.to_string());

                    let _ = ui_tx.send(UiEvent::Message {
                        from: peer_id,
                        text: text.to_string(),
                        is_system: false,
                        ttl,
                        group,
                    }).await;
                }
            }
            Ok((0x03, payload, true, _)) => {
                let json = serde_json::from_slice::<serde_json::Value>(&payload)?;

                if json.get("ttl_notice").is_some() {
                    let peer_ttl = json["ttl_notice"].as_u64();
                    let msg = match peer_ttl {
                        Some(s) => format!("Peer messages will disappear after {}", crate::tui::format_ttl(s)),
                        None => "Peer disabled message TTL".to_string(),
                    };
                    let _ = ui_tx.send(sys_msg(msg)).await;
                } else if let Some(offer_val) = json.get("file_offer") {
                    if let Ok(offer) = serde_json::from_value::<FileOffer>(offer_val.clone()) {
                        self.pending_recv_offer = Some(offer.clone());

                        let _ = ui_tx.send(sys_msg(format!("Received file offer: {} ({} bytes)", offer.file_name, offer.size))).await;
                        let _ = ui_tx.send(sys_msg("To accept, type: '/accept' or '/accept <path>'")).await;
                        let _ = ui_tx.send(sys_msg("To decline, type: '/decline'")).await;
                    }
                } else if let Some(accept_val) = json.get("file_accept") {
                    if let Some(_merkle_root) = accept_val.get("merkle_root").and_then(|v| v.as_str()) {
                        if let Some((path, file_key, file_name)) = self.pending_send_file.take() {
                            let start_offset = accept_val.get("start_offset").and_then(|v| v.as_u64()).unwrap_or(0);
                            let _ = ui_tx.send(sys_msg(format!("Peer accepted. Transmitting file: {file_name} starting at offset {start_offset}..."))).await;

                            match tokio::fs::File::open(&path).await {
                                Ok(mut file) => {
                                    let total_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                                    if start_offset > 0 {
                                        if let Err(e) = file.seek(std::io::SeekFrom::Start(start_offset)).await {
                                            let _ = ui_tx.send(sys_msg(format!("Failed to seek to offset {start_offset}: {e}"))).await;
                                            return Ok(());
                                        }
                                    }
                                    self.active_send_file = Some((file, file_key, total_size, start_offset, file_name));
                                }
                                Err(e) => {
                                    let _ = ui_tx.send(sys_msg(format!("Failed to open file for sending: {e}"))).await;
                                }
                            }
                        }
                    }
                } else if let Some(decline_val) = json.get("file_decline") {
                    if let Some(_merkle_root) = decline_val.get("merkle_root").and_then(|v| v.as_str()) {
                        if let Some((_, _, file_name)) = self.pending_send_file.take() {
                            let _ = ui_tx.send(sys_msg(format!("Peer declined file transfer of: {file_name}"))).await;
                        }
                    }
                }
            }
            Ok((0x02, payload, _, _)) => {
                match payload.first().copied() {
                    Some(CTRL_PING) => {
                        self.send_control_frame(writer, CTRL_PONG).await?;
                    }
                    Some(CTRL_PONG) => {
                        self.pending_pong = false;
                    }
                    Some(CTRL_BYE) => {
                        self.send_bye = false;
                        return Err(anyhow!("Peer disconnected gracefully via CTRL_BYE"));
                    }
                    _ => {}
                }
            }
            Ok((0x03, payload, false, _)) => {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    if json.get("ttl_notice").is_some() {
                        let msg = match json["ttl_notice"].as_u64() {
                            Some(s) => format!("Peer messages will disappear after {}", crate::tui::format_ttl(s)),
                            None => "Peer disabled message TTL".to_string(),
                        };
                        let _ = ui_tx.send(sys_msg(msg)).await;
                    } else {
                        let _ = ui_tx.send(sys_msg(format!(
                            "Got unknown extension packet data: `{}...`",
                            json.to_string().chars().take(16).collect::<String>()
                        ))).await;
                    }
                } else if let (Some((mut file, name, size)), Some(key)) = (self.receiving_file.take(), self.receiving_key) {
                    match self.decrypt_file_chunk(&key, &payload) {
                        Ok((0x03, chunk)) => {
                            file.write_all(&chunk).await?;
                            self.receiving_bytes_seen += chunk.len() as u64;
                            let current_seen = self.receiving_bytes_seen;

                            let _ = ui_tx.try_send(UiEvent::FileProgress {
                                peer_id: peer_id.clone(),
                                file_name: name.clone(),
                                total_size: size,
                                bytes_transferred: current_seen,
                                is_sending: false,
                            });

                            if current_seen >= size {
                                let _ = ui_tx.send(sys_msg(format!("File transfer complete: {name}"))).await;
                                self.receiving_file = None;
                                self.receiving_key = None;
                            } else {
                                self.receiving_file = Some((file, name, size));
                            }
                        }
                        _ => {
                            let _ = ui_tx.send(sys_msg("Failed to decrypt file chunk")).await;
                            return Err(anyhow!("Failed to decrypt file chunk"));
                        }
                    }
                }
            }
            Ok((msg_type, _, _, _)) => {
                let _ = ui_tx.send(sys_msg(format!("Unknown message type: 0x{msg_type:02x}"))).await;
                return Err(anyhow!("Unknown message type: 0x{msg_type:02x}"));
            }
            Err(e) => {
                self.send_bye = false;
                return Err(e);
            }
        }
        Ok(())
    }

    pub async fn send_active_file_chunk<W>(
        &mut self,
        writer: &mut W,
        ui_tx: &mpsc::Sender<UiEvent>,
    ) -> Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let peer_id = self.peer_node_id.clone().unwrap_or_else(|| "Unknown".to_string());
        let mut file_done = false;
        let mut error_occurred = None;

        if let Some((mut file, file_key, total_size, mut sent_bytes, file_name)) = self.active_send_file.take() {
            let mut chunk_buffer = vec![0u8; 16384]; // 16KB chunks
            let mut more_chunks = true;
            match file.read(&mut chunk_buffer).await {
                Ok(0) => {
                    file_done = true;
                    more_chunks = false;
                }
                Ok(n) => {
                    if let Err(e) = self.send_file_chunk(writer, &file_key, &chunk_buffer[..n]).await {
                        error_occurred = Some(e);
                        more_chunks = false;
                    } else {
                        sent_bytes += n as u64;
                        let _ = ui_tx.try_send(UiEvent::FileProgress {
                            peer_id: peer_id.clone(),
                            file_name: file_name.clone(),
                            total_size,
                            bytes_transferred: sent_bytes,
                            is_sending: true,
                        });
                    }
                }
                Err(e) => {
                    error_occurred = Some(e.into());
                    more_chunks = false;
                }
            }

            if more_chunks {
                self.active_send_file = Some((file, file_key, total_size, sent_bytes, file_name.clone()));
            }

            if let Some(err) = error_occurred {
                let _ = ui_tx.send(sys_msg(format!("Error sending file chunk for {file_name}: {err}"))).await;
                return Err(err);
            }

            if file_done {
                let _ = ui_tx.send(sys_msg(format!("Finished sending {file_name} ({total_size} bytes)"))).await;
                return Ok(false);
            }

            Ok(more_chunks)
        } else {
            Ok(false)
        }
    }


    pub async fn handle_outbound_msg<W>(
        &mut self,
        stream: &mut W,
        msg: OutboundMessage,
        ui_tx: &mpsc::Sender<UiEvent>,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        match msg {
            OutboundMessage::Message { target, text, ttl } => {
                // We keep track of the target context (e.g. if it is a group message)
                // in send_app_message. We pass the full OutboundMessage to handle_outbound_command
                // so it can propagate the target properly.
                self.handle_outbound_command(stream, target, text, ttl, ui_tx).await
            }
            OutboundMessage::TTLNotice { target, ttl } => {
                if let Err(e) = self.send_app_message(stream, OutboundMessage::TTLNotice { target, ttl }).await {
                    self.send_bye = false;
                    return Err(e);
                }
                Ok(())
            }
        }
    }

    pub async fn handle_outbound_command<W>(
        &mut self,
        stream: &mut W,
        target: String,
        text: String,
        ttl: Option<u64>,
        ui_tx: &mpsc::Sender<UiEvent>,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        if text.starts_with("/send ") {
            if self.pending_send_file.is_some() {
                let _ = ui_tx.send(sys_msg(
                    "A file offer is already pending. Please wait until the peer accepts or declines."
                )).await;
                return Ok(());
            }

            let path_str = text.strip_prefix("/send ").unwrap().trim();
            let path = std::path::Path::new(path_str);

            if !path.exists() {
                let _ = ui_tx.send(sys_msg(format!("File not found: {path_str}"))).await;
                return Ok(());
            }

            let file_name = path.file_name().unwrap().to_string_lossy().to_string();
            let metadata = std::fs::metadata(path)?;
            let size = metadata.len();

            let mut hasher = blake3::Hasher::new();
            let mut file = tokio::fs::File::open(path).await?;
            let mut buffer = vec![0u8; 64 * 1024];
            while let Ok(n) = file.read(&mut buffer).await {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }

            let merkle_root = hasher.finalize().to_hex().to_string();

            let offer = FileOffer {
                file_name: file_name.clone(),
                size,
                merkle_root: merkle_root.clone(),
            };

            if let Err(e) = self.send_file_offer(stream, &offer).await {
                let _ = ui_tx.send(sys_msg(format!("Failed to send file offer: {e}"))).await;
                return Ok(());
            }

            let _ = ui_tx.send(sys_msg(format!(
                "Offered file: {file_name} ({size} bytes). Waiting for peer to accept/decline..."
            ))).await;

            let file_key = self
                .crypto
                .derive_file_key(merkle_root.as_bytes())
                .map_err(|e| anyhow!(e))?;

            self.pending_send_file = Some((path.to_path_buf(), file_key, file_name));
            return Ok(());
        }

        if text.starts_with("/save_dir ") {
            let path_str = text.strip_prefix("/save_dir ").unwrap().trim();
            if path_str.is_empty() {
                let _ = ui_tx.send(sys_msg(format!("Current save directory: {}", self.save_dir.display()))).await;
                return Ok(());
            }

            let new_path = std::path::PathBuf::from(path_str);
            match tokio::fs::create_dir_all(&new_path).await {
                Ok(_) => {
                    self.save_dir = new_path;
                    let _ = ui_tx.send(sys_msg(format!("Save directory set to: {}", self.save_dir.display()))).await;
                }
                Err(e) => {
                    let _ = ui_tx.send(sys_msg(format!("Failed to create/set save directory: {e}"))).await;
                }
            }
            return Ok(());
        }

        if text == "/save_dir" {
            let _ = ui_tx.send(sys_msg(format!("Current save directory: {}", self.save_dir.display()))).await;
            return Ok(());
        }

        if text.starts_with("/accept") {
            if self.pending_recv_offer.is_none() {
                let _ = ui_tx.send(sys_msg("No pending file offer to accept.")).await;
                return Ok(());
            }

            let offer = self.pending_recv_offer.take().unwrap();
            let path_arg = text.strip_prefix("/accept").unwrap().trim();

            let target_path = if path_arg.is_empty() {
                self.save_dir.join(&offer.file_name)
            } else {
                let path = std::path::Path::new(path_arg);
                if path.is_dir() || path_arg.ends_with('/') || path_arg.ends_with('\\') {
                    path.join(&offer.file_name)
                } else {
                    path.to_path_buf()
                }
            };

            if let Some(parent) = target_path.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = tokio::fs::create_dir_all(parent).await {
                        let _ = ui_tx.send(sys_msg(format!("Failed to create parent directories: {e}"))).await;
                        self.pending_recv_offer = Some(offer);
                        return Ok(());
                    }
                }
            }

            let mut start_offset = 0u64;
            if target_path.exists() {
                if let Ok(metadata) = std::fs::metadata(&target_path) {
                    let local_len = metadata.len();
                    if local_len < offer.size {
                        start_offset = local_len;
                        let _ = ui_tx.send(sys_msg(format!("Found partial download of {} bytes. Attempting to resume...", start_offset))).await;
                    } else if local_len == offer.size {
                        let _ = ui_tx.send(sys_msg("File already completely downloaded.")).await;
                        return Ok(());
                    }
                }
            }

            let mut file_opts = tokio::fs::OpenOptions::new();
            file_opts.write(true).create(true);
            if start_offset == 0 {
                file_opts.truncate(true);
            }

            match file_opts.open(&target_path).await {
                Ok(mut file) => {
                    if start_offset > 0 {
                        if let Err(e) = file.seek(std::io::SeekFrom::Start(start_offset)).await {
                            let _ = ui_tx.send(sys_msg(format!("Failed to seek destination file: {e}"))).await;
                            self.pending_recv_offer = Some(offer);
                            return Ok(());
                        }
                    }

                    let key = match self.crypto.derive_file_key(offer.merkle_root.as_bytes()) {
                        Ok(k) => k,
                        Err(e) => {
                            let _ = ui_tx.send(sys_msg(format!("Key derivation failed: {e}"))).await;
                            self.pending_recv_offer = Some(offer);
                            return Ok(());
                        }
                    };

                    let display_path = target_path.display().to_string();

                    let _ = ui_tx.send(sys_msg(format!(
                        "Accepted file offer. Saving to: {display_path}. Waiting for peer to transmit..."
                    ))).await;

                    self.receiving_file = Some((file, offer.file_name.clone(), offer.size));
                    self.receiving_key = Some(key);
                    self.receiving_bytes_seen = start_offset;

                    if let Err(e) = self.send_file_accept(stream, &offer.merkle_root, Some(start_offset)).await {
                        let _ = ui_tx.send(sys_msg(format!("Failed to send acceptance: {e}"))).await;
                    }
                }
                Err(e) => {
                    let _ = ui_tx.send(sys_msg(format!("Failed to create destination file: {e}"))).await;
                    self.pending_recv_offer = Some(offer);
                }
            }
            return Ok(());
        }

        if text == "/decline" {
            if self.pending_recv_offer.is_none() {
                let _ = ui_tx.send(sys_msg("No pending file offer to decline.")).await;
                return Ok(());
            }

            let offer = self.pending_recv_offer.take().unwrap();

            let _ = ui_tx.send(sys_msg(format!("Declined file transfer of: {}", offer.file_name))).await;

            if let Err(e) = self.send_file_decline(stream, &offer.merkle_root).await {
                let _ = ui_tx.send(sys_msg(format!("Failed to send decline notice: {e}"))).await;
            }
            return Ok(());
        }

        // Default: Send as normal application message
        if let Err(e) = self.send_app_message(stream, OutboundMessage::Message { target, text, ttl }).await {
            self.send_bye = false;
            return Err(e);
        }

        Ok(())
    }

    pub async fn disconnect<S>(&mut self, stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        if self.send_bye {
            self.send_control_frame(stream, CTRL_BYE).await?;
        }
        Ok(())
    }

    pub async fn send_app_message<S>(&mut self, stream: &mut S, msg: OutboundMessage) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let (msg_type, json) = match msg {
            OutboundMessage::Message { target, text, ttl } => {
                let mut base = serde_json::json!({"text": text});

                if target == "__group__" {
                    if let Some(obj) = base.as_object_mut() {
                        obj.insert("group".to_string(), "Lobby".into());
                    }
                }

                if let Some(val) = ttl {
                    if let Some(obj) = base.as_object_mut() {
                        obj.insert("ttl".to_string(), val.into());
                    }
                }

                (0x01, base)
            }
            OutboundMessage::TTLNotice { ttl, .. } => (0x03, serde_json::json!({ "ttl_notice": ttl })),
        };

        let payload = serde_json::to_vec(&json)?;
        let frame = self.encrypt_message(msg_type, &payload)?;
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
        let json = serde_json::json!({ "file_offer": offer });
        let payload = serde_json::to_vec(&json)?;
        let frame = self.encrypt_message(0x03, &payload)?; // 0x03: Extension Data
        stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_file_accept<S>(
        &mut self,
        stream: &mut S,
        merkle_root: &str,
        start_offset: Option<u64>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let json = serde_json::json!({
            "file_accept": {
                "merkle_root": merkle_root,
                "start_offset": start_offset
            }
        });
        let payload = serde_json::to_vec(&json)?;
        let frame = self.encrypt_message(0x03, &payload)?; // 0x03: Extension Data
        stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_file_decline<S>(&mut self, stream: &mut S, merkle_root: &str) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let json = serde_json::json!({
            "file_decline": {
                "merkle_root": merkle_root
            }
        });
        let payload = serde_json::to_vec(&json)?;
        let frame = self.encrypt_message(0x03, &payload)?; // 0x03: Extension Data
        stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_file_chunk<S>(
        &mut self,
        stream: &mut S,
        key: &[u8; 32],
        chunk: &[u8],
    ) -> Result<()>
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

        if u16::try_from(ciphertext_and_tag.len()).is_err() {
            return Err(anyhow!("Ciphertext and tag length overflows u16"));
        }

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

    #[allow(dead_code)]
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
            return Err(anyhow!(
                "Message too large to frame (max {} bytes)",
                u16::MAX
            ));
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
