mod client;
mod crypto;
mod discovery;
mod tui;

use std::{fs, path::Path, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use crate::client::FileOffer;
use tokio::io::AsyncReadExt as _;
use clap::Parser;
use data_encoding::BASE64;
use directories::ProjectDirs;
use discovery::DiscoveryService;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use ssh_key::{LineEnding, PrivateKey};
use tokio::sync::mpsc;
use tokio::time;
use tui::{App, run_app};

use crate::client::OutboundMessage;

// 8.2: lumos pulse
const CTRL_PING: u8 = 0x01;
const CTRL_PONG: u8 = 0x02;
// 8.3: graceful closure
const CTRL_BYE: u8 = 0x03;

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(30);

// connection lifecycle: Disconnected -> Handshaking -> Established -> Closing -> Disconnected
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ConnectionState {
    Disconnected,
    Handshaking,
    Established,
    Closing,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    name: Option<String>,
    #[arg(short, long)]
    priv_key: Option<String>,
    #[arg(short, long)]
    broadcast: Option<bool>,
    #[arg(short, long)]
    save_dir: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UiEvent {
    Message {
        from: String,
        text: String,
        is_system: bool,
        ttl: Option<u64>,
    },
    HandshakeComplete(String),
    PeerUpdate {
        id: String,
        name: String,
        addr: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pk = match args.priv_key {
        Some(p) => PrivateKey::read_openssh_file(Path::new(&p)),
        None => {
            let pd = ProjectDirs::from("com", "patronus", "patronus")
                .expect("No valid user OS profile found");

            let cd = pd.config_dir();

            if !cd.exists() {
                fs::create_dir_all(cd).expect("Couldn't create config directory")
            }

            let fp = pd.config_dir().join("key");

            if fp.exists() {
                PrivateKey::read_openssh_file(&fp)
            } else {
                let pk = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();

                #[cfg(windows)]
                let line_ending = LineEnding::CRLF;

                #[cfg(not(windows))]
                let line_ending = LineEnding::LF;

                PrivateKey::write_openssh_file(&pk, &fp, line_ending)
                    .expect("Error writing new random key");

                Ok(pk)
            }
        }
    }
    .unwrap();

    let ed_sk = pk.key_data().ed25519().expect("Ed25519 key required");
    let signing_key = SigningKey::from_bytes(ed_sk.private.as_ref());
    let local_node_id =
        BASE64.encode(Sha256::digest(signing_key.verifying_key().as_bytes()).as_slice());

    let mut app = App::new();

    let (ui_tx, ui_rx) = mpsc::channel(100);
    let (msg_tx, msg_rx) = mpsc::channel::<OutboundMessage>(100);
    let (connect_tx, connect_rx) = mpsc::channel::<String>(100);

    let app_port: u16 = (rand::random::<u16>() % 255) + 6000;

    let ui_tx_net = ui_tx.clone();
    let signing_key_net = signing_key.clone();
    let initial_save_dir = args.save_dir.clone();

    tokio::spawn(async move {
        if let Err(e) = run_network(signing_key_net, app_port, ui_tx_net, msg_rx, connect_rx, initial_save_dir).await
        {
            eprintln!("Network error: {}", e);
        }
    });

    let discovery = Arc::new(DiscoveryService::new(app_port, local_node_id.to_string()));

    discovery.set_broadcasting(args.broadcast.unwrap_or(true));
    app.broadcasting = args.broadcast.unwrap_or(true);

    let ui_tx_disc = ui_tx.clone();

    discovery.start(ui_tx_disc);

    // UI loop
    let mut terminal = ratatui::init();
    let result = run_app(
        &mut terminal,
        app,
        ui_rx,
        msg_tx,
        connect_tx,
        discovery.clone(),
    )
    .await;

    ratatui::restore();

    discovery.stop();

    result
}

async fn run_network(
    singing_key: SigningKey,
    app_port: u16,
    ui_tx: mpsc::Sender<UiEvent>,
    mut msg_rx: mpsc::Receiver<OutboundMessage>,
    mut connect_rx: mpsc::Receiver<String>,
    initial_save_dir: Option<String>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{app_port}")).await?;

    loop {
        // disconnected: wait for inbound or outbound connection (9.1 & 9.2)
        let (mut stream, is_initiator, peer_addr) = loop {
            tokio::select! {
                incoming = listener.accept() => {
                    if let Ok((stream, addr)) = incoming {
                        break (stream, false, addr.to_string());
                    }
                }
                addr = connect_rx.recv() => {
                    if let Some(addr) = addr {
                        match tokio::net::TcpStream::connect(&addr).await {
                            Ok(stream) => break (stream, true, addr),
                            Err(e) => {
                                let _ = ui_tx.send(UiEvent::Message {
                                    from: "System".to_string(),
                                    text: format!("Connection to {addr} failed: {e}"),
                                    is_system: true,
                                    ttl: None,
                                }).await;
                            }
                        }
                    }
                }
            }
        };

        // handshake (4.1)
        let mut client = client::PatronusClient::new(singing_key.clone());

        if let Err(e) = client.handshake(&mut stream, is_initiator).await {
            let _ = ui_tx
                .send(UiEvent::Message {
                    from: "System".to_string(),
                    text: format!("Handshake failed: {e}"),
                    is_system: true,
                    ttl: None,
                })
                .await;
            continue;
        }

        let peer_id = client
            .peer_node_id
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());

        // 5.2: display identity phrase for out-of-band verification
        if let Some(phrase) = &client.identity_phrase {
            let _ = ui_tx.send(UiEvent::HandshakeComplete(phrase.clone())).await;
        }

        let _ = ui_tx.try_send(UiEvent::PeerUpdate {
            id: peer_id.clone(),
            name: peer_id.chars().take(8).collect(),
            addr: peer_addr,
        });

        let our_exts = client::SUPPORTED_EXTENSIONS.join(", ");
        let peer_exts = client.peer_extensions.join(", ");
        let _ = ui_tx.send(UiEvent::Message {
            from: "System".to_string(),
            text: format!("Connection established! Our extensions: [{our_exts}]. Peer extensions: [{peer_exts}]"),
            is_system: true,
            ttl: None,
        }).await;

        let _ = ui_tx
            .send(UiEvent::Message {
                from: "System".to_string(),
                text: format!("Connected to {peer_id}"),
                is_system: true,
                ttl: None,
            })
            .await;

        // established: interval_at so the first tick fires after the interval, not immediately
        let mut keep_alive = time::interval_at(
            time::Instant::now() + KEEP_ALIVE_INTERVAL,
            KEEP_ALIVE_INTERVAL,
        );
        let mut pending_pong = false;
        let mut last_ping = time::Instant::now();
        // false when the connection is already gone and a BYE would fail
        let mut send_bye = true;

        // drain messages that queued up while disconnected
        while msg_rx.try_recv().is_ok() {}

        let mut save_dir = initial_save_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("downloads"));

        let mut receiving_file: Option<(tokio::fs::File, String, u64)> = None;
        let mut receiving_key: Option<[u8; 32]> = None;
        let mut receiving_bytes_seen = 0u64;

        let mut pending_send_file: Option<(std::path::PathBuf, [u8; 32], String)> = None;
        let mut pending_recv_offer: Option<FileOffer> = None;

        loop {
            tokio::select! {
                msg = msg_rx.recv() => {
                    match msg {
                        Some(text) => {
                            if text.starts_with("/send ") {
                                if pending_send_file.is_some() {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: "A file offer is already pending response. Please wait until the peer accepts or declines.".to_string(),
                                        is_system: true,
                                    }).await;
                                    continue;
                                }

                                let path_str = text.strip_prefix("/send ").unwrap().trim();
                                let path = Path::new(path_str);
                                if !path.exists() {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: format!("File not found: {path_str}"),
                                        is_system: true,
                                    }).await;
                                    continue;
                                }

                                let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                                let metadata = fs::metadata(path)?;
                                let size = metadata.len();

                                // Calculate BLAKE3 hash
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

                                if let Err(e) = client.send_file_offer(&mut stream, &offer).await {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: format!("Failed to send file offer: {e}"),
                                        is_system: true,
                                    }).await;
                                    continue;
                                }

                                let _ = ui_tx.send(UiEvent::Message {
                                    from: "System".to_string(),
                                    text: format!("Offered file: {file_name} ({size} bytes). Waiting for peer to accept/decline..."),
                                    is_system: true,
                                }).await;

                                // Derive file key and store in pending
                                let file_key = client.crypto.derive_file_key(merkle_root.as_bytes()).map_err(|e| anyhow!(e))?;
                                pending_send_file = Some((path.to_path_buf(), file_key, file_name));
                                continue;
                            }

                            if text.starts_with("/save_dir ") {
                                let path_str = text.strip_prefix("/save_dir ").unwrap().trim();
                                if path_str.is_empty() {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: format!("Current save directory: {}", save_dir.display()),
                                        is_system: true,
                                    }).await;
                                } else {
                                    let new_path = std::path::PathBuf::from(path_str);
                                    match tokio::fs::create_dir_all(&new_path).await {
                                        Ok(_) => {
                                            save_dir = new_path;
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("Save directory set to: {}", save_dir.display()),
                                                is_system: true,
                                            }).await;
                                        }
                                        Err(e) => {
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("Failed to create/set save directory: {e}"),
                                                is_system: true,
                                            }).await;
                                        }
                                    }
                                }
                                continue;
                            }

                            if text == "/save_dir" {
                                let _ = ui_tx.send(UiEvent::Message {
                                    from: "System".to_string(),
                                    text: format!("Current save directory: {}", save_dir.display()),
                                    is_system: true,
                                }).await;
                                continue;
                            }

                            if text.starts_with("/accept") {
                                if pending_recv_offer.is_none() {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: "No pending file offer to accept.".to_string(),
                                        is_system: true,
                                    }).await;
                                    continue;
                                }

                                let offer = pending_recv_offer.take().unwrap();
                                let path_arg = text.strip_prefix("/accept").unwrap().trim();
                                
                                let target_path = if path_arg.is_empty() {
                                    save_dir.join(&offer.file_name)
                                } else {
                                    let path = Path::new(path_arg);
                                    if path.is_dir() || path_arg.ends_with('/') || path_arg.ends_with('\\') {
                                        path.join(&offer.file_name)
                                    } else {
                                        path.to_path_buf()
                                    }
                                };

                                // Ensure parent directory exists
                                if let Some(parent) = target_path.parent() {
                                    if !parent.as_os_str().is_empty() {
                                        if let Err(e) = tokio::fs::create_dir_all(parent).await {
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("Failed to create parent directories: {e}"),
                                                is_system: true,
                                            }).await;
                                            pending_recv_offer = Some(offer); // Put it back so they can try again
                                            continue;
                                        }
                                    }
                                }

                                match tokio::fs::File::create(&target_path).await {
                                    Ok(file) => {
                                        let key = match client.crypto.derive_file_key(offer.merkle_root.as_bytes()) {
                                            Ok(k) => k,
                                            Err(e) => {
                                                let _ = ui_tx.send(UiEvent::Message {
                                                    from: "System".to_string(),
                                                    text: format!("Key derivation failed: {e}"),
                                                    is_system: true,
                                                }).await;
                                                pending_recv_offer = Some(offer);
                                                continue;
                                            }
                                        };

                                        let display_path = target_path.display().to_string();
                                        let _ = ui_tx.send(UiEvent::Message {
                                            from: "System".to_string(),
                                            text: format!("Accepted file offer. Saving to: {display_path}. Waiting for peer to transmit..."),
                                            is_system: true,
                                        }).await;

                                        receiving_file = Some((file, offer.file_name.clone(), offer.size));
                                        receiving_key = Some(key);
                                        receiving_bytes_seen = 0;

                                        // Send accept frame
                                        if let Err(e) = client.send_file_accept(&mut stream, &offer.merkle_root).await {
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("Failed to send acceptance: {e}"),
                                                is_system: true,
                                            }).await;
                                        }
                                    }
                                    Err(e) => {
                                        let _ = ui_tx.send(UiEvent::Message {
                                            from: "System".to_string(),
                                            text: format!("Failed to create destination file: {e}"),
                                            is_system: true,
                                        }).await;
                                        pending_recv_offer = Some(offer); // Put it back so they can try again
                                    }
                                }
                                continue;
                            }

                            if text == "/decline" {
                                if pending_recv_offer.is_none() {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: "No pending file offer to decline.".to_string(),
                                        is_system: true,
                                    }).await;
                                    continue;
                                }

                                let offer = pending_recv_offer.take().unwrap();
                                let _ = ui_tx.send(UiEvent::Message {
                                    from: "System".to_string(),
                                    text: format!("Declined file transfer of: {}", offer.file_name),
                                    is_system: true,
                                }).await;

                                if let Err(e) = client.send_file_decline(&mut stream, &offer.merkle_root).await {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: format!("Failed to send decline notice: {e}"),
                                        is_system: true,
                                    }).await;
                                }
                                continue;
                            }

                            let json = serde_json::json!({ "text": text });
                            if client.send_app_message(&mut stream, &json).await.is_err() {
                                send_bye = false;
                                break;
                            }
                        }
                        None => break,
                    }
                }

                res = client.receive_message(&mut stream) => {
                    match res {
                        Ok((0x01, payload, _, _)) => {
                            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                                if let Some(text) = json["text"].as_str() {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: peer_id.clone(),
                                        text: text.to_string(),
                                        is_system: false,
                                    }).await;
                                }
                            }
                        }
                        Ok((0x03, payload, true, _)) => {
                            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                                if let Some(offer_val) = json.get("file_offer") {
                                    if let Ok(offer) = serde_json::from_value::<FileOffer>(offer_val.clone()) {
                                        pending_recv_offer = Some(offer.clone());
                                        let _ = ui_tx.send(UiEvent::Message {
                                            from: "System".to_string(),
                                            text: format!("Received file offer: {} ({} bytes)", offer.file_name, offer.size),
                                            is_system: true,
                                        }).await;
                                        let _ = ui_tx.send(UiEvent::Message {
                                            from: "System".to_string(),
                                            text: "To accept, type: '/accept' or '/accept <path>'".to_string(),
                                            is_system: true,
                                        }).await;
                                        let _ = ui_tx.send(UiEvent::Message {
                                            from: "System".to_string(),
                                            text: "To decline, type: '/decline'".to_string(),
                                            is_system: true,
                                        }).await;
                                    }
                                } else if let Some(accept_val) = json.get("file_accept") {
                                    if let Some(_merkle_root) = accept_val.get("merkle_root").and_then(|v| v.as_str()) {
                                        if let Some((path, file_key, file_name)) = pending_send_file.take() {
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("Peer accepted. Transmitting file: {file_name}..."),
                                                is_system: true,
                                            }).await;

                                            // Start sending file chunks!
                                            match tokio::fs::File::open(&path).await {
                                                Ok(mut file) => {
                                                    let mut chunk_buffer = vec![0u8; 16384]; // 16KB chunks
                                                    let mut sent_bytes = 0;
                                                    let mut error_occurred = false;

                                                    while let Ok(n) = file.read(&mut chunk_buffer).await {
                                                        if n == 0 { break; }
                                                        if let Err(e) = client.send_file_chunk(&mut stream, &file_key, &chunk_buffer[..n]).await {
                                                            let _ = ui_tx.send(UiEvent::Message {
                                                                from: "System".to_string(),
                                                                text: format!("Error sending file chunk: {e}"),
                                                                is_system: true,
                                                            }).await;
                                                            error_occurred = true;
                                                            break;
                                                        }
                                                        sent_bytes += n as u64;
                                                    }

                                                    if !error_occurred {
                                                        let _ = ui_tx.send(UiEvent::Message {
                                                            from: "System".to_string(),
                                                            text: format!("Finished sending {file_name} ({sent_bytes} bytes)"),
                                                            is_system: true,
                                                        }).await;
                                                    }
                                                }
                                                Err(e) => {
                                                    let _ = ui_tx.send(UiEvent::Message {
                                                        from: "System".to_string(),
                                                        text: format!("Failed to open file for sending: {e}"),
                                                        is_system: true,
                                                    }).await;
                                                }
                                            }
                                        }
                                    }
                                } else if let Some(decline_val) = json.get("file_decline") {
                                    if let Some(_merkle_root) = decline_val.get("merkle_root").and_then(|v| v.as_str()) {
                                        if let Some((_, _, file_name)) = pending_send_file.take() {
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("Peer declined file transfer of: {file_name}"),
                                                is_system: true,
                                            }).await;
                                        }
                                    }
                                }
                            }
                        }
                        // 8.2: lumos pulse
                        Ok((0x02, payload, _, _)) => {
                            match payload.first().copied() {
                                Some(CTRL_PING) => {
                                    let _ = client.send_control_frame(&mut stream, CTRL_PONG).await;
                                }
                                Some(CTRL_PONG) => {
                                    pending_pong = false;
                                }
                                Some(CTRL_BYE) => {
                                    send_bye = false;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        Ok((0x03, payload, false, _)) => {
                          if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                                if json.get("ttl_notice").is_some() {
                                    let peer_ttl = json["ttl_notice"].as_u64();
                                    let msg = match peer_ttl {
                                        Some(s) => format!("Peer messages will disappear after {}", tui::format_ttl(s)),
                                        None => "Peer disabled message TTL".to_string(),
                                    };
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: msg,
                                        is_system: true,
                                        ttl: None,
                                    }).await;
                                } else {
                                    let _ = ui_tx.send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: format!("Got unkown extension packet data: `{}...`", json.to_string().chars().take(16).collect::<String>()),
                                        is_system: true,
                                        ttl: None,
                                    }).await;
                                }
                            
                                return;
                            }
                          
                            if let (Some((mut file, name, size)), Some(key)) = (receiving_file.take(), receiving_key) {
                                match client.decrypt_file_chunk(&key, &payload) {
                                    Ok((0x03, chunk)) => {
                                        use tokio::io::AsyncWriteExt;
                                        file.write_all(&chunk).await?;
                                        receiving_bytes_seen += chunk.len() as u64;

                                        if receiving_bytes_seen >= size {
                                            let _ = ui_tx.send(UiEvent::Message {
                                                from: "System".to_string(),
                                                text: format!("File transfer complete: {name}"),
                                                is_system: true,
                                            }).await;
                                            receiving_file = None;
                                            receiving_key = None;
                                        } else {
                                            receiving_file = Some((file, name, size));
                                        }
                                    }
                                    _ => {
                                        let _ = ui_tx.send(UiEvent::Message {
                                            from: "System".to_string(),
                                            text: "Failed to decrypt file chunk".to_string(),
                                            is_system: true,
                                        }).await;
                                    }
                                }
                            }
                        }
                        Ok((msg_type, _, _, _)) => {
                            let _ = ui_tx.send(UiEvent::Message {
                                from: "System".to_string(),
                                text: format!("Unknown message type: 0x{msg_type:02x}"),
                                is_system: true,
                                ttl: None,
                            }).await;
                        }
                        Err(e) => {
                            let _ = ui_tx.send(UiEvent::Message {
                                from: "System".to_string(),
                                text: format!("Connection lost with {peer_id}: {e}"),
                                is_system: true,
                                ttl: None,
                            }).await;
                            send_bye = false;
                            break;
                        }
                    }
                }

                // 8.2: lumos pulse - ping every 15s, timeout after 30s with no pong
                _ = keep_alive.tick() => {
                    if pending_pong && last_ping.elapsed() >= KEEP_ALIVE_TIMEOUT {
                        let _ = ui_tx.send(UiEvent::Message {
                            from: "System".to_string(),
                            text: format!("Connection timed out: {peer_id}"),
                            is_system: true,
                            ttl: None,
                        }).await;
                        send_bye = false;
                        break;
                    }

                    if !pending_pong {
                        pending_pong = true;
                        last_ping = time::Instant::now();
                        let _ = client.send_control_frame(&mut stream, CTRL_PING).await;
                    }
                }
            }
        }

        // closing (8.3)
        if send_bye {
            let _ = client.send_control_frame(&mut stream, CTRL_BYE).await;
        }

        let _ = ui_tx
            .send(UiEvent::Message {
                from: "System".to_string(),
                text: format!("{peer_id} disconnected."),
                is_system: true,
                ttl: None,
            })
            .await;
    }
}
