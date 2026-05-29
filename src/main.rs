mod client;
mod crypto;
mod discovery;
mod tui;

use std::{fs, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
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

    tokio::spawn(async move {
        if let Err(e) = run_network(signing_key_net, app_port, ui_tx_net, msg_rx, connect_rx).await
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

        loop {
            tokio::select! {
                msg = msg_rx.recv() => {
                    if msg.is_none() {
                        break;
                    }

                    if client.send_app_message(&mut stream, msg.unwrap()).await.is_err() {
                        send_bye = false;
                        break;
                    }
                }

                res = client.receive_message(&mut stream) => {
                    match res {
                        Ok((0x01, payload)) => {
                            let json = serde_json::from_slice::<serde_json::Value>(&payload).expect("Invlaid message content");

                            let text = json["text"].as_str().expect("Invalid text field");
                            let ttl = json["ttl"].as_u64();

                            let _ = ui_tx.send(UiEvent::Message {
                                from: peer_id.clone(),
                                text: text.to_string(),
                                is_system: false,
                                ttl,
                            }).await;
                        }
                        // 8.2: lumos pulse
                        Ok((0x02, payload)) => {
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
                        Ok((0x03, payload)) => {
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
                            }
                        }
                        Ok((msg_type, _)) => {
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
