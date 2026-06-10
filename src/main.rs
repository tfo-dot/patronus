mod client;
mod crypto;
mod discovery;
mod storage;
mod tui;

use std::{fs, path::Path, sync::Arc, net::IpAddr, collections::HashMap};

use anyhow::Result;
use clap::Parser;
use data_encoding::BASE64;
use directories::ProjectDirs;
use discovery::DiscoveryService;
use ed25519_dalek::SigningKey;
use get_if_addrs::get_if_addrs;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use ssh_key::{LineEnding, PrivateKey};
use tokio::sync::mpsc;
use tokio::time;
use tokio::io::AsyncReadExt;
use tui::{App, run_app};

pub use crate::client::{OutboundMessage, UiEvent};

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
    #[arg(short, long)]
    interface: Option<String>,
}


fn get_available_interfaces() -> Result<Vec<get_if_addrs::Interface>> {
    get_if_addrs().map_err(|e| anyhow::anyhow!("Failed to list network interfaces: {}", e))
}

fn resolve_interface(name_or_ip: &str) -> Result<(String, IpAddr)> {
    let interfaces = get_available_interfaces()?;
    for iface in &interfaces {
        if iface.name == name_or_ip || iface.addr.ip().to_string() == name_or_ip {
            return Ok((iface.name.clone(), iface.addr.ip()));
        }
    }

    let mut err_msg = format!("Interface or IP '{}' not found.\n\nAvailable interfaces:\n", name_or_ip);
    for iface in &interfaces {
        err_msg.push_str(&format!("  - {} ({})\n", iface.name, iface.addr.ip()));
    }
    Err(anyhow::anyhow!(err_msg))
}

fn get_default_interface() -> Option<(String, IpAddr)> {
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if !iface.is_loopback() && iface.addr.ip().is_ipv4() {
                return Some((iface.name, iface.addr.ip()));
            }
        }
    }
    None
}

macro_rules! sys_msg {
    ($($arg:tt)*) => {
        UiEvent::Message {
            from: "System".to_string(),
            text: format!($($arg)*),
            is_system: true,
            ttl: None,
            group: None,
        }
    };
}


#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pk = match args.priv_key {
        Some(p) => {
            let expanded_path = if p.starts_with("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    p.replacen("~/", &format!("{}/", home), 1)
                } else {
                    p.clone()
                }
            } else if p == "~" {
                std::env::var("HOME").unwrap_or(p.clone())
            } else {
                p.clone()
            };
            let path = Path::new(&expanded_path);
            PrivateKey::read_openssh_file(path)
                .map_err(|e| anyhow::anyhow!("Failed to read private key from '{}': {}", path.display(), e))?
        }
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
                    .map_err(|e| anyhow::anyhow!("Failed to read private key from config '{}': {}", fp.display(), e))?
            } else {
                let pk = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();

                #[cfg(windows)]
                let line_ending = LineEnding::CRLF;

                #[cfg(not(windows))]
                let line_ending = LineEnding::LF;

                PrivateKey::write_openssh_file(&pk, &fp, line_ending)
                    .map_err(|e| anyhow::anyhow!("Failed to write new private key to '{}': {}", fp.display(), e))?;

                pk
            }
        }
    };

    let ed_sk = pk.key_data().ed25519().expect("Ed25519 key required");
    let signing_key = SigningKey::from_bytes(ed_sk.private.as_ref());
    let local_node_id =
        BASE64.encode(Sha256::digest(signing_key.verifying_key().as_bytes()).as_slice());

    let (selected_interface, bind_ip) = match &args.interface {
        Some(iface_name_or_ip) => {
            let (name, ip) = resolve_interface(iface_name_or_ip)?;
            (Some((name, ip)), ip)
        }
        None => {
            let ip: IpAddr = "0.0.0.0".parse().unwrap();
            (None, ip)
        }
    };

    let pd = ProjectDirs::from("com", "patronus", "patronus")
        .expect("No valid user OS profile found");
    let key_hash = data_encoding::HEXLOWER.encode(Sha256::digest(signing_key.verifying_key().as_bytes()).as_slice());
    let config_dir = pd.config_dir().join(&key_hash[..16]);
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir).ok();
    }

    let storage_key = storage::derive_storage_key(signing_key.to_bytes().as_ref());

    let app_port: u16 = (rand::random::<u16>() % 255) + 6000;

    let mut app = App::new();
    app.selected_interface = selected_interface;
    app.default_interface = get_default_interface();
    app.storage_key = Some(storage_key);
    app.config_dir = Some(config_dir.clone());
    app.app_port = app_port;

    // Load persisted peers and history
    let loaded_peers = storage::load_peers(&config_dir, &storage_key).unwrap_or_default();
    let loaded_history = storage::load_history(&config_dir, &storage_key).unwrap_or_default();

    // Initialize custom names and peers map
    let mut peer_ids: Vec<String> = loaded_peers.keys().cloned().collect();
    peer_ids.sort();
    app.peer_ids = peer_ids;

    for (id, peer_info) in &loaded_peers {
        if let Some(name) = &peer_info.custom_name {
            app.custom_names.insert(id.clone(), name.clone());
        }
        let name = peer_info.custom_name.clone().unwrap_or_else(|| id.chars().take(8).collect());
        app.peers.insert(id.clone(), (name, "Offline".to_string()));
    }

    for msg in loaded_history {
        app.messages.entry(msg.peer_id).or_default().push(tui::Message {
            from: msg.from,
            content: msg.content,
            is_system: msg.is_system,
            ttl: msg.ttl,
            received_at: std::time::Instant::now(),
        });
    }

    let (ui_tx, ui_rx) = mpsc::channel(100);
    let (msg_tx, msg_rx) = mpsc::channel::<OutboundMessage>(100);
    let (connect_tx, connect_rx) = mpsc::channel::<String>(100);

    let ui_tx_net = ui_tx.clone();
    let signing_key_net = signing_key.clone();
    let initial_save_dir = args.save_dir.clone();
    let config_dir_net = config_dir.clone();
    let storage_key_net = storage_key.clone();

    tokio::spawn(async move {
        if let Err(e) = run_network(
            signing_key_net,
            app_port,
            bind_ip,
            ui_tx_net,
            msg_rx,
            connect_rx,
            initial_save_dir,
            config_dir_net,
            storage_key_net,
        )
        .await
        {
            eprintln!("Network error: {}", e);
        }
    });

    let discovery = Arc::new(DiscoveryService::new(app_port, local_node_id.to_string(), bind_ip));

    discovery.set_broadcasting(args.broadcast.unwrap_or(true));
    app.broadcasting = args.broadcast.unwrap_or(true);

    let ui_tx_disc = ui_tx.clone();

    discovery.start(ui_tx_disc);

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
    signing_key: SigningKey,
    app_port: u16,
    bind_ip: IpAddr,
    ui_tx: mpsc::Sender<UiEvent>,
    mut msg_rx: mpsc::Receiver<OutboundMessage>,
    mut connect_rx: mpsc::Receiver<String>,
    initial_save_dir: Option<String>,
    config_dir: std::path::PathBuf,
    storage_key: [u8; 32],
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("{bind_ip}:{app_port}")).await?;

    let trusted_peers = Arc::new(std::sync::Mutex::new(
        storage::load_peers(&config_dir, &storage_key).unwrap_or_default()
    ));

    let active_conns = Arc::new(std::sync::Mutex::new(
        HashMap::<String, mpsc::Sender<OutboundMessage>>::new()
    ));

    let active_conns_clone = active_conns.clone();
    let ui_tx_clone = ui_tx.clone();

    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            match msg {
                OutboundMessage::Message { target, text, ttl } => {
                    let sender = {
                        let conns = active_conns_clone.lock().unwrap();
                        conns.get(&target).cloned()
                    };
                    if let Some(sender) = sender {
                        let _ = sender.send(OutboundMessage::Message {
                            target: target.clone(),
                            text,
                            ttl,
                        }).await;
                    } else {
                        let _ = ui_tx_clone.send(sys_msg!("Peer {} is not connected.", target)).await;
                    }
                }
                OutboundMessage::TTLNotice { target, ttl } => {
                    let sender = {
                        let conns = active_conns_clone.lock().unwrap();
                        conns.get(&target).cloned()
                    };
                    if let Some(sender) = sender {
                        let _ = sender.send(OutboundMessage::TTLNotice { target, ttl }).await;
                    }
                }
            }
        }
    });

    loop {
        let (mut stream, is_initiator, peer_addr) = tokio::select! {
            incoming = listener.accept() => {
                match incoming {
                    Ok((stream, addr)) => {
                        let _ = stream.set_nodelay(true);
                        (stream, false, addr.to_string())
                    }
                    Err(_) => continue,
                }
            }
            addr = connect_rx.recv() => {
                if let Some(addr) = addr {
                    match tokio::net::TcpStream::connect(&addr).await {
                        Ok(stream) => {
                            let _ = stream.set_nodelay(true);
                            (stream, true, addr)
                        }
                        Err(e) => {
                            let _ = ui_tx.send(sys_msg!("Connection to {addr} failed: {e}")).await;
                            continue;
                        }
                    }
                } else {
                    break;
                }
            }
        };

        let signing_key_clone = signing_key.clone();
        let initial_save_dir_clone = initial_save_dir.clone();
        let ui_tx_task = ui_tx.clone();
        let trusted_peers_task = trusted_peers.clone();
        let active_conns_task = active_conns.clone();
        let config_dir_task = config_dir.clone();
        let storage_key_task = storage_key.clone();

        tokio::spawn(async move {
            let mut client = client::PatronusClient::new(signing_key_clone, initial_save_dir_clone);

            let trusted_peers_map = {
                let map = trusted_peers_task.lock().unwrap();
                map.clone()
            };

            if let Err(e) = client.handshake(&mut stream, is_initiator, &trusted_peers_map).await {
                let _ = ui_tx_task.send(sys_msg!("Handshake failed: {e}")).await;
                return;
            }

            let peer_id = client.peer_node_id.clone().unwrap_or_else(|| "Unknown".to_string());

            {
                let mut map = trusted_peers_task.lock().unwrap();
                if !map.contains_key(&peer_id) {
                    map.insert(peer_id.clone(), storage::PeerInfo {
                        static_public_key_b64: client.peer_static_pk.clone().unwrap_or_default(),
                        custom_name: None,
                        is_verified: false,
                    });
                    let _ = storage::save_peers(&config_dir_task, &storage_key_task, &map);
                }
            }

            if let Some(phrase) = &client.identity_phrase {
                let _ = ui_tx_task.send(UiEvent::HandshakeComplete(phrase.clone())).await;
            }

            let _ = ui_tx_task.send(UiEvent::PeerUpdate {
                id: peer_id.clone(),
                name: peer_id.chars().take(8).collect(),
                addr: peer_addr.clone(),
            }).await;

            let our_exts = client::SUPPORTED_EXTENSIONS.join(", ");
            let peer_exts = client.peer_extensions.join(", ");

            let _ = ui_tx_task.send(sys_msg!(
                "Connection established! Our extensions: [{our_exts}]. Peer extensions: [{peer_exts}]"
            )).await;

            let _ = ui_tx_task.send(sys_msg!("Connected to {peer_id}")).await;

            let (peer_tx, mut peer_rx) = mpsc::channel::<OutboundMessage>(100);

            {
                let mut conns = active_conns_task.lock().unwrap();
                conns.insert(peer_id.clone(), peer_tx);
            }

            let mut keep_alive = time::interval_at(
                time::Instant::now() + client::KEEP_ALIVE_INTERVAL,
                client::KEEP_ALIVE_INTERVAL,
            );

            let (mut read_half, mut write_half) = stream.into_split();
            let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(100);

            tokio::spawn(async move {
                loop {
                    // read length (4 bytes)
                    let mut len_bytes = [0u8; 4];
                    if read_half.read_exact(&mut len_bytes).await.is_err() {
                        break;
                    }
                    let len = u32::from_be_bytes(len_bytes);

                    // read ratchet_index (4 bytes)
                    let mut ratchet_bytes = [0u8; 4];
                    if read_half.read_exact(&mut ratchet_bytes).await.is_err() {
                        break;
                    }

                    // read nonce (12 bytes)
                    let mut nonce = [0u8; 12];
                    if read_half.read_exact(&mut nonce).await.is_err() {
                        break;
                    }

                    // read payload (len bytes)
                    let mut payload = vec![0u8; len as usize];
                    if read_half.read_exact(&mut payload).await.is_err() {
                        break;
                    }

                    // package into a single Vec<u8>
                    let mut frame = Vec::with_capacity(4 + 4 + 12 + payload.len());
                    frame.extend_from_slice(&len_bytes);
                    frame.extend_from_slice(&ratchet_bytes);
                    frame.extend_from_slice(&nonce);
                    frame.extend_from_slice(&payload);

                    if frame_tx.send(frame).await.is_err() {
                        break;
                    }
                }
            });

            loop {
                tokio::select! {
                    msg = peer_rx.recv() => {
                        if msg.is_none() {
                            break;
                        }
                        if client.handle_outbound_msg(&mut write_half, msg.unwrap(), &ui_tx_task).await.is_err() {
                            break;
                        }
                    }

                    frame_opt = frame_rx.recv() => {
                        if let Some(frame) = frame_opt {
                            if client.handle_incoming_frame(&frame, &mut write_half, &ui_tx_task).await.is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    _ = keep_alive.tick() => {
                        if client.tick_keep_alive(&mut write_half, &ui_tx_task).await.is_err() {
                            break;
                        }
                    }

                    send_res = async {
                        if client.active_send_file.is_some() {
                            client.send_active_file_chunk(&mut write_half, &ui_tx_task).await
                        } else {
                            std::future::pending::<Result<bool>>().await
                        }
                    } => {
                        if send_res.is_err() {
                            break;
                        }
                    }
                }
            }

            let _ = client.disconnect(&mut write_half).await;

            {
                let mut conns = active_conns_task.lock().unwrap();
                conns.remove(&peer_id);
            }

            let _ = ui_tx_task.send(sys_msg!("{peer_id} disconnected.")).await;
            let _ = ui_tx_task.send(UiEvent::PeerUpdate {
                id: peer_id.clone(),
                name: peer_id.chars().take(8).collect(),
                addr: "Offline".to_string(),
            }).await;
        });
    }

    Ok(())
}
