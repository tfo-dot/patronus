mod client;
mod crypto;
mod discovery;
mod tui;

use std::{fs, path::Path, sync::Arc, net::IpAddr};

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
        }
    };
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

    let mut app = App::new();
    app.selected_interface = selected_interface;
    app.default_interface = get_default_interface();

    let (ui_tx, ui_rx) = mpsc::channel(100);
    let (msg_tx, msg_rx) = mpsc::channel::<OutboundMessage>(100);
    let (connect_tx, connect_rx) = mpsc::channel::<String>(100);

    let app_port: u16 = (rand::random::<u16>() % 255) + 6000;

    let ui_tx_net = ui_tx.clone();
    let signing_key_net = signing_key.clone();
    let initial_save_dir = args.save_dir.clone();

    tokio::spawn(async move {
        if let Err(e) = run_network(
            signing_key_net,
            app_port,
            bind_ip,
            ui_tx_net,
            msg_rx,
            connect_rx,
            initial_save_dir,
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
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("{bind_ip}:{app_port}")).await?;

    loop {
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
                                let _ = ui_tx.send(sys_msg!("Connection to {addr} failed: {e}")).await;
                            }
                        }
                    }
                }
            }
        };

        let mut client = client::PatronusClient::new(signing_key.clone(), initial_save_dir.clone());

        if let Err(e) = client.handshake(&mut stream, is_initiator).await {
            let _ = ui_tx.send(sys_msg!("Handshake failed: {e}")).await;
            continue;
        }

        let peer_id = client
            .peer_node_id
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());

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

        let _ = ui_tx.send(sys_msg!(
            "Connection established! Our extensions: [{our_exts}]. Peer extensions: [{peer_exts}]"
        )).await;

        let _ = ui_tx.send(sys_msg!("Connected to {peer_id}")).await;

        let mut keep_alive = time::interval_at(
            time::Instant::now() + client::KEEP_ALIVE_INTERVAL,
            client::KEEP_ALIVE_INTERVAL,
        );

        while msg_rx.try_recv().is_ok() {}

        loop {
            tokio::select! {
                msg = msg_rx.recv() => {
                    if msg.is_none() {
                        break;
                    }
                    if client.handle_outbound_msg(&mut stream, msg.unwrap(), &ui_tx).await.is_err() {
                        break;
                    }
                }

                res = client.handle_incoming(&mut stream, &ui_tx) => {
                    if res.is_err() {
                        break;
                    }
                }

                _ = keep_alive.tick() => {
                    if client.tick_keep_alive(&mut stream, &ui_tx).await.is_err() {
                        break;
                    }
                }
            }
        }

        let _ = client.disconnect(&mut stream).await;

        let _ = ui_tx.send(sys_msg!("{peer_id} disconnected.")).await;
    }
}
