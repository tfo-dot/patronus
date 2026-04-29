mod crypto;
mod discovery;

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use discovery::DiscoveryService;
use futures_lite::StreamExt;
use iroh::{Endpoint, EndpointId, endpoint::presets, protocol::Router};
use iroh_gossip::{TopicId, api::Event, net::Gossip};
use serde::{Deserialize, Serialize};
use ssh_key::PrivateKey;
use tokio::sync::{Mutex, mpsc};

use crate::crypto::CryptoState;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    name: Option<String>,
    #[arg(short, long)]
    priv_key: Option<String>,
}

#[derive(Debug, Clone)]
enum UiEvent {
    Message {
        from: String,
        text: String,
        is_system: bool,
    },
    HandshakeComplete(String),
    LocalInfo {
        node_id: String,
    },
    PeerUpdate {
        id: String,
        name: String,
    },
    PeerLeft {
        id: String,
    },
}

struct App {
    messages: Vec<(String, String, bool)>, // (Sender, Content, IsSystem)
    peers: HashMap<String, String>,
    local_node_id: String,
    identity_phrase: Option<String>,
    input: String,
}

impl App {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            peers: HashMap::new(),
            local_node_id: "Initializing...".to_string(),
            identity_phrase: None,
            input: String::new(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| "Anonymous".to_string());

    let pk = match args.priv_key {
        Some(p) => PrivateKey::read_openssh_file(Path::new(&p)),
        None => {
            //Source: `keys/one`
            PrivateKey::from_openssh(
                r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDdIGzOO9EekDQsuUq+NwQhgMkxFtucMv3ZfSBEaZZ0KwAAAJjeTmNM3k5j
TAAAAAtzc2gtZWQyNTUxOQAAACDdIGzOO9EekDQsuUq+NwQhgMkxFtucMv3ZfSBEaZZ0Kw
AAAED7wCW1EnAbrv1eo8S5ltXItDwrhriZKtEYLdSK1OUjJd0gbM470R6QNCy5Sr43BCGA
yTEW25wy/dl9IERplnQrAAAAD3Rmb0B3YXJyb3Zlci1ycAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----"#,
            )
        }
    }
    .unwrap();

    let res = pk.public_key().fingerprint(ssh_key::HashAlg::Sha256);

    let crypto = Arc::new(Mutex::new(CryptoState::new()));
    let closed = Arc::new(Mutex::new(false));
    let app = App::new();

    let (ui_tx, ui_rx) = mpsc::channel(100);
    let (msg_tx, mut msg_rx) = mpsc::channel::<String>(100);

    let crypto_iroh = crypto.clone();
    let ui_tx_iroh = ui_tx.clone();
    let is_closed = closed.clone();
    tokio::spawn(async move {
        let iroh_tx = ui_tx_iroh.clone();
        let error_tx = ui_tx_iroh.clone();

        if let Err(e) = run_iroh(name, crypto_iroh, iroh_tx, &mut msg_rx, is_closed).await {
            let _ = error_tx
                .send(UiEvent::Message {
                    from: "Error".to_string(),
                    text: format!("Iroh error: {}", e),
                    is_system: true,
                })
                .await;
        }
    });

    let app_port: u16 = (rand::random::<u16>() % 255) + 6000;
    let discovery = Arc::new(DiscoveryService::new(app_port, res.to_string()));

    let ui_tx_disc = ui_tx.clone();

    discovery.start(ui_tx_disc);

    // UI loop
    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal, app, ui_rx, msg_tx).await;

    ratatui::restore();

    discovery.stop();
    *closed.lock().await = true;

    result
}

async fn run_iroh(
    name: String,
    crypto: Arc<Mutex<CryptoState>>,
    ui_tx: mpsc::Sender<UiEvent>,
    msg_rx: &mut mpsc::Receiver<String>,
    closed: Arc<Mutex<bool>>,
) -> Result<()> {
    let endpoint = Endpoint::builder(presets::N0).bind().await?;

    let gossip = Gossip::builder().spawn(endpoint.clone());

    let _router = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();

    let node_id = endpoint.id();
    ui_tx
        .send(UiEvent::LocalInfo {
            node_id: node_id.to_string(),
        })
        .await?;

    ui_tx
        .send(UiEvent::Message {
            from: "System".to_string(),
            text: format!("Welcome to Patronus. Your NodeID is {}", node_id),
            is_system: true,
        })
        .await?;

    let topic_id = TopicId::from([0u8; 32]);
    let topic = gossip.subscribe_and_join(topic_id, vec![]).await?;
    let (gossip_tx, mut gossip_rx) = topic.split();

    let crypto_c = crypto.clone();
    let ui_tx_c = ui_tx.clone();
    let endpoint_c = endpoint.clone();
    let name_c = name.clone();
    let gossip_tx_r = gossip_tx.clone();

    // Gossip receiver task
    tokio::spawn(async move {
        let mut peer_names: HashMap<EndpointId, String> = HashMap::new();

        // Broadcast our name periodically or at start
        let intro = Message::new(MessageBody::AboutMe {
            from: endpoint_c.id(),
            name: name_c.clone(),
        });
        let _ = gossip_tx_r.broadcast(intro.to_vec().into()).await;

        // Broadcast our public key for handshake
        let pk = crypto_c.lock().await.local_public;
        let kex = Message::new(MessageBody::KeyExchange {
            from: endpoint_c.id(),
            public_key: pk.as_bytes().to_vec(),
        });
        let _ = gossip_tx_r.broadcast(kex.to_vec().into()).await;

        while let Some(Ok(event)) = gossip_rx.next().await {
            match event {
                Event::Received(msg) => {
                    if let Ok(m) = Message::from_bytes(&msg.content) {
                        match m.body {
                            MessageBody::AboutMe { from, name } => {
                                peer_names.insert(from, name.clone());
                                let _ = ui_tx_c
                                    .send(UiEvent::PeerUpdate {
                                        id: from.to_string(),
                                        name: name.clone(),
                                    })
                                    .await;
                                let _ = ui_tx_c
                                    .send(UiEvent::Message {
                                        from: "System".to_string(),
                                        text: format!(
                                            "{} is now known as {}",
                                            from.fmt_short(),
                                            name
                                        ),
                                        is_system: true,
                                    })
                                    .await;
                            }
                            MessageBody::KeyExchange {
                                from: _,
                                public_key,
                            } => {
                                if public_key.len() == 32 {
                                    let peer_public = x25519_dalek::PublicKey::from(
                                        <[u8; 32]>::try_from(&public_key[..]).unwrap(),
                                    );
                                    let mut cs = crypto_c.lock().await;
                                    if !cs.is_ready() {
                                        let code = cs.complete_handshake(&peer_public);
                                        let _ =
                                            ui_tx_c.send(UiEvent::HandshakeComplete(code)).await;
                                    }
                                }
                            }
                            MessageBody::Message { from, text } => {
                                let name = peer_names
                                    .get(&from)
                                    .cloned()
                                    .unwrap_or_else(|| from.fmt_short().to_string());
                                let _ = ui_tx_c
                                    .send(UiEvent::Message {
                                        from: name,
                                        text,
                                        is_system: false,
                                    })
                                    .await;
                            }
                            MessageBody::Encrypted { from, data } => {
                                let cs = crypto_c.lock().await;
                                if let Ok(plaintext) = cs.decrypt(&data) {
                                    let text = String::from_utf8_lossy(&plaintext).to_string();
                                    let name = peer_names
                                        .get(&from)
                                        .cloned()
                                        .unwrap_or_else(|| from.fmt_short().to_string());
                                    let _ = ui_tx_c
                                        .send(UiEvent::Message {
                                            from: name,
                                            text,
                                            is_system: false,
                                        })
                                        .await;
                                }
                            }
                        }
                    }
                }
                Event::NeighborUp(peer) => {
                    let _ = ui_tx_c
                        .send(UiEvent::Message {
                            from: "System".to_string(),
                            text: format!("Neighbor {} up", peer.fmt_short()),
                            is_system: true,
                        })
                        .await;
                    // Send them our info
                    let intro = Message::new(MessageBody::AboutMe {
                        from: endpoint_c.id(),
                        name: name_c.clone(),
                    });
                    let _ = gossip_tx_r.broadcast(intro.to_vec().into()).await;
                }
                Event::NeighborDown(peer) => {
                    let _ = ui_tx_c
                        .send(UiEvent::PeerLeft {
                            id: peer.to_string(),
                        })
                        .await;
                    let _ = ui_tx_c
                        .send(UiEvent::Message {
                            from: "System".to_string(),
                            text: format!("Neighbor {} down", peer.fmt_short()),
                            is_system: true,
                        })
                        .await;
                }
                _ => {}
            }
        }
    });

    // Sender task
    let gossip_tx_s = gossip_tx.clone();
    let endpoint_s = endpoint.clone();
    let crypto_s = crypto.clone();

    while *closed.lock().await == false
        && let Some(text) = msg_rx.recv().await
    {
        let cs = crypto_s.lock().await;
        let msg = if cs.is_ready() {
            Message::new(MessageBody::Encrypted {
                from: endpoint_s.id(),
                data: cs.encrypt(text.as_bytes()),
            })
        } else {
            Message::new(MessageBody::Message {
                from: endpoint_s.id(),
                text,
            })
        };
        let _ = gossip_tx_s.broadcast(msg.to_vec().into()).await;
    }

    Ok(())
}

async fn run_app(
    terminal: &mut DefaultTerminal,
    mut app: App,
    mut ui_rx: mpsc::Receiver<UiEvent>,
    msg_tx: mpsc::Sender<String>,
) -> Result<()> {
    loop {
        terminal.draw(|f| render(f, &app))?;

        if event::poll(Duration::from_millis(10))? {
            if let CrosstermEvent::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Enter => {
                            if !app.input.is_empty() {
                                let input = app.input.drain(..).collect::<String>();
                                if msg_tx.try_send(input.clone()).is_ok() {
                                    app.messages.push(("Me".to_string(), input, false));
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            app.input.push(c);
                        }
                        KeyCode::Backspace => {
                            app.input.pop();
                        }
                        KeyCode::Esc => {
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }

        while let Ok(event) = ui_rx.try_recv() {
            match event {
                UiEvent::Message {
                    from,
                    text,
                    is_system,
                } => {
                    app.messages.push((from, text, is_system));
                }
                UiEvent::HandshakeComplete(code) => {
                    app.identity_phrase = Some(code);
                }
                UiEvent::LocalInfo { node_id } => {
                    app.local_node_id = node_id;
                }
                UiEvent::PeerUpdate { id, name } => {
                    app.peers.insert(id, name);
                }
                UiEvent::PeerLeft { id } => {
                    app.peers.remove(&id);
                }
            }
        }
    }
}

fn render(f: &mut Frame, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Info bar
            Constraint::Min(0),    // Middle part (Peers + Chat)
            Constraint::Length(3), // Input
        ])
        .split(f.area());

    // Info Bar
    let identity = app
        .identity_phrase
        .as_deref()
        .unwrap_or("Waiting for handshake...");
    let info_text = vec![Line::from(vec![
        Span::styled("Identity: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(identity, Style::default().fg(Color::Cyan)),
    ])];
    let info = Paragraph::new(info_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Patronus Status"),
    );
    f.render_widget(info, main_layout[0]);

    // Middle Layout (Peers sidebar + Chat)
    let middle_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25), // Peers
            Constraint::Percentage(75), // Chat
        ])
        .split(main_layout[1]);

    // Peers List
    let mut peers_data: Vec<_> = app.peers.iter().collect();
    peers_data.sort_by(|a, b| a.1.cmp(b.1));

    let peers: Vec<ListItem> = peers_data
        .into_iter()
        .map(|(id, name)| {
            ListItem::new(Line::from(vec![
                Span::styled(name, Style::default().fg(Color::Yellow)),
                Span::raw(" ("),
                Span::styled(id, Style::default().fg(Color::DarkGray)),
                Span::raw(")"),
            ]))
        })
        .collect();

    let peers_list = List::new(peers).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Nearby Devices"),
    );
    f.render_widget(peers_list, middle_layout[0]);

    // Chat
    let messages: Vec<ListItem> = app
        .messages
        .iter()
        .map(|(from, content, is_system)| {
            let style = if *is_system {
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC)
            } else if from == "Me" {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Yellow)
            };

            let header = Span::styled(format!("{}: ", from), style.add_modifier(Modifier::BOLD));
            let body = Span::raw(content);
            ListItem::new(Line::from(vec![header, body]))
        })
        .collect();

    let chat = List::new(messages).block(Block::default().borders(Borders::ALL).title("Chat"));
    f.render_widget(chat, middle_layout[1]);

    // Input
    let input = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Message (Esc to quit)"),
    );
    f.render_widget(input, main_layout[2]);
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    body: MessageBody,
    nonce: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize)]
enum MessageBody {
    AboutMe {
        from: EndpointId,
        name: String,
    },
    KeyExchange {
        from: EndpointId,
        public_key: Vec<u8>,
    },
    Message {
        from: EndpointId,
        text: String,
    },
    Encrypted {
        from: EndpointId,
        data: Vec<u8>,
    },
}

impl Message {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }

    pub fn new(body: MessageBody) -> Self {
        Self {
            body,
            nonce: rand::random(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json::to_vec is infallible")
    }
}
