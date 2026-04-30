mod client;
mod crypto;
mod discovery;

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use discovery::DiscoveryService;
use ed25519_dalek::SigningKey;
use ssh_key::{HashAlg, PrivateKey};
use tokio::sync::{Mutex, mpsc};

use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind, KeyModifiers},
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
    PeerUpdate {
        id: String,
        name: String,
        addr: String,
    },
}

struct App {
    messages: Vec<(String, String, bool)>, // (Sender, Content, IsSystem)
    peers: HashMap<String, (String, String)>, //(Name, Address)
    peer_ids: Vec<String>,
    selected: usize,
    identity_phrase: Option<String>,
    input: String,
    broadcasting: bool,
}

impl App {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            peers: HashMap::new(),
            peer_ids: Vec::new(),
            selected: 0,
            identity_phrase: None,
            input: String::new(),
            broadcasting: true,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _name = args.name.unwrap_or_else(|| "Anonymous".to_string());

    let pk = match args.priv_key {
        Some(p) => PrivateKey::read_openssh_file(Path::new(&p)),
        None => PrivateKey::from_openssh(include_str!("../keys/one")),
    }
    .unwrap();

    let binding = pk.public_key().fingerprint(HashAlg::Sha256).to_string();
    let local_node_id = binding.strip_prefix("SHA256:").unwrap();

    let ed_sk = pk.key_data().ed25519().expect("Ed25519 key required");
    let signing_key = SigningKey::from_bytes(ed_sk.private.as_ref());

    let closed = Arc::new(Mutex::new(false));
    let app = App::new();

    let (ui_tx, ui_rx) = mpsc::channel(100);
    let (msg_tx, msg_rx) = mpsc::channel::<String>(100);
    let (connect_tx, connect_rx) = mpsc::channel::<String>(100);

    let app_port: u16 = (rand::random::<u16>() % 255) + 6000;

    let ui_tx_net = ui_tx.clone();
    let singing_key_net = signing_key.clone();

    tokio::spawn(async move {
        if let Err(e) = run_network(singing_key_net, app_port, ui_tx_net, msg_rx, connect_rx).await
        {
            eprintln!("Network error: {}", e);
        }
    });

    let discovery = Arc::new(DiscoveryService::new(app_port, local_node_id.to_string()));

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
    *closed.lock().await = true;

    result
}

async fn run_app(
    terminal: &mut DefaultTerminal,
    mut app: App,
    mut ui_rx: mpsc::Receiver<UiEvent>,
    msg_tx: mpsc::Sender<String>,
    connect_tx: mpsc::Sender<String>,
    discovery: Arc<DiscoveryService>,
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
                            } else if !app.peer_ids.is_empty() {
                                let peer_id = &app.peer_ids[app.selected];
                                if let Some((_, addr)) = app.peers.get(peer_id) {
                                    let _ = connect_tx.try_send(addr.clone());
                                }
                            }
                        }
                        KeyCode::Up => {
                            if !app.peer_ids.is_empty() {
                                app.selected = if app.selected > 0 {
                                    app.selected - 1
                                } else {
                                    app.peer_ids.len() - 1
                                }
                            }
                        }
                        KeyCode::Down => {
                            if !app.peer_ids.is_empty() {
                                app.selected = (app.selected + 1) % app.peer_ids.len();
                            }
                        }
                        KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let new_state = !discovery.is_broadcasting();
                            discovery.set_broadcasting(new_state);
                            app.broadcasting = new_state;
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
                UiEvent::PeerUpdate { id, name, addr } => {
                    if !app.peers.contains_key(&id) {
                        app.peer_ids.push(id.clone());
                        app.peer_ids.sort_by(|a, b| {
                            let name_a = &app.peers.get(a).map(|p| p.0.as_str()).unwrap_or(a);
                            let name_b = &app.peers.get(b).map(|p| p.0.as_str()).unwrap_or(b);

                            name_a.cmp(name_b)
                        });
                    }

                    app.peers.insert(id, (name, addr));
                }
            }
        }
    }
}

async fn run_network(
    singing_key: SigningKey,
    app_port: u16,
    ui_tx: mpsc::Sender<UiEvent>,
    mut msg_rx: mpsc::Receiver<String>,
    mut connect_rx: mpsc::Receiver<String>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", app_port)).await?;
    let mut client = client::PatronusClient::new(singing_key);

    loop {
        tokio::select! {
            incoming = listener.accept() => {
                if let Ok((mut stream, _)) = incoming {
                    if let Err(e) = client.handshake(&mut stream).await {
                        let _ = ui_tx.try_send(UiEvent::Message{
                            from: "System".to_string(),
                            text: format!("Inbound handshake failed {}", e),
                            is_system: true
                        });

                        continue;
                    }

                    if let Some(phrase) = &client.identity_phrase {
                        let _ = ui_tx.send(UiEvent::HandshakeComplete(phrase.clone())).await;
                    }

                    handle_connection(&client, stream, ui_tx.clone(), &mut msg_rx).await?;
                }
            }

                outgoing_addr = connect_rx.recv() => {
                    if let Some(addr) = outgoing_addr {
                        match tokio::net::TcpStream::connect(&addr).await {
                            Ok(mut stream) => {
                                if let Err(e) = client.handshake(&mut stream).await {
                                    let _ = ui_tx.send(UiEvent::Message{
                                        from: "System".to_string(),
                                        text: format!("Outbound handshake failed {}", e),
                                        is_system: true
                                    }).await;

                                    continue;
                                }

                                if let Some(phrase) = &client.identity_phrase {
                        let _ = ui_tx.send(UiEvent::HandshakeComplete(phrase.clone())).await;
                    }

                    handle_connection(&client, stream, ui_tx.clone(), &mut msg_rx).await?;
                            }
                            Err(e) => {
                                let _ = ui_tx.send(UiEvent::Message{
                                    from: "System".to_string(),
                                    text: format!("Connection to {} failed: {}", addr, e),
                                    is_system: true
                                }).await;
                            }
                        }
                    }
            }
        }
    }
}

async fn handle_connection<S>(
    client: &client::PatronusClient,
    mut stream: S,
    ui_tx: mpsc::Sender<UiEvent>,
    msg_rx: &mut mpsc::Receiver<String>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = ui_tx
        .send(UiEvent::Message {
            from: "System".to_string(),
            text: "Connect to peer".to_string(),
            is_system: true,
        })
        .await;

    loop {
        tokio::select! {
            msg = msg_rx.recv() => {
                if let Some(text) = msg {
                    let json = serde_json::json!({ "text": text });
                    client.send_app_message(&mut stream, &json).await?;
                }
            }

            res = client.receive_message(&mut stream) => {
                match res {
                    Ok((0x01, payload)) => {
                        let json: serde_json::Value = serde_json::from_slice(&payload)?;
                        if let Some(text) = json["text"].as_str() {
                            let _ = ui_tx.send(UiEvent::Message {
                                from: "Peer".to_string(),
                                text: text.to_string(),
                                is_system: false,
                            }).await;
                        }
                    }
                    Ok((message_type, _)) => {
                        let _ = ui_tx.send(UiEvent::Message {
                            from: "System".to_string(),
                            text: format!("Received unknown message type: 0x{:02x}", message_type),
                            is_system: false
                        }).await;
                    }
                    Err(e) => {
                        let _ = ui_tx.send(UiEvent::Message {
                            from: "System".to_string(),
                            text: format!("Connection lost {}", e),
                            is_system: true
                        }).await;

                        return Ok(());
                    }
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
    let (broadcast_label, broadcast_color) = if app.broadcasting {
        ("ON", Color::Green)
    } else {
        ("OFF", Color::Red)
    };
    let info_text = vec![Line::from(vec![
        Span::styled("Identity: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(identity, Style::default().fg(Color::Cyan)),
        Span::raw(" | "),
        Span::styled("Broadcast: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(broadcast_label, Style::default().fg(broadcast_color)),
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

    let peers: Vec<ListItem> = app
        .peer_ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let (name, _addr): &(String, String) = app.peers.get(id).unwrap();
            let style = if i == app.selected {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::Yellow)
            };

            ListItem::new(Line::from(vec![
                Span::styled(name.as_str(), style),
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
        .rev()
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
            .title("Message (Esc to quit, Ctrl+B to toggle broadcast)"),
    );
    f.render_widget(input, main_layout[2]);
}