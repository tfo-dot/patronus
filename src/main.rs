mod client;
mod crypto;
mod discovery;

use std::{collections::HashMap, fs, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use data_encoding::BASE64;
use directories::ProjectDirs;
use discovery::DiscoveryService;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssh_key::{LineEnding, PrivateKey};
use sha2::{Digest, Sha256};
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
    #[arg(short, long)]
    broadcast: Option<bool>,
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
    custom_names: HashMap<String, String>,
    selected: usize,
    identity_phrase: Option<String>,
    input: String,
    rename_input: String,
    is_renaming: bool,
    broadcasting: bool,
}

impl App {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            peers: HashMap::new(),
            peer_ids: Vec::new(),
            custom_names: HashMap::new(),
            selected: 0,
            identity_phrase: None,
            input: String::new(),
            rename_input: String::new(),
            is_renaming: false,
            broadcasting: true,
        }
    }

    fn get_display_name(&self, id: &str) -> String {
        if let Some(name) = self.custom_names.get(id) {
            return name.clone();
        }
        if let Some((name, _)) = self.peers.get(id) {
            return name.clone();
        }
        if id.len() > 8 {
            id.chars().take(8).collect()
        } else {
            id.to_string()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _name = args.name.unwrap_or_else(|| "Anonymous".to_string());

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

    let closed = Arc::new(Mutex::new(false));
    let mut app = App::new();

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
                    if app.is_renaming {
                        match key.code {
                            KeyCode::Enter => {
                                if !app.rename_input.is_empty() {
                                    let peer_id = app.peer_ids[app.selected].clone();
                                    app.custom_names
                                        .insert(peer_id, app.rename_input.drain(..).collect());

                                    let current_peer_id = app.peer_ids[app.selected].clone();
                                    app.peer_ids.sort_by(|a, b| {
                                        let name_a = app
                                            .custom_names
                                            .get(a)
                                            .map(|s| s.as_str())
                                            .unwrap_or_else(|| {
                                                app.peers.get(a).map(|p| p.0.as_str()).unwrap_or(a)
                                            });
                                        let name_b = app
                                            .custom_names
                                            .get(b)
                                            .map(|s| s.as_str())
                                            .unwrap_or_else(|| {
                                                app.peers.get(b).map(|p| p.0.as_str()).unwrap_or(b)
                                            });

                                        name_a.cmp(name_b)
                                    });
                                    app.selected = app
                                        .peer_ids
                                        .iter()
                                        .position(|id| id == &current_peer_id)
                                        .unwrap_or(0);
                                }
                                app.is_renaming = false;
                            }
                            KeyCode::Esc => {
                                app.is_renaming = false;
                                app.rename_input.clear();
                            }
                            KeyCode::Char(c) => {
                                app.rename_input.push(c);
                            }
                            KeyCode::Backspace => {
                                app.rename_input.pop();
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Enter => {
                                if !app.input.is_empty() {
                                    let input = app.input.drain(..).collect::<String>();
                                    if msg_tx.try_send(input.clone()).is_ok() {
                                        app.messages.push(("Me".to_string(), input, false));
                                    }
                                } else if !app.peer_ids.is_empty() {
                                    let peer_id = &app.peer_ids[app.selected];
                                    if let Some((name, addr)) = app.peers.get(peer_id) {
                                        let display_name =
                                            app.custom_names.get(peer_id).unwrap_or(name);
                                        app.messages.push((
                                            "System".to_string(),
                                            format!("Connecting to {}...", display_name),
                                            true,
                                        ));
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
                            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                if !app.peer_ids.is_empty() {
                                    app.is_renaming = true;
                                    let peer_id = &app.peer_ids[app.selected];
                                    app.rename_input =
                                        app.custom_names.get(peer_id).cloned().unwrap_or_else(
                                            || app.peers.get(peer_id).unwrap().0.clone(),
                                        );
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
        }

        while let Ok(event) = ui_rx.try_recv() {
            match event {
                UiEvent::Message {
                    from,
                    mut text,
                    is_system,
                } => {
                    if is_system {
                        if text.starts_with("Connected to ") {
                            let id = text.strip_prefix("Connected to ").unwrap();
                            text = format!("Connected to {}", app.get_display_name(id));
                        } else if text.starts_with("Connection lost with ") {
                            let parts: Vec<&str> = text
                                .strip_prefix("Connection lost with ")
                                .unwrap()
                                .splitn(2, ": ")
                                .collect();
                            if parts.len() == 2 {
                                let id = parts[0];
                                let err = parts[1];
                                text = format!(
                                    "Connection lost with {}: {}",
                                    app.get_display_name(id),
                                    err
                                );
                            }
                        }
                    }
                    app.messages.push((from, text, is_system));
                }
                UiEvent::HandshakeComplete(code) => {
                    app.identity_phrase = Some(code);
                }
                UiEvent::PeerUpdate { id, name, addr } => {
                    if !app.peers.contains_key(&id) {
                        app.peer_ids.push(id.clone());
                        app.peer_ids.sort_by(|a, b| {
                            let name_a = app
                                .custom_names
                                .get(a)
                                .map(|s| s.as_str())
                                .unwrap_or_else(|| {
                                    app.peers.get(a).map(|p| p.0.as_str()).unwrap_or(a)
                                });
                            let name_b = app
                                .custom_names
                                .get(b)
                                .map(|s| s.as_str())
                                .unwrap_or_else(|| {
                                    app.peers.get(b).map(|p| p.0.as_str()).unwrap_or(b)
                                });

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
                if let Ok((mut stream, addr)) = incoming {
                    if let Err(e) = client.handshake(&mut stream, false).await {
                        let _ = ui_tx.try_send(UiEvent::Message{
                            from: "System".to_string(),
                            text: format!("Inbound handshake failed {}", e),
                            is_system: true
                        });

                        continue;
                    }

                    if let Some(id) = &client.peer_node_id {
                        let _ = ui_tx.try_send(UiEvent::PeerUpdate {
                            id: id.clone(),
                            name: id.chars().take(8).collect(),
                            addr: addr.to_string(),
                        });
                    }

                    let our_exts = client::SUPPORTED_EXTENSIONS.join(", ");
                    let peer_exts = client.peer_extensions.join(", ");
                    let _ = ui_tx.send(UiEvent::Message {
                        from: "System".to_string(),
                        text: format!(
                            "Connection established! Our extensions: [{}]. Peer extensions: [{}]",
                            our_exts, peer_exts
                        ),
                        is_system: true,
                    }).await;

                    if let Some(phrase) = &client.identity_phrase {
                        let _ = ui_tx.send(UiEvent::HandshakeComplete(phrase.clone())).await;
                    }

                    handle_connection(&mut client, stream, ui_tx.clone(), &mut msg_rx).await?;
                }
            }

                outgoing_addr = connect_rx.recv() => {
                    if let Some(addr) = outgoing_addr {
                        match tokio::net::TcpStream::connect(&addr).await {
                            Ok(mut stream) => {
                                if let Err(e) = client.handshake(&mut stream, true).await {
                                    let _ = ui_tx.send(UiEvent::Message{
                                        from: "System".to_string(),
                                        text: format!("Outbound handshake failed {}", e),
                                        is_system: true
                                    }).await;

                                    continue;
                                }

                                if let Some(id) = &client.peer_node_id {
                                    let _ = ui_tx.try_send(UiEvent::PeerUpdate {
                                        id: id.clone(),
                                        name: id.chars().take(8).collect(),
                                        addr: addr.clone(),
                                    });
                                }

                                let our_exts = client::SUPPORTED_EXTENSIONS.join(", ");
                                let peer_exts = client.peer_extensions.join(", ");
                                let _ = ui_tx.send(UiEvent::Message {
                                    from: "System".to_string(),
                                    text: format!(
                                        "Connection established! Our extensions: [{}]. Peer extensions: [{}]",
                                        our_exts, peer_exts
                                    ),
                                    is_system: true,
                                }).await;

                                if let Some(phrase) = &client.identity_phrase {
                        let _ = ui_tx.send(UiEvent::HandshakeComplete(phrase.clone())).await;
                    }

                    handle_connection(&mut client, stream, ui_tx.clone(), &mut msg_rx).await?;
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
    client: &mut client::PatronusClient,
    mut stream: S,
    ui_tx: mpsc::Sender<UiEvent>,
    msg_rx: &mut mpsc::Receiver<String>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let peer_id = client
        .peer_node_id
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());

    let _ = ui_tx
        .send(UiEvent::Message {
            from: "System".to_string(),
            text: format!("Connected to {}", peer_id),
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
                                from: peer_id.clone(),
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
                            text: format!("Connection lost with {}: {}", peer_id, e),
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
            let display_name = app.get_display_name(id);
            let style = if i == app.selected {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::Yellow)
            };

            ListItem::new(Line::from(vec![
                Span::styled(display_name, style),
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

            let display_from = if *is_system || from == "Me" {
                from.clone()
            } else {
                app.get_display_name(from)
            };

            let header = Span::styled(
                format!("{}: ", display_from),
                style.add_modifier(Modifier::BOLD),
            );
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
            .title("Message (Esc to quit, Ctrl+B to toggle broadcast, Ctrl+R to rename peer)"),
    );
    f.render_widget(input, main_layout[2]);

    if app.is_renaming {
        let block = Block::default()
            .title("Rename Peer")
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Blue));
        let area = centered_rect(60, 20, f.area());
        f.render_widget(ratatui::widgets::Clear, area); //this clears out the background
        let input = Paragraph::new(app.rename_input.as_str()).block(block);
        f.render_widget(input, area);
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
