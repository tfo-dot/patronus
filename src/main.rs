mod client;
mod crypto;
mod discovery;

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use discovery::DiscoveryService;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PrivateKey};
use tokio::sync::{Mutex, mpsc};

use crate::crypto::CryptoState;
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
    LocalInfo {
        node_id: String,
    },
    PeerUpdate {
        id: String,
        name: String,
    },
}

struct App {
    messages: Vec<(String, String, bool)>, // (Sender, Content, IsSystem)
    peers: HashMap<String, String>,
    local_node_id: String,
    identity_phrase: Option<String>,
    input: String,
    broadcasting: bool,
}

impl App {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            peers: HashMap::new(),
            local_node_id: "Initializing...".to_string(),
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

    let _crypto = Arc::new(Mutex::new(CryptoState::new(signing_key)));
    let closed = Arc::new(Mutex::new(false));
    let app = App::new();

    let (ui_tx, ui_rx) = mpsc::channel(100);
    let (msg_tx, _msg_rx) = mpsc::channel::<String>(100);

    let app_port: u16 = (rand::random::<u16>() % 255) + 6000;
    let discovery = Arc::new(DiscoveryService::new(app_port, local_node_id.to_string()));

    let ui_tx_disc = ui_tx.clone();

    discovery.start(ui_tx_disc);

    // UI loop
    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal, app, ui_rx, msg_tx, discovery.clone()).await;

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
                UiEvent::LocalInfo { node_id } => {
                    app.local_node_id = node_id;
                }
                UiEvent::PeerUpdate { id, name } => {
                    app.peers.insert(id, name);
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
            .title("Message (Esc to quit, Ctrl+B to toggle broadcast)"),
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
    AboutMe { from: String, name: String },
    KeyExchange { from: String, public_key: Vec<u8> },
    Message { from: String, text: String },
    Encrypted { from: String, data: Vec<u8> },
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
