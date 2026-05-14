use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Result;
use crate::discovery::DiscoveryService;
use tokio::sync::mpsc;

use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::UiEvent;

pub struct App {
    pub messages: Vec<(String, String, bool)>, // (sender, content, is_system)
    pub peers: HashMap<String, (String, String)>, // (name, address)
    pub peer_ids: Vec<String>,
    pub custom_names: HashMap<String, String>,
    pub selected: usize,
    pub identity_phrase: Option<String>,
    pub input: String,
    pub rename_input: String,
    pub is_renaming: bool,
    pub broadcasting: bool,
}

impl App {
    pub fn new() -> Self {
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

    pub fn get_display_name(&self, id: &str) -> String {
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

pub async fn run_app(
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

fn render(f: &mut Frame, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

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

    let middle_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(75),
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
        f.render_widget(ratatui::widgets::Clear, area);
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