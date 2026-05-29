use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};

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

use crate::{UiEvent, OutboundMessage};

// 24 hour limit on ttl since longer values are pointless
const MAX_TTL: u64 = 24 * 3600;

pub fn format_ttl(secs: u64) -> String {
    if secs >= 86400 {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        if h > 0 { format!("{}d {}h", d, h) } else { format!("{}d", d) }
    } else if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 { format!("{}h {}m", h, m) } else { format!("{}h", h) }
    } else if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        if s > 0 { format!("{}m {}s", m, s) } else { format!("{}m", m) }
    } else {
        format!("{}s", secs)
    }
}

fn parse_ttl(s: &str) -> Result<u64, ()> {
    if s.is_empty() {
        return Err(());
    }

    let mut total: u64 = 0;
    let mut current_val: u64 = 0;
    let mut num_started = false;

    for c in s.chars() {
        if let Some(digit) = c.to_digit(10) {

            current_val = current_val
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit as u64))
                .ok_or(())?;
            num_started = true;
        } else {
            if !num_started {
                return Err(());
            }

            let multiplier = match c {
                'd' => 86400,
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return Err(()),
            };

            let chunk = current_val.checked_mul(multiplier).ok_or(())?;
            total = total.checked_add(chunk).ok_or(())?;
            
            current_val = 0;
            num_started = false;
        }
    }

    if num_started {
        total = total.checked_add(current_val).ok_or(())?;
    }

    Ok(total)
}

pub struct Message {
    pub from: String,
    pub content: String,
    pub is_system: bool,
    pub ttl: Option<u64>,
    pub received_at: Instant,
}

#[derive(Clone, Debug)]
pub struct AutocompleteState {
    pub matches: Vec<String>,
    pub index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutocompleteAction {
    Path,
    Directory,
}

pub struct AutocompleteRule {
    pub prefix: &'static str,
    pub action: AutocompleteAction,
}

const AUTOCOMPLETE_RULES: &[AutocompleteRule] = &[
    AutocompleteRule { prefix: "/send ", action: AutocompleteAction::Path },
    AutocompleteRule { prefix: "/save_dir ", action: AutocompleteAction::Directory },
    AutocompleteRule { prefix: "/accept ", action: AutocompleteAction::Path },
];

pub fn get_autocomplete_matches(input: &str) -> Vec<String> {
    if input.starts_with('/') && !input.contains(' ') {
        // Complete command names
        let mut commands = vec![
            "/send ".to_string(),
            "/save_dir ".to_string(),
            "/accept ".to_string(),
            "/decline".to_string(),
        ];
        // Also allow dynamic rules to be completed if they are registered
        for rule in AUTOCOMPLETE_RULES {
            let cmd = rule.prefix.to_string();
            if !commands.contains(&cmd) {
                commands.push(cmd);
            }
        }
        commands
            .into_iter()
            .filter(|c| c.starts_with(input))
            .collect()
    } else {
        // Find matching rule
        for rule in AUTOCOMPLETE_RULES {
            if input.starts_with(rule.prefix) {
                let path_fragment = &input[rule.prefix.len()..];

                // Split path_fragment into directory part and filename prefix
                let (part_before_last_slash, file_prefix) = if let Some(last_slash_idx) = path_fragment.rfind('/') {
                    (&path_fragment[..=last_slash_idx], &path_fragment[last_slash_idx + 1..])
                } else if let Some(last_backslash_idx) = path_fragment.rfind('\\') {
                    (&path_fragment[..=last_backslash_idx], &path_fragment[last_backslash_idx + 1..])
                } else {
                    ("", path_fragment)
                };

                // Expand tilde
                let dir_to_read = if part_before_last_slash.starts_with('~') {
                    if let Ok(home) = std::env::var("HOME") {
                        part_before_last_slash.replacen('~', &home, 1)
                    } else {
                        part_before_last_slash.to_string()
                    }
                } else {
                    part_before_last_slash.to_string()
                };

                let dir_path = if dir_to_read.is_empty() {
                    std::path::PathBuf::from(".")
                } else {
                    std::path::PathBuf::from(&dir_to_read)
                };

                let show_hidden = file_prefix.starts_with('.');

                let mut matches = Vec::new();
                if file_prefix == "." {
                    matches.push(format!("{}{}{}/", rule.prefix, part_before_last_slash, "."));
                }
                if file_prefix == ".." {
                    matches.push(format!("{}{}{}/", rule.prefix, part_before_last_slash, ".."));
                }
                if let Ok(entries) = std::fs::read_dir(dir_path) {
                    for entry in entries.flatten() {
                        if let Ok(file_type) = entry.file_type() {
                            // Filter for directory-only completions
                            if rule.action == AutocompleteAction::Directory && !file_type.is_dir() {
                                continue;
                            }

                            let file_name = entry.file_name().to_string_lossy().into_owned();
                            if !show_hidden && file_name.starts_with('.') {
                                continue;
                            }

                            if file_name.starts_with(file_prefix) {
                                let mut completed = format!("{}{}{}", rule.prefix, part_before_last_slash, file_name);
                                if file_type.is_dir() {
                                    completed.push('/');
                                }
                                matches.push(completed);
                            }
                        }
                    }
                }

                matches.sort();
                return matches;
            }
        }
        Vec::new()
    }
}

pub struct App {
    pub messages: Vec<Message>,
    pub peers: HashMap<String, (String, String)>, // (name, address)
    pub peer_ids: Vec<String>,
    pub custom_names: HashMap<String, String>,
    pub selected: usize,
    pub identity_phrase: Option<String>,
    pub input: String,
    pub rename_input: String,
    pub is_renaming: bool,
    pub broadcasting: bool,
    pub autocomplete: Option<AutocompleteState>,
    pub current_ttl: Option<u64>,
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
            autocomplete: None,
            current_ttl: None,
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

    pub fn cleanup_expired_messages(&mut self) {
        let now = Instant::now();
        self.messages.retain(|msg| {
            if let Some(ttl) = msg.ttl {
                now.duration_since(msg.received_at) < Duration::from_secs(ttl)
            } else {
                true
            }
        });
    }
}

pub async fn run_app(
    terminal: &mut DefaultTerminal,
    mut app: App,
    mut ui_rx: mpsc::Receiver<UiEvent>,
    msg_tx: mpsc::Sender<OutboundMessage>,
    connect_tx: mpsc::Sender<String>,
    discovery: Arc<DiscoveryService>,
) -> Result<()> {
    loop {
        app.cleanup_expired_messages();
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
                                  
                                    app.autocomplete = None;
                                  
                                    if input == "/ttl" {
                                        let status = match app.current_ttl {
                                            Some(s) => format!("TTL is set to {} — messages disappear after that time. Use /ttl <time> to change or /ttl 0 to disable.", format_ttl(s)),
                                            None => "TTL is disabled — messages persist until you close the app. Use /ttl <time> to enable (e.g. /ttl 30m, /ttl 2h, /ttl 1d).".to_string(),
                                        };
                                        app.messages.push(Message {
                                            from: "System".to_string(),
                                            content: status,
                                            is_system: true,
                                            ttl: None,
                                            received_at: Instant::now(),
                                        });
                                    } else if input.starts_with("/ttl ") {
                                        let parts: Vec<&str> = input.split_whitespace().collect();
                                        // fix: wrong arg count now surfaces an error instead of silently doing nothing
                                        if parts.len() != 2 {
                                            app.messages.push(Message {
                                                from: "System".to_string(),
                                                content: "Usage: /ttl <time>  (e.g. 30s, 5m, 2h, 1d) or /ttl 0 to disable".to_string(),
                                                is_system: true,
                                                ttl: None,
                                                received_at: Instant::now(),
                                            });
                                        } else {
                                            match parse_ttl(parts[1]) {
                                                Ok(0) => {
                                                    app.current_ttl = None;
                                                    
                                                    let _ = msg_tx.try_send(OutboundMessage::TTLNotice { ttl: None });

                                                    app.messages.push(Message {
                                                        from: "System".to_string(),
                                                        content: "TTL disabled — new messages will persist.".to_string(),
                                                        is_system: true,
                                                        ttl: None,
                                                        received_at: Instant::now(),
                                                    });
                                                }
                                                Ok(ttl) if ttl <= MAX_TTL => {
                                                    app.current_ttl = Some(ttl);

                                                    let _ = msg_tx.try_send(OutboundMessage::TTLNotice { ttl: Some(ttl) });

                                                    app.messages.push(Message {
                                                        from: "System".to_string(),
                                                        content: format!("TTL set to {} — new messages will disappear after that time.", format_ttl(ttl)),
                                                        is_system: true,
                                                        ttl: None,
                                                        received_at: Instant::now(),
                                                    });
                                                }
                                                // fix: values above MAX_TTL now surface an error instead of silently doing nothing
                                                Ok(_) => {
                                                    app.messages.push(Message {
                                                        from: "System".to_string(),
                                                        content: format!("TTL too large — maximum is {} ({}s).", format_ttl(MAX_TTL), MAX_TTL),
                                                        is_system: true,
                                                        ttl: None,
                                                        received_at: Instant::now(),
                                                    });
                                                }
                                                // fix: unparseable input now surfaces an error instead of silently doing nothing
                                                Err(()) => {
                                                    app.messages.push(Message {
                                                        from: "System".to_string(),
                                                        content: format!("Invalid TTL '{}' — expected a number with an optional unit: 30s, 5m, 2h, 1d.", parts[1]),
                                                        is_system: true,
                                                        ttl: None,
                                                        received_at: Instant::now(),
                                                    });
                                                }
                                            }
                                        }
                                    } else if msg_tx.try_send(OutboundMessage::Message { text: input.clone(), ttl: app.current_ttl }).is_ok() {
                                        app.messages.push(Message {
                                            from: "Me".to_string(),
                                            content: input,
                                            is_system: false,
                                            ttl: app.current_ttl,
                                            received_at: Instant::now(),
                                        });
                                    }
                                } else if !app.peer_ids.is_empty() {
                                    let peer_id = &app.peer_ids[app.selected];
                                    if let Some((name, addr)) = app.peers.get(peer_id) {
                                        let display_name =
                                            app.custom_names.get(peer_id).unwrap_or(name);
                                        app.messages.push(Message {
                                            from: "System".to_string(),
                                            content: format!("Connecting to {}...", display_name),
                                            is_system: true,
                                            ttl: None,
                                            received_at: Instant::now(),
                                        });
                                        let _ = connect_tx.try_send(addr.clone());
                                    }
                                }
                            }
                            KeyCode::Tab | KeyCode::BackTab => {
                                let is_backwards = key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::SHIFT);
                                if let Some(mut state) = app.autocomplete.take() {
                                    if !state.matches.is_empty() {
                                        if is_backwards {
                                            state.index = if state.index > 0 {
                                                state.index - 1
                                            } else {
                                                state.matches.len() - 1
                                            };
                                        } else {
                                            state.index = (state.index + 1) % state.matches.len();
                                        }
                                        app.input = state.matches[state.index].clone();
                                        app.autocomplete = Some(state);
                                    }
                                } else {
                                    let matches = get_autocomplete_matches(&app.input);
                                    if !matches.is_empty() {
                                        let index = if is_backwards { matches.len() - 1 } else { 0 };
                                        app.input = matches[index].clone();
                                        app.autocomplete = Some(AutocompleteState {
                                            matches,
                                            index,
                                        });
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
                                app.autocomplete = None;
                            }
                            KeyCode::Backspace => {
                                app.input.pop();
                                app.autocomplete = None;
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
                    ttl,
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
                    app.messages.push(Message {
                        from,
                        content: text,
                        is_system,
                        ttl,
                        received_at: Instant::now(),
                    });
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
    let show_autocomplete = app.autocomplete.as_ref().map_or(false, |a| !a.matches.is_empty());
    let input_height = if show_autocomplete { 4 } else { 3 };
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(input_height),
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

    let ttl_info = if let Some(ttl) = app.current_ttl {
        format!(" | TTL: {}", format_ttl(ttl))
    } else {
        "".to_string()
    };

    let info_text = vec![Line::from(vec![
        Span::styled("Identity: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(identity, Style::default().fg(Color::Cyan)),
        Span::raw(" | "),
        Span::styled("Broadcast: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(broadcast_label, Style::default().fg(broadcast_color)),
        Span::raw(ttl_info),
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
        .map(|msg| {
            let style = if msg.is_system {
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC)
            } else if msg.from == "Me" {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Yellow)
            };

            let display_from = if msg.is_system || msg.from == "Me" {
                msg.from.clone()
            } else {
                app.get_display_name(&msg.from)
            };

            let spans = vec![
                Span::styled(
                    format!("{}: ", display_from),
                    style.add_modifier(Modifier::BOLD),
                ),
                Span::raw(&msg.content),
            ];

            ListItem::new(Line::from(spans))
        })
        .collect();

    let chat = List::new(messages).block(Block::default().borders(Borders::ALL).title("Chat"));
    f.render_widget(chat, middle_layout[1]);

    if show_autocomplete {
        let input_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Suggestions bar
                Constraint::Length(3), // Input field
            ])
            .split(main_layout[2]);

        if let Some(state) = &app.autocomplete {
            let mut spans = vec![Span::styled("Suggestions (Tab to cycle): ", Style::default().fg(Color::DarkGray))];
            for (idx, m) in state.matches.iter().enumerate() {
                if idx > 0 {
                    spans.push(Span::raw("  "));
                }
                
                let display_str = if m.starts_with('/') || m.contains('/') || m.contains('\\') {
                    if let Some(idx) = m.rfind('/') {
                        &m[idx+1..]
                    } else if let Some(idx) = m.rfind('\\') {
                        &m[idx+1..]
                    } else {
                        m.as_str()
                    }
                } else {
                    m.as_str()
                };

                let display_str = if display_str.is_empty() { m.as_str() } else { display_str };

                if idx == state.index {
                    spans.push(Span::styled(
                        format!("[ {} ]", display_str),
                        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
                    ));
                } else {
                    spans.push(Span::styled(
                        display_str,
                        Style::default().fg(Color::Cyan)
                    ));
                }
            }
            let suggestions = Paragraph::new(Line::from(spans));
            f.render_widget(suggestions, input_layout[0]);
        }

        let input = Paragraph::new(app.input.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Message (Esc: quit | Ctrl+B: broadcast | Ctrl+R: rename | /send <file> | /accept [<path>] | /decline | /save_dir <path> | /ttl [30s|5m|2h|0]))"),
        );
        f.render_widget(input, input_layout[1]);
    } else {
        let input = Paragraph::new(app.input.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Message (Esc: quit | Ctrl+B: broadcast | Ctrl+R: rename | /send <file> | /accept [<path>] | /decline | /save_dir <path> | /ttl [30s|5m|2h|0]))"),
        );
        f.render_widget(input, main_layout[2]);
    }

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