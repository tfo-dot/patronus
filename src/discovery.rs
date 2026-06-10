use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::mpsc;
use get_if_addrs::{get_if_addrs, IfAddr};

use crate::UiEvent;

const DISCOVERY_PORT: u16 = 8888;

pub struct DiscoveryService {
    app_port: u16,
    node_id: String,
    bind_ip: std::net::IpAddr,

    is_running: Arc<AtomicBool>,
    broadcasting: Arc<AtomicBool>,
    thread_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl DiscoveryService {
    pub fn new(app_port: u16, node_id: String, bind_ip: std::net::IpAddr) -> Self {
        Self {
            app_port,
            node_id,
            bind_ip,

            is_running: Arc::new(AtomicBool::new(false)),
            broadcasting: Arc::new(AtomicBool::new(true)),
            thread_handles: Mutex::new(Vec::new()),
        }
    }

    pub fn start(&self, ui_tx: mpsc::Sender<UiEvent>) {
        self.is_running.store(true, Ordering::SeqCst);

        let mut handles = self.thread_handles.lock().unwrap();
        handles.push(self.start_broadcaster());
        handles.push(self.start_listener(ui_tx));
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);

        let mut handles = self.thread_handles.lock().unwrap();
        for handle in handles.drain(..) {
            let _ = handle.join();
        }
    }

    pub fn set_broadcasting(&self, enabled: bool) {
        self.broadcasting.store(enabled, Ordering::SeqCst);
    }

    pub fn is_broadcasting(&self) -> bool {
        self.broadcasting.load(Ordering::SeqCst)
    }

    fn start_broadcaster(&self) -> JoinHandle<()> {
        let magic_header = format!("PATRONUSv{}", env!("CARGO_PKG_VERSION"));

        let app_port = self.app_port;
        let node_id = self.node_id.clone();
        let bind_ip = self.bind_ip;

        let is_running = Arc::clone(&self.is_running);
        let broadcasting = Arc::clone(&self.broadcasting);

        thread::spawn(move || {
            let socket = UdpSocket::bind(format!("{}:0", bind_ip)).expect("Failed to bind broadcaster");
            socket
                .set_broadcast(true)
                .expect("Failed to set broadcast flag");

            let payload = format!("{}|{}|{}", magic_header, app_port, node_id);

            while is_running.load(Ordering::SeqCst) {
                if broadcasting.load(Ordering::SeqCst) {
                    let broadcast_ips = get_broadcast_addresses(bind_ip);
                    for bcast_ip in broadcast_ips {
                        let broadcast_addr = format!("{}:{}", bcast_ip, DISCOVERY_PORT);
                        if let Err(e) = socket.send_to(payload.as_bytes(), &broadcast_addr) {
                            eprintln!("Failed to send broadcast to {}: {}", broadcast_addr, e);
                        }
                    }
                }

                for _ in 0..30 {
                    if !is_running.load(Ordering::SeqCst) {
                        break;
                    }

                    thread::sleep(Duration::from_millis(100));
                }
            }
        })
    }

    fn start_listener(&self, ui_tx: mpsc::Sender<UiEvent>) -> JoinHandle<()> {
        let magic_header = format!("PATRONUSv{}", env!("CARGO_PKG_VERSION"));
        let is_running = Arc::clone(&self.is_running);
        let self_node_id = self.node_id.clone();

        thread::spawn(move || {
            let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

            raw_socket.set_reuse_address(true).unwrap();
            #[cfg(unix)]
            {
                raw_socket.set_reuse_port(true).unwrap();
            }

            let addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT).parse().unwrap();
            raw_socket.bind(&addr.into()).unwrap();

            let socket: UdpSocket = raw_socket.into();
            let mut buf = [0; 1024];

            socket
                .set_read_timeout(Some(Duration::from_millis(1000)))
                .unwrap();

            while is_running.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buf) {
                    Ok((amt, src)) => {
                        let msg = String::from_utf8_lossy(&buf[..amt]);
                        let parts: Vec<&str> = msg.split('|').collect();

                        // payload: magic_header | app_port | node_id
                        if parts.len() == 3 && parts[0] == magic_header {
                            let incoming_node_id = parts[2].to_string();

                            if incoming_node_id == self_node_id {
                                continue;
                            }

                            // name is a placeholder until the real handshake fills it in
                            let short_name: String = incoming_node_id.chars().take(8).collect();

                            let addr = format!("{}:{}", src.ip(), parts[1]);

                            let _ = ui_tx.try_send(UiEvent::PeerUpdate {
                                id: incoming_node_id,
                                name: short_name,
                                addr,
                            });
                        }
                    }
                    Err(e) => {
                        use std::io::ErrorKind;

                        if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::TimedOut {
                            eprintln!("Listener socket error: {}", e);
                        }
                    }
                }
            }
        })
    }
}

fn get_broadcast_addresses(bind_ip: std::net::IpAddr) -> Vec<std::net::IpAddr> {
    let mut addrs = Vec::new();
    if let Ok(interfaces) = get_if_addrs() {
        if bind_ip.is_unspecified() {
            // If binding to all interfaces (0.0.0.0 / ::), find all IPv4 non-loopback interfaces with broadcast addrs
            for iface in interfaces {
                if !iface.is_loopback() {
                    if let IfAddr::V4(ifv4) = iface.addr {
                        if let Some(bcast) = ifv4.broadcast {
                            addrs.push(std::net::IpAddr::V4(bcast));
                        }
                    }
                }
            }
        } else {
            // Find the interface that matches bind_ip
            for iface in interfaces {
                if iface.addr.ip() == bind_ip {
                    if let IfAddr::V4(ifv4) = iface.addr {
                        if let Some(bcast) = ifv4.broadcast {
                            addrs.push(std::net::IpAddr::V4(bcast));
                        }
                    }
                    break;
                }
            }
        }
    }
    // Fallback to 255.255.255.255 if no broadcast addresses were found
    if addrs.is_empty() {
        addrs.push("255.255.255.255".parse().unwrap());
    }
    addrs
}
