use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::UiEvent;

const DISCOVERY_PORT: u16 = 8888;

pub struct DiscoveryService {
    app_port: u16,
    node_id: String,

    is_running: Arc<AtomicBool>,
    thread_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl DiscoveryService {
    pub fn new(app_port: u16, node_id: String) -> Self {
        Self {
            app_port,
            node_id,

            is_running: Arc::new(AtomicBool::new(false)),
            thread_handles: Mutex::new(Vec::new()),
        }
    }

    pub fn start(&self, tx: mpsc::Sender<UiEvent>) {
        self.is_running.store(true, Ordering::SeqCst);

        let mut handles = self.thread_handles.lock().unwrap();
        handles.push(self.start_broadcaster());
        handles.push(self.start_listener(tx));
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);

        let mut handles = self.thread_handles.lock().unwrap();
        for handle in handles.drain(..) {
            let _ = handle.join();
        }
    }

    fn start_broadcaster(&self) -> JoinHandle<()> {
        let magic_header = format!("PATRONUSv{}", env!("CARGO_PKG_VERSION"));

        let app_port = self.app_port;
        let node_id = self.node_id.clone();

        let is_running = Arc::clone(&self.is_running);

        thread::spawn(move || {
            let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind broadcaster");
            socket
                .set_broadcast(true)
                .expect("Failed to set broadcast flag");

            let payload = format!("{}|{}|{}", magic_header, app_port, node_id);
            let broadcast_addr = format!("255.255.255.255:{}", DISCOVERY_PORT);

            while is_running.load(Ordering::SeqCst) {
                if let Err(e) = socket.send_to(payload.as_bytes(), &broadcast_addr) {
                    eprintln!("Failed to send broadcast: {}", e);
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

    fn start_listener(&self, tx: mpsc::Sender<UiEvent>) -> JoinHandle<()> {
        let magic_header = format!("PATRONUSv{}", env!("CARGO_PKG_VERSION"));
        let is_running = Arc::clone(&self.is_running);
        let node_id = self.node_id.clone();

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
                    Ok((amt, _src)) => {
                        let msg = String::from_utf8_lossy(&buf[..amt]);
                        let parts: Vec<&str> = msg.split('|').collect();

                        if parts.len() == 3 && parts[0] == magic_header {
                            let other_node_id = parts[2].to_string();

                            if node_id == other_node_id {
                                continue;
                            }

                            let _ = tx.blocking_send(UiEvent::PeerUpdate {
                                id: other_node_id.to_owned(),
                                name: other_node_id,
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
