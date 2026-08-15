//! Minimal HTTP/1.1 server that serves `/.well-known/acme-challenge/*`
//! from an in-memory `token → body` map.
//!
//! Threading model: one thread accepts connections and spawns a worker
//! per connection. Each worker reads one HTTP request (up to a
//! reasonable header ceiling), matches on the path, and writes one
//! response. This is not a general-purpose HTTP server — it is the
//! smallest thing that answers Pebble's single `GET
//! /.well-known/acme-challenge/<token>` probe. Pebble's HTTP-01
//! validator issues exactly one request per challenge, so single-shot
//! response handling is sufficient.
//!
//! The server binds `0.0.0.0:5002` by default — Pebble's default
//! `httpPort`. Callers who want a different port pass one to
//! [`Http01Server::bind_on`].

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use acme_core::challenge::{ChallengeKind, ChallengeReady, ChallengeSolver};
use acme_core::error::{AcmeError, Result as AcmeResult};
use acme_core::order::Identifier;

/// Pebble's default HTTP-01 validation port (see the `httpPort`
/// field of the bundled `pebble-config.json`).
pub const DEFAULT_HTTP_PORT: u16 = 5002;

/// A running HTTP-01 responder — the well-known token → body map is
/// shared behind an `Arc<Mutex<_>>` so the caller can seed entries
/// after start.
pub struct Http01Server {
    map: Arc<Mutex<HashMap<String, String>>>,
    local_addr: SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    _handle: Option<JoinHandle<()>>,
}

impl Http01Server {
    /// Bind on `0.0.0.0:5002` — the port Pebble's validator dials by
    /// default. Fails with an `io::Error` if something else already
    /// owns the port.
    pub fn bind_default() -> std::io::Result<Self> {
        Self::bind_on(("0.0.0.0", DEFAULT_HTTP_PORT))
    }

    /// Bind on an arbitrary address. Useful for negative tests or when
    /// running under an alternate Pebble config that changes
    /// `httpPort`.
    pub fn bind_on<A: std::net::ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        let local_addr = listener.local_addr()?;

        let map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let map_for_thread = map.clone();
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("acme-testing-http01-accept".into())
            .spawn(move || accept_loop(listener, map_for_thread, shutdown_for_thread))?;

        Ok(Self {
            map,
            local_addr,
            shutdown,
            _handle: Some(handle),
        })
    }

    /// The bound `SocketAddr`. Useful when the caller bound port 0
    /// and needs to learn the OS-assigned port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Insert a token → key-authorization mapping. The server serves
    /// this body when a GET arrives at `/.well-known/acme-challenge/<token>`.
    pub fn insert(&self, token: &str, body: &str) {
        self.map
            .lock()
            .unwrap()
            .insert(token.to_string(), body.to_string());
    }

    /// Remove a mapping. Idempotent.
    pub fn remove(&self, token: &str) {
        self.map.lock().unwrap().remove(token);
    }
}

impl Drop for Http01Server {
    fn drop(&mut self) {
        // Flip the flag and open a dummy connection to unstick the
        // accept loop. Best-effort — we never panic in Drop.
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(500));
    }
}

/// The accept loop reads one request per accepted socket and writes
/// one response. Pebble opens a fresh connection per validation probe,
/// so we do not bother with keep-alive.
fn accept_loop(
    listener: TcpListener,
    map: Arc<Mutex<HashMap<String, String>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    // Short read/accept timeouts so shutdown is responsive.
    let _ = listener.set_nonblocking(false);
    for stream in listener.incoming() {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let map = map.clone();
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &map);
        });
    }
}

/// Read one HTTP/1.1 request line + headers, dispatch on the path,
/// write one response. Body is unread — no HTTP-01 probe carries one.
fn handle_connection(
    mut stream: TcpStream,
    map: &Arc<Mutex<HashMap<String, String>>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain headers.
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header)?;
        if n == 0 || header == "\r\n" || header == "\n" {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" {
        return write_response(&mut stream, 405, "Method Not Allowed", b"");
    }

    const PREFIX: &str = "/.well-known/acme-challenge/";
    if let Some(token) = path.strip_prefix(PREFIX) {
        if let Some(body) = map.lock().unwrap().get(token).cloned() {
            return write_response(&mut stream, 200, "OK", body.as_bytes());
        }
    }
    write_response(&mut stream, 404, "Not Found", b"")
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    // Consume any client body so we don't RST before the client sees
    // our response — Pebble's HTTP-01 probes have no body but be
    // defensive.
    let mut sink = [0u8; 64];
    let _ = stream.read(&mut sink);
    Ok(())
}

// --------------------------------------------------------------------
// ChallengeSolver adapter — plugs the running server into the
// acme_core::issue_certificate driver.
// --------------------------------------------------------------------

/// `ChallengeSolver` that installs the key authorization into a
/// running [`Http01Server`] on arm, and removes it on drop.
///
/// The server is passed in — the solver does not own it — so a single
/// server can back multiple challenges within one order.
pub struct Http01SolverAdapter {
    server: Arc<Http01Server>,
}

impl Http01SolverAdapter {
    pub fn new(server: Arc<Http01Server>) -> Self {
        Self { server }
    }
}

impl ChallengeSolver for Http01SolverAdapter {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Http01
    }

    fn arm(
        &self,
        _identifier: &Identifier,
        key_authorization: &str,
    ) -> AcmeResult<Box<dyn ChallengeReady>> {
        // Extract the token — key authorization is `token.thumbprint`.
        let token = key_authorization
            .split('.')
            .next()
            .ok_or_else(|| AcmeError::Malformed("empty key authorization".into()))?
            .to_string();
        self.server.insert(&token, key_authorization);
        Ok(Box::new(Http01Ready {
            server: self.server.clone(),
            token,
        }))
    }
}

struct Http01Ready {
    server: Arc<Http01Server>,
    token: String,
}

impl ChallengeReady for Http01Ready {
    fn self_check(&self) -> AcmeResult<()> {
        // The map is populated synchronously in `arm`; nothing to
        // verify externally.
        Ok(())
    }
}

impl Drop for Http01Ready {
    fn drop(&mut self) {
        self.server.remove(&self.token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_answers_registered_token() {
        let server = Http01Server::bind_on(("127.0.0.1", 0)).expect("bind");
        server.insert("tok-1", "tok-1.thumbprint");
        let addr = server.local_addr();

        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream
            .write_all(b"GET /.well-known/acme-challenge/tok-1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read");
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got {text}");
        assert!(text.contains("tok-1.thumbprint"), "got {text}");
    }

    #[test]
    fn server_returns_404_for_unknown_token() {
        let server = Http01Server::bind_on(("127.0.0.1", 0)).expect("bind");
        let addr = server.local_addr();
        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream
            .write_all(b"GET /.well-known/acme-challenge/nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read");
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 404"), "got {text}");
    }
}
