// SPDX-License-Identifier: MPL-2.0

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use thiserror::Error;

const MAX_BOOTSTRAP_REQUEST: usize = 128;

pub struct AgentServer {
    listener: TcpListener,
}

impl AgentServer {
    pub fn bind(address: SocketAddr) -> Result<Self, AgentError> {
        if !address.ip().is_loopback() {
            return Err(AgentError::NonLoopbackBinding(address));
        }
        Ok(Self {
            listener: TcpListener::bind(address)?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, AgentError> {
        Ok(self.listener.local_addr()?)
    }

    pub fn serve_once(&self) -> Result<(), AgentError> {
        let (stream, peer) = self.listener.accept()?;
        if !peer.ip().is_loopback() {
            return Err(AgentError::NonLoopbackPeer(peer));
        }
        handle_bootstrap_connection(stream)
    }

    pub fn serve_forever(&self) -> Result<(), AgentError> {
        loop {
            self.serve_once()?;
        }
    }
}

fn handle_bootstrap_connection(mut stream: TcpStream) -> Result<(), AgentError> {
    let mut buffer = [0u8; MAX_BOOTSTRAP_REQUEST];
    let read = stream.read(&mut buffer)?;
    let request = std::str::from_utf8(&buffer[..read]).map_err(|_| AgentError::InvalidUtf8)?;
    let command = request.trim();
    let response = match command {
        "PING" => format!("PONG vor-agent/{}\n", env!("CARGO_PKG_VERSION")),
        "INFO" => format!(
            "INFO {{\"version\":\"{}\",\"transport\":\"loopback-bootstrap\",\"remote_actions\":false}}\n",
            env!("CARGO_PKG_VERSION")
        ),
        _ => "ERR unsupported_bootstrap_command\n".to_owned(),
    };
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("vor-agent bootstrap listener may bind only to loopback: {0}")]
    NonLoopbackBinding(SocketAddr),
    #[error("vor-agent bootstrap listener rejected non-loopback peer: {0}")]
    NonLoopbackPeer(SocketAddr),
    #[error("bootstrap request is not UTF-8")]
    InvalidUtf8,
    #[error("agent I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;

    #[test]
    fn rejects_non_loopback_binding() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(matches!(
            AgentServer::bind(address),
            Err(AgentError::NonLoopbackBinding(_))
        ));
    }

    #[test]
    fn ping_roundtrip_is_loopback_only() {
        let server = AgentServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve_once().unwrap());
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"PING\n").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        handle.join().unwrap();
        assert!(response.starts_with("PONG vor-agent/"));
    }
}
