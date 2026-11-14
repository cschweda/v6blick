//! A WebSocket client, as much of one as talking to Chrome's DevTools
//! port needs: the opening handshake, text messages in both directions,
//! and the control frames. Written here so that the page test adds no
//! dependency; it speaks only to a browser v6blick started itself, on
//! the loopback address.

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The fixed text every WebSocket handshake is hashed with (RFC 6455).
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The head of the handshake reply may be at most this large.
const MAX_HEAD: usize = 16 * 1024;
/// One message may be at most this large. A page's network events are
/// small; this is a bound, not an expectation.
pub const MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// Standard base64, with padding.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What the server must answer for a handshake key.
pub fn accept_for(key: &str) -> String {
    let hashed = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{GUID}").as_bytes(),
    );
    base64(hashed.as_ref())
}

/// One frame as it was read.
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

pub struct WebSocket<S> {
    stream: S,
    /// Bytes read and not yet used. Reading goes through this buffer, so
    /// that a read given up at a timeout loses nothing.
    buf: Vec<u8>,
    /// The parts of a message that is still arriving.
    partial: Vec<u8>,
    random: SystemRandom,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {
    /// Open a WebSocket on a connected stream.
    pub async fn connect(mut stream: S, host: &str, path: &str) -> Result<Self, String> {
        let random = SystemRandom::new();
        let mut nonce = [0u8; 16];
        random
            .fill(&mut nonce)
            .map_err(|_| "no random numbers are available".to_string())?;
        let key = base64(&nonce);
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            if buf.len() > MAX_HEAD {
                return Err("the handshake reply is too large".to_string());
            }
            let mut chunk = [0u8; 2048];
            match stream.read(&mut chunk).await {
                Ok(0) => return Err("the connection closed during the handshake".to_string()),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e.to_string()),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or_default();
        if !status.starts_with("HTTP/1.1 101") {
            return Err(format!("the handshake was answered with '{status}'"));
        }
        let accepted = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("sec-websocket-accept"))
            .map(|(_, value)| value.trim().to_string());
        if accepted.as_deref() != Some(accept_for(&key).as_str()) {
            return Err("the handshake reply does not match the request".to_string());
        }
        buf.drain(..end);
        Ok(Self {
            stream,
            buf,
            partial: Vec::new(),
            random,
        })
    }

    /// Send one text message. A client's frames are masked.
    pub async fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.send_frame(0x1, text.as_bytes()).await
    }

    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut mask = [0u8; 4];
        self.random
            .fill(&mut mask)
            .map_err(|_| "no random numbers are available".to_string())?;
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode);
        match payload.len() {
            n if n < 126 => frame.push(0x80 | n as u8),
            n if n <= usize::from(u16::MAX) => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| e.to_string())
    }

    /// Take one whole frame out of the buffer, if one is there.
    fn take_frame(&mut self) -> Result<Option<Frame>, String> {
        let buf = &self.buf;
        if buf.len() < 2 {
            return Ok(None);
        }
        let (fin, opcode) = (buf[0] & 0x80 != 0, buf[0] & 0x0f);
        if buf[0] & 0x70 != 0 {
            return Err("a frame uses an extension that was not agreed".to_string());
        }
        let masked = buf[1] & 0x80 != 0;
        let (len, mut at) = match buf[1] & 0x7f {
            126 => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
            }
            127 => {
                if buf.len() < 10 {
                    return Ok(None);
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&buf[2..10]);
                (u64::from_be_bytes(bytes), 10)
            }
            n => (u64::from(n), 2),
        };
        if len > MAX_MESSAGE as u64 {
            return Err("a frame is too large".to_string());
        }
        let len = len as usize;
        let mask = if masked {
            if buf.len() < at + 4 {
                return Ok(None);
            }
            at += 4;
            Some([buf[at - 4], buf[at - 3], buf[at - 2], buf[at - 1]])
        } else {
            None
        };
        if buf.len() < at + len {
            return Ok(None);
        }
        let mut payload = buf[at..at + len].to_vec();
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        self.buf.drain(..at + len);
        Ok(Some(Frame {
            fin,
            opcode,
            payload,
        }))
    }

    /// The next text message. `None` when the other side closed. Safe to
    /// give up at a timeout and call again.
    pub async fn next_text(&mut self) -> Result<Option<String>, String> {
        loop {
            while let Some(frame) = self.take_frame()? {
                match frame.opcode {
                    // Text, binary, or the continuation of either.
                    0x0..=0x2 => {
                        if self.partial.len() + frame.payload.len() > MAX_MESSAGE {
                            return Err("a message is too large".to_string());
                        }
                        self.partial.extend_from_slice(&frame.payload);
                        if frame.fin {
                            let whole = std::mem::take(&mut self.partial);
                            return Ok(Some(String::from_utf8_lossy(&whole).into_owned()));
                        }
                    }
                    0x8 => return Ok(None),
                    0x9 => self.send_frame(0xA, &frame.payload).await?,
                    0xA => {}
                    other => return Err(format!("a frame has the unknown type {other}")),
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.stream.read(&mut chunk).await {
                Ok(0) => return Ok(None),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! The server's side of the protocol, for tests.
    use super::*;

    /// Read the client's handshake and answer it.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
        let mut buf = Vec::new();
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the client closed during the handshake");
            buf.extend_from_slice(&chunk[..n]);
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let key = head
            .split("\r\n")
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .to_string();
        let reply = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(&key)
        );
        stream.write_all(reply.as_bytes()).await.unwrap();
    }

    /// One unmasked frame, as a server sends it.
    pub fn frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
        match payload.len() {
            n if n < 126 => out.push(n as u8),
            n if n <= usize::from(u16::MAX) => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    /// Read one masked frame from a client and return its type and text.
    pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, String) {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.unwrap();
        assert!(head[1] & 0x80 != 0, "a client's frame must be masked");
        let len = match head[1] & 0x7f {
            126 => {
                let mut b = [0u8; 2];
                stream.read_exact(&mut b).await.unwrap();
                usize::from(u16::from_be_bytes(b))
            }
            127 => {
                let mut b = [0u8; 8];
                stream.read_exact(&mut b).await.unwrap();
                u64::from_be_bytes(b) as usize
            }
            n => usize::from(n),
        };
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask).await.unwrap();
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        (head[0] & 0x0f, String::from_utf8(payload).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn base64_and_the_handshake_answer_match_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // The example in RFC 6455, section 1.3.
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn messages_go_both_ways() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn(async move {
            accept(&mut server).await;
            let (opcode, text) = read_frame(&mut server).await;
            assert_eq!((opcode, text.as_str()), (1, "hello"));
            // A long message, to use the 16-bit length.
            let (_, long) = read_frame(&mut server).await;
            assert_eq!(long.len(), 70_000);
            server.write_all(&frame(true, 1, b"one")).await.unwrap();
            // A message in three parts, with a ping in the middle.
            server.write_all(&frame(false, 1, b"tw")).await.unwrap();
            server
                .write_all(&frame(true, 9, b"are you there"))
                .await
                .unwrap();
            server.write_all(&frame(false, 0, b"o ")).await.unwrap();
            server.write_all(&frame(true, 0, b"three")).await.unwrap();
            let (opcode, text) = read_frame(&mut server).await;
            assert_eq!((opcode, text.as_str()), (0xA, "are you there"));
            server
                .write_all(&frame(true, 1, &vec![b'x'; 200_000]))
                .await
                .unwrap();
            server.write_all(&frame(true, 8, b"")).await.unwrap();
        });
        let mut ws = WebSocket::connect(client, "127.0.0.1", "/devtools")
            .await
            .unwrap();
        ws.send_text("hello").await.unwrap();
        ws.send_text(&"y".repeat(70_000)).await.unwrap();
        assert_eq!(ws.next_text().await.unwrap().as_deref(), Some("one"));
        assert_eq!(ws.next_text().await.unwrap().as_deref(), Some("two three"));
        assert_eq!(ws.next_text().await.unwrap().unwrap().len(), 200_000);
        assert_eq!(ws.next_text().await.unwrap(), None);
        serving.await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_handshake_answer_is_refused() {
        for reply in [
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ] {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = server.read(&mut buf).await;
                let _ = server.write_all(reply.as_bytes()).await;
            });
            assert!(
                WebSocket::connect(client, "x", "/").await.is_err(),
                "{reply}"
            );
        }
    }

    #[tokio::test]
    async fn a_frame_that_is_too_large_is_an_error_not_an_allocation() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            accept(&mut server).await;
            // A length of 2^62 bytes, and nothing after it.
            let mut head = vec![0x81, 127];
            head.extend_from_slice(&(1u64 << 62).to_be_bytes());
            server.write_all(&head).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let mut ws = WebSocket::connect(client, "x", "/").await.unwrap();
        assert!(ws.next_text().await.is_err());
    }

    #[tokio::test]
    async fn a_read_given_up_at_a_timeout_loses_nothing() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            accept(&mut server).await;
            let whole = frame(true, 1, b"in two halves");
            server.write_all(&whole[..5]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            server.write_all(&whole[5..]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let mut ws = WebSocket::connect(client, "x", "/").await.unwrap();
        let short = std::time::Duration::from_millis(50);
        assert!(tokio::time::timeout(short, ws.next_text()).await.is_err());
        assert_eq!(
            ws.next_text().await.unwrap().as_deref(),
            Some("in two halves")
        );
    }
}
