//! A client for the Chrome DevTools Protocol, over one WebSocket: send a
//! command and wait for its answer, and hand out the events that arrive
//! in between. One thing at a time, with no background task: the driver
//! asks, then listens.

use std::collections::VecDeque;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};

use super::ws::WebSocket;

/// Something the browser reported without being asked.
#[derive(Debug, Clone)]
pub struct Event {
    pub method: String,
    pub params: Value,
    /// The session it came from: the page, or a frame or worker of it.
    pub session: Option<String>,
}

pub struct Cdp<S> {
    ws: WebSocket<S>,
    next_id: u64,
    /// Events that arrived while an answer was awaited.
    waiting: VecDeque<Event>,
    /// How long a command may take.
    patience: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Cdp<S> {
    pub fn new(ws: WebSocket<S>) -> Self {
        Self {
            ws,
            next_id: 1,
            waiting: VecDeque::new(),
            patience: Duration::from_secs(15),
        }
    }

    /// Send a command, to the browser or to one session of it, and
    /// return its result. Events that arrive first are kept for
    /// [`Cdp::event`].
    pub async fn call(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        self.ws.send_text(&message.to_string()).await?;
        let answer = async {
            loop {
                let Some(text) = self.ws.next_text().await? else {
                    return Err(format!("the browser closed before answering {method}"));
                };
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                if value["id"].as_u64() == Some(id) {
                    if let Some(error) = value.get("error") {
                        let why = error["message"].as_str().unwrap_or("an error");
                        return Err(format!("{method}: {why}"));
                    }
                    return Ok(value["result"].clone());
                }
                if let Some(event) = as_event(value) {
                    self.waiting.push_back(event);
                }
            }
        };
        match tokio::time::timeout(self.patience, answer).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "the browser did not answer {method} in {} s",
                self.patience.as_secs()
            )),
        }
    }

    /// Send a command without waiting for its answer, which is then
    /// dropped when it comes. For a command whose answer waits on
    /// something this client must do first, such as a navigation whose
    /// first request is being held.
    pub async fn send(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<(), String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        self.ws.send_text(&message.to_string()).await
    }

    /// The next event, waiting at most `wait` for one. `Ok(None)` when
    /// none came in that time.
    pub async fn event(&mut self, wait: Duration) -> Result<Option<Event>, String> {
        if let Some(event) = self.waiting.pop_front() {
            return Ok(Some(event));
        }
        let next = async {
            loop {
                let Some(text) = self.ws.next_text().await? else {
                    return Err("the browser closed the connection".to_string());
                };
                if let Some(event) = serde_json::from_str(&text).ok().and_then(as_event) {
                    return Ok(event);
                }
            }
        };
        match tokio::time::timeout(wait, next).await {
            Ok(Ok(event)) => Ok(Some(event)),
            Ok(Err(why)) => Err(why),
            Err(_) => Ok(None),
        }
    }
}

fn as_event(value: Value) -> Option<Event> {
    let method = value.get("method")?.as_str()?.to_string();
    Some(Event {
        method,
        params: value.get("params").cloned().unwrap_or(Value::Null),
        session: value
            .get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::super::ws::testing::*;
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn answers_are_matched_and_events_are_kept() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            accept(&mut server).await;
            let (_, asked) = read_frame(&mut server).await;
            let asked: Value = serde_json::from_str(&asked).unwrap();
            assert_eq!(asked["method"], "Page.navigate");
            assert_eq!(asked["sessionId"], "S1");
            assert_eq!(asked["params"]["url"], "https://example.org/");
            // An event first, then the answer, then another event.
            let send = |v: Value| frame(true, 1, v.to_string().as_bytes());
            server
                .write_all(&send(
                    json!({"method": "Network.requestWillBeSent", "params": {"requestId": "1"}}),
                ))
                .await
                .unwrap();
            server
                .write_all(&send(
                    json!({"id": asked["id"], "result": {"frameId": "F"}}),
                ))
                .await
                .unwrap();
            server
                .write_all(&send(
                    json!({"method": "Page.loadEventFired", "params": {}, "sessionId": "S1"}),
                ))
                .await
                .unwrap();
            // A command that fails.
            let (_, asked) = read_frame(&mut server).await;
            let asked: Value = serde_json::from_str(&asked).unwrap();
            server
                .write_all(&send(
                    json!({"id": asked["id"], "error": {"message": "no such method"}}),
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let ws = WebSocket::connect(client, "127.0.0.1", "/").await.unwrap();
        let mut cdp = Cdp::new(ws);
        let result = cdp
            .call(
                "Page.navigate",
                json!({"url": "https://example.org/"}),
                Some("S1"),
            )
            .await
            .unwrap();
        assert_eq!(result["frameId"], "F");
        let first = cdp.event(Duration::from_secs(1)).await.unwrap().unwrap();
        assert_eq!(first.method, "Network.requestWillBeSent");
        assert_eq!(first.params["requestId"], "1");
        let second = cdp.event(Duration::from_secs(1)).await.unwrap().unwrap();
        assert_eq!(second.method, "Page.loadEventFired");
        assert_eq!(second.session.as_deref(), Some("S1"));
        assert_eq!(first.session, None);
        let err = cdp.call("No.such", json!({}), None).await.unwrap_err();
        assert_eq!(err, "No.such: no such method");
        // Nothing more comes: a timeout, not an error.
        assert!(
            cdp.event(Duration::from_millis(50))
                .await
                .unwrap()
                .is_none()
        );
    }
}
