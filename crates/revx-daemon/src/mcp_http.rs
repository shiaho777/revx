use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{handle_mcp_jsonrpc, CapabilityService};

#[derive(Clone)]
struct HttpState {
    service: CapabilityService,
    token: Option<String>,
    sessions: Arc<Mutex<HashMap<String, ()>>>,
}

pub async fn serve_mcp_http(
    workspace_root: std::path::PathBuf,
    bind: SocketAddr,
    token: Option<String>,
) -> Result<()> {
    let _ = revx_analysis::resource::ensure_process_resource_limits();
    let state = HttpState {
        service: CapabilityService::new(workspace_root),
        token,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    eprintln!("revx mcp http listening on http://{bind}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                eprintln!("mcp http {peer}: {err:#}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, state: HttpState) -> Result<()> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 1024 * 1024 {
            write_response(&mut stream, 413, "text/plain", b"payload too large", None).await?;
            return Ok(());
        }
    }

    let header_bytes = &buf[..header_end];
    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let path_q = parts.next().unwrap_or("/");
    let (path, query) = split_path_query(path_q);

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > 16 * 1024 * 1024 {
        write_response(&mut stream, 413, "text/plain", b"payload too large", None).await?;
        return Ok(());
    }

    let body_already = buf.len().saturating_sub(header_end);
    let mut body = Vec::new();
    if body_already > 0 {
        body.extend_from_slice(&buf[header_end..]);
    }
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    if body.len() > content_length {
        body.truncate(content_length);
    }

    if method == "OPTIONS" {
        write_response(&mut stream, 204, "text/plain", b"", None).await?;
        return Ok(());
    }

    if !authorized(&state, &headers) {
        write_response(&mut stream, 401, "application/json", br#"{"error":"unauthorized"}"#, None)
            .await?;
        return Ok(());
    }

    let path_norm = normalize_mcp_path(path);
    match (method.as_str(), path_norm.as_str()) {
        ("GET", "/health") | ("GET", "/mcp/health") => {
            write_response(&mut stream, 200, "application/json", br#"{"ok":true,"server":"revx"}"#, None)
                .await?;
        }
        ("GET", "/sse") | ("GET", "/mcp/sse") => {
            handle_sse_open(&mut stream, &state).await?;
        }
        ("POST", "/message") | ("POST", "/mcp/message") => {
            let session = query_param(query, "sessionId").or_else(|| {
                headers
                    .get("mcp-session-id")
                    .cloned()
                    .filter(|s| !s.is_empty())
            });
            if session.is_none() {
                write_response(
                    &mut stream,
                    400,
                    "application/json",
                    br#"{"error":"missing sessionId"}"#,
                    None,
                )
                .await?;
                return Ok(());
            }
            handle_jsonrpc_post(&mut stream, &state, &body, session).await?;
        }
        ("POST", "/") | ("POST", "/mcp") | ("POST", "/mcp/") => {
            let session = headers
                .get("mcp-session-id")
                .cloned()
                .filter(|s| !s.is_empty());
            handle_jsonrpc_post(&mut stream, &state, &body, session).await?;
        }
        ("GET", "/") | ("GET", "/mcp") | ("GET", "/mcp/") => {
            let accept = headers.get("accept").map(|s| s.as_str()).unwrap_or("");
            if accept.contains("text/event-stream") {
                handle_sse_open(&mut stream, &state).await?;
            } else {
                write_response(
                    &mut stream,
                    200,
                    "application/json",
                    br#"{"ok":true,"server":"revx","transport":["streamable-http","sse"]}"#,
                    None,
                )
                .await?;
            }
        }
        _ => {
            write_response(&mut stream, 404, "application/json", br#"{"error":"not found"}"#, None)
                .await?;
        }
    }
    Ok(())
}

async fn handle_sse_open(stream: &mut TcpStream, state: &HttpState) -> Result<()> {
    let session_id = Uuid::new_v4().to_string();
    state.sessions.lock().await.insert(session_id.clone(), ());
    let endpoint = format!("/mcp/message?sessionId={session_id}");
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
Content-Type: text/event-stream\r\n\
Cache-Control: no-cache\r\n\
Connection: keep-alive\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Expose-Headers: Mcp-Session-Id\r\n\
Mcp-Session-Id: {session_id}\r\n\
\r\n"
    );
    stream.write_all(headers.as_bytes()).await?;
    let open = format!("event: endpoint\ndata: {endpoint}\n\n");
    stream.write_all(open.as_bytes()).await?;
    stream.flush().await?;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(25)).await;
        if stream.write_all(b": ping\n\n").await.is_err() {
            break;
        }
        if stream.flush().await.is_err() {
            break;
        }
    }
    state.sessions.lock().await.remove(&session_id);
    Ok(())
}

async fn handle_jsonrpc_post(
    stream: &mut TcpStream,
    state: &HttpState,
    body: &[u8],
    session: Option<String>,
) -> Result<()> {
    if body.is_empty() {
        write_response(
            stream,
            400,
            "application/json",
            br#"{"error":"empty body"}"#,
            session.as_deref(),
        )
        .await?;
        return Ok(());
    }

    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            let msg = format!(r#"{{"error":"invalid json: {err}"}}"#);
            write_response(
                stream,
                400,
                "application/json",
                msg.as_bytes(),
                session.as_deref(),
            )
            .await?;
            return Ok(());
        }
    };

    let session_id = match session {
        Some(s) => s,
        None => {
            let id = Uuid::new_v4().to_string();
            state.sessions.lock().await.insert(id.clone(), ());
            id
        }
    };

    if value.is_array() {
        let mut out = Vec::new();
        for item in value.as_array().cloned().unwrap_or_default() {
            if let Some(resp) = dispatch_one(state, item).await {
                out.push(resp);
            }
        }
        if out.is_empty() {
            write_response(stream, 202, "text/plain", b"", Some(&session_id)).await?;
        } else {
            let body = serde_json::to_vec(&serde_json::Value::Array(out))?;
            write_response(stream, 200, "application/json", &body, Some(&session_id)).await?;
        }
        return Ok(());
    }

    match dispatch_one(state, value).await {
        Some(resp) => {
            let body = serde_json::to_vec(&resp)?;
            write_response(stream, 200, "application/json", &body, Some(&session_id)).await?;
        }
        None => {
            write_response(stream, 202, "text/plain", b"", Some(&session_id)).await?;
        }
    }
    Ok(())
}

async fn dispatch_one(state: &HttpState, request: serde_json::Value) -> Option<serde_json::Value> {
    let service = state.service.clone();
    tokio::task::spawn_blocking(move || handle_mcp_jsonrpc(&service, request))
        .await
        .ok()
        .flatten()
}

fn authorized(state: &HttpState, headers: &HashMap<String, String>) -> bool {
    let Some(expected) = state.token.as_ref() else {
        return true;
    };
    if expected.is_empty() {
        return true;
    }
    if headers.get("x-revx-token").is_some_and(|v| v == expected) {
        return true;
    }
    if let Some(auth) = headers.get("authorization") {
        let bearer = format!("Bearer {expected}");
        if auth == &bearer || auth == expected {
            return true;
        }
    }
    false
}

fn normalize_mcp_path(path: &str) -> String {
    let p = path.split('?').next().unwrap_or(path);
    let p = if p.len() > 1 && p.ends_with('/') {
        p.trim_end_matches('/').to_string()
    } else {
        p.to_string()
    };
    if p.is_empty() {
        "/".to_string()
    } else {
        p
    }
}

fn split_path_query(path_q: &str) -> (&str, &str) {
    match path_q.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_q, ""),
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        if k == key {
            return Some(urlencoding_decode(v));
        }
    }
    None
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = String::from_utf8_lossy(&bytes[i + 1..i + 3]);
                if let Ok(v) = u8::from_str_radix(&h, 16) {
                    out.push(v as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    session: Option<&str>,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
Content-Type: {content_type}\r\n\
Content-Length: {}\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization, X-Revx-Token, Mcp-Session-Id, Accept\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Expose-Headers: Mcp-Session-Id\r\n\
Connection: close\r\n",
        body.len()
    );
    if let Some(session) = session {
        head.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}
