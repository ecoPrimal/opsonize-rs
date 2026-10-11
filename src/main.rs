//! Opsonize — immune tagging + visitor traces for primals.eco
//!
//! Replaces Python opsonize/svc.py (port 8095) + traces_svc.py (port 8096)
//! with a single Rust binary running both servers.
//!
//! No cookies. No identity tracking. IPs one-way hashed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

// ═══════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════

const DATA_DIR: &str = "/opt/ecoPrimals/opsonize";
const ACCESS_LOG: &str = "/var/log/caddy/access.log";
const OPSONIZE_PORT: u16 = 8095;
const TRACES_PORT: u16 = 8096;
const RATE_WINDOW_SECS: u64 = 3600;
const RATE_MAX: usize = 5;
const MAX_BODY: usize = 10_000;

// ═══════════════════════════════════════════════════════
// TAG TAXONOMY
// ═══════════════════════════════════════════════════════

fn valid_tags() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("witness", "I have direct knowledge of events described"),
        ("document", "I have documents that support or contradict this"),
        ("connection", "I know of additional connections not shown"),
        ("correction", "Something here needs correction"),
        ("confirmation", "I can confirm facts presented here"),
        ("threat", "I or someone I know faces ongoing harm"),
        ("pattern", "I see this pattern in another jurisdiction"),
        ("resource", "I can offer professional resources or assistance"),
    ])
}

// ═══════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
struct Signal {
    ts: String,
    epoch: f64,
    ip_hash: String,
    page: String,
    tag: String,
    body: String,
    contact: Option<String>,
    status: String,
}

#[derive(Deserialize)]
struct SubmitRequest {
    page: Option<String>,
    tag: Option<String>,
    body: Option<String>,
    contact: Option<String>,
}

#[derive(Default)]
struct RateLimiter {
    windows: HashMap<String, Vec<u64>>,
}

impl RateLimiter {
    fn check(&mut self, ip: &str) -> bool {
        let now = epoch_secs();
        let entry = self.windows.entry(ip.to_string()).or_default();
        entry.retain(|&t| now - t < RATE_WINDOW_SECS);
        if entry.len() >= RATE_MAX {
            return false;
        }
        entry.push(now);
        true
    }
}

type SharedState = Arc<Mutex<RateLimiter>>;

// ═══════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_ip(ip: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("opsn-{ip}-salt7f3a").as_bytes());
    let result = h.finalize();
    hex::encode(&result[..6])
}

fn sanitize(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

fn json_response(code: StatusCode, data: serde_json::Value, cors_origin: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&data).unwrap_or_default();
    Response::builder()
        .status(code)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", cors_origin)
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn signals_path() -> PathBuf { Path::new(DATA_DIR).join("signals.jsonl") }
fn approved_path() -> PathBuf { Path::new(DATA_DIR).join("approved.jsonl") }

// ═══════════════════════════════════════════════════════
// OPSONIZE HANDLER (port 8095)
// ═══════════════════════════════════════════════════════

async fn handle_opsonize(
    req: Request<Incoming>,
    state: SharedState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let cors = "https://tuebor.primals.eco";

    if req.method() == Method::OPTIONS {
        return Ok(json_response(StatusCode::NO_CONTENT, serde_json::json!({}), cors));
    }

    let path = req.uri().path();

    match (req.method(), path) {
        (&Method::POST, "/api/opsonize") => {
            let ip = req
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            {
                let mut limiter = state.lock().unwrap();
                if !limiter.check(&ip) {
                    return Ok(json_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        serde_json::json!({"error": "rate limited", "detail": "max 5 per hour"}),
                        cors,
                    ));
                }
            }

            let body_bytes = http_body_util::BodyExt::collect(req.into_body())
                .await?
                .to_bytes();
            if body_bytes.len() > MAX_BODY {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    serde_json::json!({"error": "too large"}),
                    cors,
                ));
            }

            let data: SubmitRequest = match serde_json::from_slice(&body_bytes) {
                Ok(d) => d,
                Err(_) => {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({"error": "invalid JSON"}),
                        cors,
                    ));
                }
            };

            let page = sanitize(data.page.as_deref().unwrap_or(""), 200);
            let tag = sanitize(data.tag.as_deref().unwrap_or(""), 50);
            let body_text = sanitize(data.body.as_deref().unwrap_or(""), 2000);
            let contact = data.contact.map(|c| sanitize(&c, 200));

            let tags = valid_tags();
            if page.is_empty() || tag.is_empty() || body_text.is_empty() {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "page, tag, and body required"}),
                    cors,
                ));
            }
            if !tags.contains_key(tag.as_str()) {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "invalid tag", "valid": tags.keys().collect::<Vec<_>>()}),
                    cors,
                ));
            }
            if body_text.len() < 10 {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "body too short (min 10 chars)"}),
                    cors,
                ));
            }

            let signal = Signal {
                ts: chrono::Utc::now().to_rfc3339(),
                epoch: epoch_secs() as f64,
                ip_hash: hash_ip(&ip),
                page,
                tag: tag.clone(),
                body: body_text,
                contact,
                status: "pending".into(),
            };

            std::fs::create_dir_all(DATA_DIR).ok();
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(signals_path())
            {
                let line = serde_json::to_string(&signal).unwrap_or_default();
                let _ = writeln!(f, "{line}");
            }

            let tag_meaning = tags.get(tag.as_str()).unwrap_or(&"");
            Ok(json_response(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "message": "Signal received. Your observation strengthens the network.",
                    "tag": tag,
                    "tag_meaning": tag_meaning,
                }),
                cors,
            ))
        }

        (&Method::GET, "/api/opsonize/feed") => {
            let mut signals = Vec::new();
            if let Ok(f) = std::fs::File::open(approved_path()) {
                for line in BufReader::new(f).lines().flatten() {
                    if let Ok(mut s) = serde_json::from_str::<serde_json::Value>(&line) {
                        s.as_object_mut().map(|o| { o.remove("ip_hash"); o.remove("contact"); });
                        signals.push(s);
                    }
                }
            }
            let total = signals.len();
            let recent: Vec<_> = signals.into_iter().rev().take(50).collect();
            Ok(json_response(StatusCode::OK, serde_json::json!({"signals": recent, "total": total}), cors))
        }

        (&Method::GET, "/api/opsonize/stats") => {
            let mut total = 0u64;
            let mut by_tag: HashMap<String, u64> = HashMap::new();
            let mut by_page: HashMap<String, u64> = HashMap::new();
            if let Ok(f) = std::fs::File::open(signals_path()) {
                for line in BufReader::new(f).lines().flatten() {
                    if let Ok(s) = serde_json::from_str::<serde_json::Value>(&line) {
                        total += 1;
                        if let Some(t) = s.get("tag").and_then(|v| v.as_str()) {
                            *by_tag.entry(t.to_string()).or_default() += 1;
                        }
                        if let Some(p) = s.get("page").and_then(|v| v.as_str()) {
                            *by_page.entry(p.to_string()).or_default() += 1;
                        }
                    }
                }
            }
            Ok(json_response(
                StatusCode::OK,
                serde_json::json!({"total_signals": total, "by_tag": by_tag, "by_page": by_page, "tags": valid_tags()}),
                cors,
            ))
        }

        (&Method::GET, "/api/opsonize/tags") => {
            Ok(json_response(StatusCode::OK, serde_json::json!({"tags": valid_tags()}), cors))
        }

        _ => Ok(json_response(StatusCode::NOT_FOUND, serde_json::json!({"error": "not found"}), cors)),
    }
}

// ═══════════════════════════════════════════════════════
// TRACES HANDLER (port 8096)
// ═══════════════════════════════════════════════════════

const WATCH_HOSTS: &[&str] = &[
    "tuebor.primals.eco",
    "barry.primals.eco",
    "detroit.primals.eco",
    "clutch.primals.eco",
];

const SKIP_EXTS: &[&str] = &[
    ".css", ".js", ".ico", ".png", ".jpg", ".woff", ".svg", ".xml", ".txt", ".wasm", ".env",
];

const BOT_MARKERS: &[&str] = &[
    "bot", "spider", "crawl", "curl", "python", "go-http", "scan", "archive.org",
];

fn build_traces(hours: u64) -> (Vec<serde_json::Value>, HashMap<String, u64>, usize) {
    let cutoff = epoch_secs().saturating_sub(hours * 3600);
    let mut by_session: HashMap<String, Vec<(u64, String)>> = HashMap::new();
    let mut heatmap: HashMap<String, u64> = HashMap::new();

    if let Ok(f) = std::fs::File::open(ACCESS_LOG) {
        for line in BufReader::new(f).lines().flatten() {
            let Ok(d) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let ts = d.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
            if ts < cutoff { continue; }

            let req = match d.get("request") { Some(r) => r, None => continue };
            let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("");
            if !WATCH_HOSTS.contains(&host) { continue; }

            let uri = req.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            if SKIP_EXTS.iter().any(|ext| uri.ends_with(ext)) { continue; }
            if uri.contains("/ws") || uri.contains("/api/") { continue; }

            let ip = req.get("client_ip").and_then(|v| v.as_str()).unwrap_or("");
            let ua = req
                .get("headers")
                .and_then(|h| h.get("User-Agent"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if ua.is_empty() { continue; }
            let ua_lower = ua.to_lowercase();
            if BOT_MARKERS.iter().any(|b| ua_lower.contains(b)) { continue; }

            let session_id = {
                let mut h = Sha256::new();
                h.update(format!("trace-{ip}-{}", &ua[..ua.len().min(20)]).as_bytes());
                let r = h.finalize();
                hex::encode(&r[..4])
            };

            let site = host.replace(".primals.eco", "");
            let page = format!("{site}{uri}");

            *heatmap.entry(page.clone()).or_default() += 1;
            by_session.entry(session_id).or_default().push((ts, page));
        }
    }

    let mut traces = Vec::new();
    let total_sessions = by_session.len();

    for (sid, mut hits) in by_session {
        hits.sort_by_key(|h| h.0);
        let mut deduped = vec![hits[0].clone()];
        for h in &hits[1..] {
            if h.1 != deduped.last().unwrap().1 {
                deduped.push(h.clone());
            }
        }
        if deduped.len() >= 2 {
            let duration = deduped.last().unwrap().0 - deduped[0].0;
            traces.push(serde_json::json!({
                "id": sid,
                "pages": deduped.iter().map(|h| &h.1).collect::<Vec<_>>(),
                "start": deduped[0].0,
                "end": deduped.last().unwrap().0,
                "duration": duration,
                "depth": deduped.len(),
            }));
        }
    }
    traces.sort_by(|a, b| {
        b.get("end").and_then(|v| v.as_u64()).cmp(&a.get("end").and_then(|v| v.as_u64()))
    });

    // Sort heatmap by count, keep top 50
    let mut heatmap_sorted: Vec<_> = heatmap.into_iter().collect();
    heatmap_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    heatmap_sorted.truncate(50);
    let heatmap: HashMap<String, u64> = heatmap_sorted.into_iter().collect();

    (traces, heatmap, total_sessions)
}

async fn handle_traces(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == &Method::OPTIONS {
        return Ok(Response::builder()
            .status(204)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, OPTIONS")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if req.uri().path() != "/api/traces" {
        return Ok(json_response(StatusCode::NOT_FOUND, serde_json::json!({"error": "not found"}), "*"));
    }

    let (traces, heatmap, total) = tokio::task::spawn_blocking(|| build_traces(2))
        .await
        .unwrap_or_default();

    let data = serde_json::json!({
        "traces": &traces[..traces.len().min(20)],
        "heatmap": heatmap,
        "total_sessions": total,
        "ts": epoch_secs(),
    });

    let body = serde_json::to_vec(&data).unwrap_or_default();
    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Cache-Control", "public, max-age=30")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

// ═══════════════════════════════════════════════════════
// SALESMAN WATCH — log tail for human arrivals
// Replaces Python salesman_watch.py
// ═══════════════════════════════════════════════════════

const SALESMAN_HOSTS: &[&str] = &["tuebor.primals.eco", "barry.primals.eco"];

const PRIORITY_URIS: &[&str] = &[
    "/analysis/they-banked-on-banks/",
    "/analysis/tommy-boy/",
    "/analysis/hey-mikey/",
    "/analysis/enforcement-ecosystem/",
];

const SALESMAN_BOT_SIGS: &[&str] = &[
    "bot", "crawler", "spider", "scraper", "curl", "wget", "python-requests",
    "httpx", "go-http", "java/", "googlebot", "bingbot", "yandexbot",
    "facebookexternalhit", "twitterbot", "linkedinbot", "slackbot",
    "claudebot", "chatgpt", "gptbot", "applebot", "bytespider",
    "ahrefsbot", "semrushbot", "dotbot", "mj12bot", "petalbot",
    "dataforseobot", "barkrowler", "seokicks", "blexbot",
];

fn classify_visitor(ua: &str) -> &'static str {
    let ua_lower = ua.to_lowercase();
    if SALESMAN_BOT_SIGS.iter().any(|s| ua_lower.contains(s)) { return "BOT"; }
    if ua.is_empty() || ua == "-" { return "EMPTY"; }
    if ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone") { return "HUMAN-MOBILE"; }
    if ua.contains("Mozilla") && (ua.contains("Chrome") || ua.contains("Firefox") || ua.contains("Safari")) {
        return "HUMAN-DESKTOP";
    }
    "UNKNOWN"
}

async fn salesman_watch() {
    use tokio::io::{AsyncBufReadExt, BufReader as TokioBufReader};
    use tokio::fs::File;

    eprintln!("[salesman] watching {} for human arrivals", ACCESS_LOG);

    // Seek to end and tail
    loop {
        let file = match File::open(ACCESS_LOG).await {
            Ok(f) => f,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Get file size to seek to end
        let metadata = file.metadata().await.unwrap_or_else(|_| unreachable!());
        let file_len = metadata.len();

        let file = match File::open(ACCESS_LOG).await {
            Ok(f) => f,
            Err(_) => continue,
        };

        let mut reader = TokioBufReader::new(file);

        // Skip to near end of file (last 64KB for baseline context)
        let skip_to = file_len.saturating_sub(65536);
        if skip_to > 0 {
            tokio::io::AsyncSeekExt::seek(&mut reader, std::io::SeekFrom::Start(skip_to)).await.ok();
            // Discard partial line
            let mut discard = String::new();
            let _ = reader.read_line(&mut discard).await;
        }

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF — wait for more data
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Ok(_) => {
                    let Ok(d) = serde_json::from_str::<serde_json::Value>(line.trim()) else { continue };
                    let Some(req) = d.get("request") else { continue };
                    let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("");
                    if !SALESMAN_HOSTS.contains(&host) { continue; }

                    let uri = req.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                    if SKIP_EXTS.iter().any(|ext| uri.ends_with(ext)) { continue; }

                    let ua = req.get("headers")
                        .and_then(|h| h.get("User-Agent"))
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let kind = classify_visitor(ua);

                    // Only log human arrivals and priority page hits
                    let is_priority = PRIORITY_URIS.iter().any(|p| uri.contains(p))
                        || uri.to_lowercase().contains("they-banked")
                        || uri.to_lowercase().contains("brian");

                    if kind.starts_with("HUMAN") {
                        let ts = d.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
                            .unwrap_or_default();
                        let time_str = dt.format("%H:%M:%S").to_string();
                        let ip = req.get("client_ip").and_then(|v| v.as_str()).unwrap_or("?");

                        if is_priority {
                            eprintln!("[salesman] PRIORITY {time_str} | {kind} | {ip} | {host}{}", &uri[..uri.len().min(60)]);
                        } else {
                            eprintln!("[salesman] {time_str} | {kind} | {ip} | {host}{}", &uri[..uri.len().min(60)]);
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    break; // Re-open file
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════
// MAIN — run all three services
// ═══════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    std::fs::create_dir_all(DATA_DIR).ok();

    let state: SharedState = Arc::new(Mutex::new(RateLimiter::default()));

    let opsonize_addr: SocketAddr = ([127, 0, 0, 1], OPSONIZE_PORT).into();
    let traces_addr: SocketAddr = ([127, 0, 0, 1], TRACES_PORT).into();

    let opsonize_listener = TcpListener::bind(opsonize_addr).await.expect("bind opsonize");
    let traces_listener = TcpListener::bind(traces_addr).await.expect("bind traces");

    eprintln!("[opsonize] listening on {opsonize_addr}");
    eprintln!("[traces]   listening on {traces_addr}");

    let opsonize_state = state.clone();
    let opsonize_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = opsonize_listener.accept().await else { continue };
            let io = TokioIo::new(stream);
            let st = opsonize_state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    handle_opsonize(req, st.clone())
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    let traces_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = traces_listener.accept().await else { continue };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(handle_traces);
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    let salesman_task = tokio::spawn(salesman_watch());

    tokio::select! {
        _ = opsonize_task => {}
        _ = traces_task => {}
        _ = salesman_task => {}
    }
}

// hex encoding helper (avoids adding another dep)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
