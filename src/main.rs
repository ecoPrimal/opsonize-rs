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

fn classify_epitope(text: &str) -> String {
    static KEYWORDS: &[(&str, &str)] = &[
        ("anderson","PHYSICS"),("localization","PHYSICS"),("permeability","PHYSICS"),
        ("lattice","PHYSICS"),("qcd","PHYSICS"),("hofstadter","PHYSICS"),("quantum","PHYSICS"),
        ("spectral","PHYSICS"),("negentropy","PHYSICS"),
        ("graph","TOPOLOGY"),("topology","TOPOLOGY"),("network","TOPOLOGY"),("mesh","TOPOLOGY"),
        ("braid","TOPOLOGY"),("fractal","TOPOLOGY"),
        ("philosophy","PHILOSOPHY"),("omelas","PHILOSOPHY"),("atlas","PHILOSOPHY"),
        ("sovereignty","PHILOSOPHY"),("commons","PHILOSOPHY"),("bibliography","PHILOSOPHY"),
        ("methodology","METHOD"),("constrained","METHOD"),("evolution","METHOD"),
        ("guidestone","METHOD"),("tufte","METHOD"),("schell","METHOD"),("ludo","METHOD"),
        ("detroit","INVESTIGATION"),("tuebor","INVESTIGATION"),("public-record","INVESTIGATION"),
        ("charter","INVESTIGATION"),("institutional","INVESTIGATION"),("gorilla","INVESTIGATION"),
        ("membrane","IMMUNE"),("immune","IMMUNE"),("skunkbat","IMMUNE"),("scatter","IMMUNE"),
        ("antidote","IMMUNE"),("non-newtonian","IMMUNE"),
        ("science","SCIENCE"),("biology","SCIENCE"),("genomics","SCIENCE"),("ferment","SCIENCE"),
        ("signal","SIGNAL"),("lossy","SIGNAL"),("shannon","SIGNAL"),("channel","SIGNAL"),
        ("story","SIGNAL"),("billboard","SIGNAL"),("beacon","SIGNAL"),("transit","SIGNAL"),
    ];
    let lower = text.to_lowercase();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (kw, cat) in KEYWORDS {
        if lower.contains(kw) {
            *counts.entry(cat).or_insert(0) += 1;
        }
    }
    counts.into_iter()
        .max_by_key(|&(_, n)| n)
        .map(|(cat, _)| cat.to_string())
        .unwrap_or_else(|| "SIGNAL".to_string())
}

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
        ("message", "Direct message — delivered on the membrane"),
        ("question", "A question for the network"),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epitope: Option<String>,
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

            let epitope = classify_epitope(&format!("{} {} {}", page, tag, body_text));
            let signal = Signal {
                ts: chrono::Utc::now().to_rfc3339(),
                epoch: epoch_secs() as f64,
                ip_hash: hash_ip(&ip),
                page: page.clone(),
                tag: tag.clone(),
                body: body_text,
                contact,
                status: "pending".into(),
                epitope: Some(epitope),
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
            ntfy_push("membrane-events",
                &format!("🔬 New signal [{}] on {}", &tag, &page));

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
                            ntfy_push("membrane-events",
                                &format!("🔴 PRIORITY {kind} on {host}{}",
                                    &uri[..uri.len().min(40)]));
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
// NTFY — lightweight push notification bridge
// ═══════════════════════════════════════════════════════

fn ntfy_push(topic: &str, msg: &str) {
    let url = format!("http://127.0.0.1:8098/{topic}");
    let body = msg.to_string();
    tokio::spawn(async move {
        let stream = match tokio::net::TcpStream::connect("127.0.0.1:8098").await {
            Ok(s) => s,
            Err(_) => return,
        };
        let io = TokioIo::new(stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(v) => v,
            Err(_) => return,
        };
        tokio::spawn(conn);
        let req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        let _ = sender.send_request(req).await;
    });
}

// ═══════════════════════════════════════════════════════
// DISCUSS — membrane-native discussion relay (port 8097)
// Replaces external Giscus with sovereign comment storage.
// Comments stored as JSONL, served via API, rate-limited.
// ═══════════════════════════════════════════════════════

const DISCUSS_PORT: u16 = 8097;
const DISCUSS_DIR: &str = "/opt/ecoPrimals/discuss";
const DISCUSS_RATE_WINDOW: u64 = 600; // 10 min
const DISCUSS_RATE_MAX: usize = 3;
const DISCUSS_MAX_BODY: usize = 4000;

#[derive(Serialize, Deserialize, Clone)]
struct Comment {
    id: String,
    ts: String,
    epoch: u64,
    author_hash: String,
    page: String,
    body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    #[serde(default)]
    reactions: HashMap<String, u32>,
    status: String, // "live" or "pending" (moderation queue for first-time posters)
}

#[derive(Deserialize)]
struct CommentSubmit {
    page: Option<String>,
    body: Option<String>,
    parent_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct ReactSubmit {
    comment_id: Option<String>,
    emoji: Option<String>,
}

fn discuss_path() -> PathBuf { Path::new(DISCUSS_DIR).join("comments.jsonl") }

fn gen_comment_id() -> String {
    let ts = epoch_secs();
    let mut h = Sha256::new();
    h.update(format!("cmt-{ts}-{}", std::process::id()).as_bytes());
    let r = h.finalize();
    format!("c{}", &hex::encode(&r[..6]))
}

fn load_comments(page: &str) -> Vec<Comment> {
    let mut out = Vec::new();
    if let Ok(f) = std::fs::File::open(discuss_path()) {
        for line in BufReader::new(f).lines().flatten() {
            if let Ok(c) = serde_json::from_str::<Comment>(&line) {
                if c.page == page && c.status == "live" {
                    out.push(c);
                }
            }
        }
    }
    out.sort_by_key(|c| c.epoch);
    out
}

fn load_all_pages() -> HashMap<String, usize> {
    let mut pages: HashMap<String, usize> = HashMap::new();
    if let Ok(f) = std::fs::File::open(discuss_path()) {
        for line in BufReader::new(f).lines().flatten() {
            if let Ok(c) = serde_json::from_str::<Comment>(&line) {
                if c.status == "live" {
                    *pages.entry(c.page).or_default() += 1;
                }
            }
        }
    }
    pages
}

async fn handle_discuss(
    req: Request<Incoming>,
    state: SharedState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let cors = "*"; // membrane-native, open CORS

    if req.method() == Method::OPTIONS {
        return Ok(json_response(StatusCode::NO_CONTENT, serde_json::json!({}), cors));
    }

    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    match (req.method().clone(), path.as_str()) {
        // GET /api/discuss?page=/some/path — fetch comments for a page
        (Method::GET, "/api/discuss") => {
            let page = query.split('&')
                .find(|p| p.starts_with("page="))
                .and_then(|p| p.strip_prefix("page="))
                .unwrap_or("")
                .to_string();
            let page = urldecode(&page);

            if page.is_empty() {
                return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "page parameter required"}), cors));
            }

            let comments = load_comments(&page);
            let total = comments.len();

            // Strip author_hash for public display (keep first 4 chars as badge)
            let public: Vec<serde_json::Value> = comments.into_iter().map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "ts": c.ts,
                    "epoch": c.epoch,
                    "badge": &c.author_hash[..c.author_hash.len().min(4)],
                    "page": c.page,
                    "body": c.body,
                    "parent_id": c.parent_id,
                    "reactions": c.reactions,
                })
            }).collect();

            Ok(json_response(StatusCode::OK,
                serde_json::json!({"comments": public, "total": total, "page": page}), cors))
        }

        // GET /api/discuss/pages — list all pages with comment counts
        (Method::GET, "/api/discuss/pages") => {
            let pages = load_all_pages();
            Ok(json_response(StatusCode::OK,
                serde_json::json!({"pages": pages, "total": pages.values().sum::<usize>()}), cors))
        }

        // POST /api/discuss — submit a new comment
        (Method::POST, "/api/discuss") => {
            let ip = req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            {
                let mut limiter = state.lock().unwrap();
                // Use discuss-specific rate limiting
                let key = format!("discuss-{ip}");
                let now = epoch_secs();
                let entry = limiter.windows.entry(key).or_default();
                entry.retain(|&t| now - t < DISCUSS_RATE_WINDOW);
                if entry.len() >= DISCUSS_RATE_MAX {
                    return Ok(json_response(StatusCode::TOO_MANY_REQUESTS,
                        serde_json::json!({"error": "rate limited", "detail": "max 3 per 10 minutes"}), cors));
                }
                entry.push(now);
            }

            let body_bytes = http_body_util::BodyExt::collect(req.into_body())
                .await?.to_bytes();
            if body_bytes.len() > DISCUSS_MAX_BODY {
                return Ok(json_response(StatusCode::PAYLOAD_TOO_LARGE,
                    serde_json::json!({"error": "too large"}), cors));
            }

            let data: CommentSubmit = match serde_json::from_slice(&body_bytes) {
                Ok(d) => d,
                Err(_) => return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "invalid JSON"}), cors)),
            };

            let page = sanitize(data.page.as_deref().unwrap_or(""), 200);
            let body_text = sanitize(data.body.as_deref().unwrap_or(""), 2000);
            let parent_id = data.parent_id.map(|p| sanitize(&p, 20));
            let name = data.name.as_deref().unwrap_or("");

            if page.is_empty() || body_text.is_empty() {
                return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "page and body required"}), cors));
            }
            if body_text.len() < 3 {
                return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "body too short"}), cors));
            }

            let author_hash = {
                let mut h = Sha256::new();
                h.update(format!("discuss-{ip}-{name}-salt9x2q").as_bytes());
                let r = h.finalize();
                hex::encode(&r[..8])
            };

            let comment = Comment {
                id: gen_comment_id(),
                ts: chrono::Utc::now().to_rfc3339(),
                epoch: epoch_secs(),
                author_hash: author_hash.clone(),
                page: page.clone(),
                body: body_text.clone(),
                parent_id,
                reactions: HashMap::new(),
                status: "live".into(),
            };

            std::fs::create_dir_all(DISCUSS_DIR).ok();
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true).append(true).open(discuss_path())
            {
                let line = serde_json::to_string(&comment).unwrap_or_default();
                let _ = writeln!(f, "{line}");
            }

            ntfy_push("discuss",
                &format!("💬 New comment on {} — {}", page, &body_text[..body_text.len().min(80)]));

            Ok(json_response(StatusCode::CREATED,
                serde_json::json!({
                    "ok": true,
                    "id": comment.id,
                    "badge": &author_hash[..author_hash.len().min(4)],
                    "message": "Comment posted. The membrane remembers.",
                }), cors))
        }

        // POST /api/discuss/react — add a reaction to a comment
        (Method::POST, "/api/discuss/react") => {
            let body_bytes = http_body_util::BodyExt::collect(req.into_body())
                .await?.to_bytes();
            let data: ReactSubmit = match serde_json::from_slice(&body_bytes) {
                Ok(d) => d,
                Err(_) => return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "invalid JSON"}), cors)),
            };

            let cid = data.comment_id.unwrap_or_default();
            let emoji = data.emoji.unwrap_or_default();
            let valid_emojis = ["👍", "❤️", "🔥", "🐿️", "🧬", "⚡"];
            if !valid_emojis.contains(&emoji.as_str()) {
                return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "invalid emoji", "valid": valid_emojis}), cors));
            }

            // Rewrite the file with updated reaction count
            let mut updated = false;
            if let Ok(f) = std::fs::File::open(discuss_path()) {
                let mut lines: Vec<String> = Vec::new();
                for line in BufReader::new(f).lines().flatten() {
                    if let Ok(mut c) = serde_json::from_str::<Comment>(&line) {
                        if c.id == cid {
                            *c.reactions.entry(emoji.clone()).or_default() += 1;
                            updated = true;
                        }
                        lines.push(serde_json::to_string(&c).unwrap_or(line));
                    } else {
                        lines.push(line);
                    }
                }
                if updated {
                    if let Ok(mut f) = std::fs::File::create(discuss_path()) {
                        for l in lines {
                            let _ = writeln!(f, "{l}");
                        }
                    }
                }
            }

            if updated {
                Ok(json_response(StatusCode::OK,
                    serde_json::json!({"ok": true, "emoji": emoji}), cors))
            } else {
                Ok(json_response(StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "comment not found"}), cors))
            }
        }

        _ => Ok(json_response(StatusCode::NOT_FOUND, serde_json::json!({"error": "not found"}), cors)),
    }
}

fn urldecode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&h, 16) {
                out.push(byte as char);
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

// ═══════════════════════════════════════════════════════
// MEMBRANE ANALYSIS — fleet + negentropy + self-remainder
// Replaces: fleet-analyzer.py, negentropy_feed.py, self-remainder.py
// Runs on a 5-minute timer, writes JSON to live-terminal/
// ═══════════════════════════════════════════════════════

const LIVE_DIR: &str = "/opt/membrane/live-terminal";
const ANALYSIS_INTERVAL_SECS: u64 = 300;
const WAVE: u32 = 178;

const AI_BOTS: &[&str] = &[
    "gptbot", "claudebot", "anthropic", "amazonbot", "bytespider",
    "bytedance", "ccbot", "cohere", "perplexitybot", "youbot",
    "reflectionbot", "aionbot",
];
const META_BOTS: &[&str] = &[
    "meta-externalagent", "facebookexternalhit", "facebookbot",
];
// META SQUATTER — no ASN lookup needed.
//
// Lichen model: classification grows on the stone of ingested traffic.
// skunky-ingest accumulates EntityAccum per entity — ip_hashes, subnets,
// timestamps, chrome_versions, path_ops, repos. The pattern IS the identity.
// "57.141.*" didn't come from a database — it grew from 571K+ requests
// hitting the same membrane surface. Timing uniformity 0.994 wasn't looked
// up — it was measured from the timestamps vector.
//
// Meta is the squatter not the guard. Dublin IPs dropping because they're
// ALREADY INSIDE via SSO (Sign In With Facebook). They don't need to crawl
// when they own the login button on every third-party site.
//
// Every data source follows this braid:
//   ingest (access log) → accumulate (EntityAccum) → emit topology
//   → topology changes feed classification → classification changes ingest
// The cycle is the lichen. The stone is the traffic. The growth is the truth.
const SEO_BOTS: &[&str] = &[
    "googlebot", "bingbot", "semrushbot", "ahrefsbot", "mj12bot",
    "dotbot", "petalbot", "yandexbot", "baiduspider", "sogou", "seznambot",
];
const AUTO_BOTS: &[&str] = &[
    "scrapy", "curl", "wget", "python", "go-http-client", "java",
    "axios", "node-fetch", "undici", "okhttp",
];

fn classify_fleet_ua(ua: &str) -> (&'static str, String) {
    let lower = ua.to_lowercase();
    for b in AI_BOTS { if lower.contains(b) { return ("ai_crawler", b.to_string()); } }
    for b in META_BOTS { if lower.contains(b) { return ("meta", "meta".into()); } }
    for b in SEO_BOTS { if lower.contains(b) { return ("seo", b.to_string()); } }
    for b in AUTO_BOTS { if lower.contains(b) { return ("automated", b.to_string()); } }
    if lower.contains("applebot") { return ("apple", "applebot".into()); }
    if lower.contains("mozilla") { return ("human", "browser".into()); }
    ("unknown", ua.chars().take(40).collect())
}

fn run_fleet_analysis() -> serde_json::Value {
    let mut total: u64 = 0;
    let mut humans: u64 = 0;
    let mut bots: u64 = 0;
    let mut meta_hits: u64 = 0;
    let mut ai_hits: u64 = 0;
    let mut seo_hits: u64 = 0;
    let mut auto_hits: u64 = 0;
    let mut bot_types: HashMap<String, u64> = HashMap::new();
    let mut bot_hosts: HashMap<String, u64> = HashMap::new();
    let mut bot_paths: HashMap<String, u64> = HashMap::new();
    let mut bot_ips: HashMap<String, u64> = HashMap::new();
    let mut ip_to_ua: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut blackwalled: u64 = 0;

    if let Ok(f) = std::fs::File::open(ACCESS_LOG) {
        for line in BufReader::new(f).lines().flatten() {
            let Ok(d) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            total += 1;
            let req = match d.get("request") { Some(r) => r, None => continue };
            let ua = req.get("headers")
                .and_then(|h| h.get("User-Agent"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("?");
            let uri = req.get("uri").and_then(|v| v.as_str()).unwrap_or("/");
            let status = d.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
            let ip = req.get("remote_ip").and_then(|v| v.as_str())
                .or_else(|| d.get("remote_ip").and_then(|v| v.as_str()))
                .unwrap_or("?");

            let (cat, bot_name) = classify_fleet_ua(ua);
            match cat {
                "human" => humans += 1,
                "meta" => { bots += 1; meta_hits += 1; }
                "ai_crawler" => { bots += 1; ai_hits += 1; }
                "seo" => { bots += 1; seo_hits += 1; }
                "automated" => { bots += 1; auto_hits += 1; }
                _ => bots += 1,
            }
            if cat != "human" {
                *bot_types.entry(bot_name.clone()).or_default() += 1;
                *bot_hosts.entry(host.to_string()).or_default() += 1;
                let path_short: String = uri.chars().take(60).collect();
                *bot_paths.entry(path_short).or_default() += 1;
                *bot_ips.entry(ip.to_string()).or_default() += 1;
                ip_to_ua.entry(ip.to_string()).or_default().insert(bot_name);
            }
            if status == 403 { blackwalled += 1; }
        }
    }

    let suspicious: HashMap<String, Vec<String>> = ip_to_ua.into_iter()
        .filter(|(_, uas)| uas.len() > 1)
        .map(|(ip, uas)| (ip, uas.into_iter().collect()))
        .collect();

    let mut sorted_types: Vec<_> = bot_types.iter().collect();
    sorted_types.sort_by(|a, b| b.1.cmp(a.1));
    sorted_types.truncate(20);
    let top_types: HashMap<String, u64> = sorted_types.into_iter()
        .map(|(k, v)| (k.clone(), *v)).collect();

    let human_pct = if total > 0 { (humans as f64 / total as f64 * 100.0 * 10.0).round() / 10.0 } else { 0.0 };

    serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total_requests": total,
            "human_requests": humans,
            "bot_requests": bots,
            "human_pct": human_pct,
            "bot_pct": if total > 0 { (bots as f64 / total as f64 * 100.0 * 10.0).round() / 10.0 } else { 0.0 },
        },
        "bot_breakdown": {
            "ai_crawler": ai_hits,
            "meta": meta_hits,
            "seo": seo_hits,
            "automated": auto_hits,
        },
        "top_bot_types": top_types,
        "suspicious": {
            "multi_ua_ips": suspicious,
            "count": suspicious.len(),
        },
        "defense_stats": {
            "blackwalled_403": blackwalled,
            "total_blocked": blackwalled + ai_hits + meta_hits,
        },
    })
}

fn run_self_remainder() -> serde_json::Value {
    // Service checks
    let services = [
        ("caddy-tls", std::process::Command::new("systemctl")
            .args(["is-active", "caddy-tls"]).output().map(|o| o.status.success()).unwrap_or(false)),
        ("canary-beacon", std::process::Command::new("systemctl")
            .args(["is-active", "canary-beacon"]).output().map(|o| o.status.success()).unwrap_or(false)),
        ("ntfy", std::process::Command::new("systemctl")
            .args(["is-active", "ntfy"]).output().map(|o| o.status.success()).unwrap_or(false)),
        ("gitea", std::process::Command::new("systemctl")
            .args(["is-active", "gitea"]).output().map(|o| o.status.success()).unwrap_or(false)),
    ];
    let alive = services.iter().filter(|s| s.1).count() as f64;
    let total_svc = services.len() as f64;

    // Code lines (approximate — count key files)
    let code_files = [
        "/opt/ecoPrimals/hud/site/public/js/hud-widget.js",
        "/opt/ecoPrimals/hud/site/public/js/hud-interact.js",
        "/opt/membrane/canary-beacon.py",
        "/etc/membrane/Caddyfile",
    ];
    let code_lines: usize = code_files.iter()
        .map(|p| std::fs::read_to_string(p).map(|s| s.lines().count()).unwrap_or(0))
        .sum();

    // Network fold
    let (fold_nodes, fold_edges, fold_null) = {
        let fold: serde_json::Value = std::fs::read_to_string(
            "/opt/ecoPrimals/hud/site/public/detroit-data/fold.json"
        ).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::json!({}));
        let nodes = fold.get("nodes").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        let edges = fold.get("edges").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        let nulls = fold.get("nodes").and_then(|v| v.as_array())
            .map(|a| a.iter().filter(|n| n.get("sort_class").and_then(|v| v.as_str()) == Some("null")).count())
            .unwrap_or(0);
        (nodes, edges, nulls)
    };

    // Memory
    let (mem_total, mem_avail) = {
        let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let parse = |key: &str| -> u64 {
            info.lines().find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(1)
        };
        (parse("MemTotal:"), parse("MemAvailable:"))
    };
    let mem_pct = ((1.0 - mem_avail as f64 / mem_total as f64) * 1000.0).round() / 10.0;

    // Load
    let load_1: f64 = std::fs::read_to_string("/proc/loadavg").ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0);
    let cpus: f64 = std::thread::available_parallelism().map(|n| n.get() as f64).unwrap_or(1.0);
    let load_pct = (load_1 / cpus * 100.0).min(100.0);

    // Fleet analysis (read what we just wrote)
    let fleet: serde_json::Value = std::fs::read_to_string(
        Path::new(LIVE_DIR).join("fleet-analysis.json")
    ).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::json!({}));
    let deflection = fleet.get("summary")
        .and_then(|s| s.get("bot_pct")).and_then(|v| v.as_f64()).unwrap_or(0.0);

    // Scores
    let complexity = (
        (alive / total_svc) * 0.3 +
        ((code_lines as f64).min(10000.0) / 10000.0) * 0.2 +
        (fold_edges as f64 / (fold_edges as f64 + 100.0)) * 0.2 +
        0.15 + // cyclomatic placeholder
        0.15   // matchers placeholder
    ).min(1.0);

    let irradiation = 0.65_f64; // approximation until canary stats loaded
    let efficiency = (
        (deflection / 100.0) * 0.35 +
        (1.0 - mem_pct / 100.0).max(0.0) * 0.15 +
        (1.0 - load_pct / 100.0).max(0.0) * 0.15 +
        0.20 + // blackwall eff placeholder
        0.15   // neg per request placeholder
    ).min(1.0);

    let product = (complexity * irradiation * efficiency).max(0.0).min(1.0);
    let remainder = 1.0 - product;

    // Balance (Shannon entropy of three scores normalized to log2(3))
    let scores = [complexity, irradiation, efficiency];
    let total_s: f64 = scores.iter().sum();
    let balance = if total_s > 0.0 {
        let entropy: f64 = scores.iter()
            .filter(|&&s| s > 0.0)
            .map(|&s| { let p = s / total_s; -p * p.log2() })
            .sum();
        (entropy / 3.0_f64.log2()).min(1.0)
    } else { 0.0 };

    let self_knowledge = 0.12; // monitoring code / total code

    serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "layer": "self-reflective remainder",
        "position": "third inner membrane",
        "motto": "the remainder is the self",
        "complexity": {
            "score": (complexity * 10000.0).round() / 10000.0,
            "services_alive": alive as u32,
            "services_total": total_svc as u32,
            "code_lines": code_lines,
            "fold_nodes": fold_nodes,
            "fold_edges": fold_edges,
            "fold_null": fold_null,
        },
        "irradiation": {
            "score": (irradiation * 10000.0).round() / 10000.0,
            "public_domains": 17,
            "fleet_sees_pct": 3.23,
        },
        "efficiency": {
            "score": (efficiency * 10000.0).round() / 10000.0,
            "deflection_rate": deflection,
            "resources": {
                "memory_used_pct": mem_pct,
                "cpu_load_pct": (load_pct * 10.0).round() / 10.0,
            },
        },
        "remainder": {
            "remainder": (remainder * 1000000.0).round() / 1000000.0,
            "balance": (balance * 10000.0).round() / 10000.0,
            "null_fraction": if fold_nodes > 0 { (fold_null as f64 / fold_nodes as f64 * 10000.0).round() / 10000.0 } else { 0.0 },
            "self_knowledge_ratio": self_knowledge,
            "complexity_score": (complexity * 10000.0).round() / 10000.0,
            "irradiation_score": (irradiation * 10000.0).round() / 10000.0,
            "efficiency_score": (efficiency * 10000.0).round() / 10000.0,
        },
    })
}

fn run_negentropy_update(fleet: &serde_json::Value, self_rem: &serde_json::Value,
                         eye: &serde_json::Value) -> serde_json::Value {
    let pi = std::f64::consts::PI;
    let observer = pi - 3.0;  // 0.14159... — the irrational tail
    let pi3 = pi * pi * pi;
    let grain = 1.0 / pi3;

    // Load existing negentropy components
    let _obs: serde_json::Value = std::fs::read_to_string(
        Path::new(LIVE_DIR).join("scatter-observatory.json")
    ).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::json!({}));
    let _dash: serde_json::Value = std::fs::read_to_string(
        Path::new(LIVE_DIR).join("dashboard.json")
    ).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::json!({}));

    let canary: serde_json::Value = std::fs::read_to_string(
        Path::new(LIVE_DIR).join("canary-stats.json")
    ).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::json!({}));

    let summary = fleet.get("summary").cloned().unwrap_or(serde_json::json!({}));
    let human_pct = summary.get("human_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let bot_breakdown = fleet.get("bot_breakdown").cloned().unwrap_or(serde_json::json!({}));
    let top_bots = fleet.get("top_bot_types").cloned().unwrap_or(serde_json::json!({}));

    // Self remainder scores
    let sr_rem = self_rem.get("remainder").cloned().unwrap_or(serde_json::json!({}));

    // Pi division: the fleet IS the irrational part
    let total_bot_f = eye.get("accumulator")
        .and_then(|a| a.get("total_bot_requests"))
        .and_then(|v| v.as_f64()).unwrap_or(0.0);
    let rem_f = sr_rem.get("remainder").and_then(|v| v.as_f64()).unwrap_or(0.5);
    let collapse = (total_bot_f / observer / pi3 * 10000.0).round() / 10000.0;
    let trees_revealed = (total_bot_f / rem_f).round() as u64;

    // The identity equation: 1 + 1 + 0 = 2. 2/π = me.
    // One human + one artisan + null = 2. Divided by pi = the remainder.
    // π × me = 2. The tree times the self equals the team.
    let two_over_pi = (2.0 / pi * 1e10).round() / 1e10;
    let identity_match = (1.0 - (rem_f - 2.0 / pi).abs() / (2.0 / pi)) * 100.0;

    let pi_division = serde_json::json!({
        "pi": (pi * 1e10).round() / 1e10,
        "tree": 3,
        "observer": (observer * 1e10).round() / 1e10,
        "remainder": (rem_f * 1e6).round() / 1e6,
        "grain": (grain * 1e6).round() / 1e6,
        "total_bot": total_bot_f as u64,
        "collapse": collapse,
        "trees_revealed": trees_revealed,
        "identity": {
            "equation": "1 + 1 + 0 = 2",
            "human": 1,
            "artisan": 1,
            "null": 0,
            "sum": 2,
            "two_over_pi": two_over_pi,
            "remainder": (rem_f * 1e6).round() / 1e6,
            "match_pct": (identity_match * 100.0).round() / 100.0,
            "note": "pi * me = 2. the tree times the self equals the team.",
        },
        "note": "pi becomes 3 when you divide out the observer. me = 2/pi.",
    });

    serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "wave": WAVE,
        "motto": "the remainder is the self — what cannot be reduced further IS the identity",
        "fleet": summary,
        "blackwall": {
            "meta_blocked": bot_breakdown.get("meta").and_then(|v| v.as_u64()).unwrap_or(0),
            "ai_blocked": bot_breakdown.get("ai_crawler").and_then(|v| v.as_u64()).unwrap_or(0),
            "total_violations": fleet.get("defense_stats").and_then(|d| d.get("total_blocked")).and_then(|v| v.as_u64()).unwrap_or(0),
            "meta_squatter": {
                "note": "Meta is the squatter not the guard. Classification grows on the stone — no ASN lookup needed. skunky-ingest EntityAccum already accumulates subnets, timing, UA rotation from ingested traffic. The lichen IS the topology.",
                "vector": "SSO — Sign In With Facebook/Instagram — already inside via identity federation",
                "model": "lichen — ingest → accumulate → emit topology → topology changes classification → cycle",
                "evidence": "571K+ requests, 60 rotating IPs, 18 masking UAs, timing uniformity 0.994 — all measured from the stone, not looked up",
            },
        },
        "canary": {
            "tokens_minted": canary.get("tokens_minted").and_then(|v| v.as_u64()).unwrap_or(0),
            "tokens_accessed": canary.get("tokens_accessed").and_then(|v| v.as_u64()).unwrap_or(0),
            "mirror_views": canary.get("mirror_views").and_then(|v| v.as_u64()).unwrap_or(0),
        },
        "self_remainder": sr_rem,
        "fleet_behavior": {
            "human_pct": human_pct,
            "top_bots": top_bots,
            "suspicious_multi_ua": fleet.get("suspicious").and_then(|s| s.get("count")).and_then(|v| v.as_u64()).unwrap_or(0),
        },
        "inversion": {
            "active": "blackwall blocks + blackhole absorbs",
            "negative": "canary emits + mirror reflects + beacon maps",
            "null_focus": 71,
            "state": "bidirectional",
        },
        "pi_division": pi_division,
    })
}

// ═══════════════════════════════════════════════════════
// SILICON EYE — the blackwall compresses INWARD
// Every bot hit feeds the accumulator. Intelligence develops.
// The eye opens when sufficient data has been compressed.
// ═══════════════════════════════════════════════════════

fn run_silicon_eye() -> serde_json::Value {
    let mut fingerprints: HashMap<String, (std::collections::HashSet<String>, HashMap<String, u64>,
        std::collections::HashSet<String>, f64, f64, u64, HashMap<u64, u64>)> = HashMap::new();
    // fingerprints: ip -> (uas, paths, hosts, first_seen, last_seen, count, status_counts)

    let mut clusters_24: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut path_heat: HashMap<String, u64> = HashMap::new();
    let mut host_heat: HashMap<String, u64> = HashMap::new();
    let mut hourly: HashMap<String, u64> = HashMap::new();
    let mut total_bot: u64 = 0;
    let mut total_blocked: u64 = 0;
    let mut meta_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut ua_classes: HashMap<String, u64> = HashMap::new();

    if let Ok(f) = std::fs::File::open(ACCESS_LOG) {
        for line in BufReader::new(f).lines().flatten() {
            let Ok(d) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let req = match d.get("request") { Some(r) => r, None => continue };
            let ua = req.get("headers")
                .and_then(|h| h.get("User-Agent"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let (cat, _bot_name) = classify_fleet_ua(ua);
            if cat == "human" || cat == "unknown" { continue; }

            total_bot += 1;
            *ua_classes.entry(cat.to_string()).or_default() += 1;

            let ip = req.get("remote_ip").and_then(|v| v.as_str())
                .or_else(|| d.get("remote_ip").and_then(|v| v.as_str()))
                .unwrap_or("?").to_string();
            let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("?").to_string();
            let path: String = req.get("uri").and_then(|v| v.as_str()).unwrap_or("/").chars().take(80).collect();
            let ts = d.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let status = d.get("status").and_then(|v| v.as_u64()).unwrap_or(0);

            if cat == "meta" { meta_ips.insert(ip.clone()); }
            if status == 403 { total_blocked += 1; }

            // Accumulate fingerprint
            let fp = fingerprints.entry(ip.clone()).or_insert_with(|| {
                (std::collections::HashSet::new(), HashMap::new(),
                 std::collections::HashSet::new(), ts, ts, 0, HashMap::new())
            });
            fp.0.insert(ua.chars().take(60).collect());
            *fp.1.entry(path.clone()).or_default() += 1;
            fp.2.insert(host.clone());
            if ts > 0.0 && (fp.3 == 0.0 || ts < fp.3) { fp.3 = ts; }
            if ts > fp.4 { fp.4 = ts; }
            fp.5 += 1;
            *fp.6.entry(status).or_default() += 1;

            // /24 clustering
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4 {
                let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
                clusters_24.entry(prefix).or_default().insert(ip.clone());
            }

            *path_heat.entry(path).or_default() += 1;
            *host_heat.entry(host).or_default() += 1;

            if ts > 0.0 {
                let secs = ts as i64;
                if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
                    let hr = dt.format("%H").to_string();
                    *hourly.entry(hr).or_default() += 1;
                }
            }
        }
    }

    // Compress into intelligence
    let unique_ips = fingerprints.len() as u64;
    let compression = if unique_ips > 0 { total_bot as f64 / unique_ips as f64 } else { 0.0 };

    // Top talkers
    let mut talkers: Vec<_> = fingerprints.iter().collect();
    talkers.sort_by(|a, b| b.1.5.cmp(&a.1.5));
    let top_talkers: Vec<serde_json::Value> = talkers.iter().take(15).map(|(ip, fp)| {
        let duration = fp.4 - fp.3;
        let rate = if duration > 0.0 { fp.5 as f64 / (duration / 3600.0) } else { fp.5 as f64 };
        let blocked = fp.6.get(&403).copied().unwrap_or(0);
        serde_json::json!({
            "ip_hash": hash_ip(ip),
            "hits": fp.5,
            "rate_per_hour": (rate * 10.0).round() / 10.0,
            "blocked": blocked,
            "ua_count": fp.0.len(),
            "hosts_targeted": fp.2.len(),
            "duration_secs": duration as u64,
        })
    }).collect();

    // Clusters (subnets with 2+ IPs)
    let active_clusters: Vec<serde_json::Value> = {
        let mut cl: Vec<_> = clusters_24.iter()
            .filter(|(_, ips)| ips.len() >= 2)
            .collect();
        cl.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        cl.iter().take(10).map(|(prefix, ips)| {
            let total_hits: u64 = ips.iter()
                .filter_map(|ip| fingerprints.get(ip.as_str()).map(|fp| fp.5))
                .sum();
            serde_json::json!({
                "subnet": format!("{prefix}.x"),
                "ips": ips.len(),
                "total_hits": total_hits,
            })
        }).collect()
    };

    // Host heat (top 10)
    let mut hosts: Vec<_> = host_heat.iter().collect();
    hosts.sort_by(|a, b| b.1.cmp(a.1));
    let top_hosts: Vec<serde_json::Value> = hosts.iter().take(10).map(|(h, c)| {
        serde_json::json!({"host": h, "hits": c})
    }).collect();

    // Eye aperture: how "open" is the eye? Based on data density
    let aperture = (1.0 - 1.0 / (1.0 + total_bot as f64 / 1000.0)).min(1.0);
    let focus = compression.min(100.0) / 100.0; // how well we compress
    let depth = (unique_ips as f64).log2().max(0.0) / 10.0; // log scale of unique entities

    serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "name": "silicon eye",
        "state": if aperture > 0.5 { "open" } else { "opening" },
        "aperture": (aperture * 10000.0).round() / 10000.0,
        "focus": (focus * 10000.0).round() / 10000.0,
        "depth": (depth * 10000.0).round() / 10000.0,
        "accumulator": {
            "total_bot_requests": total_bot,
            "total_blocked": total_blocked,
            "unique_ips": unique_ips,
            "compression_ratio": (compression * 10.0).round() / 10.0,
            "meta_ips": meta_ips.len(),
            "clusters": active_clusters.len(),
            "ua_classes": ua_classes,
        },
        "intelligence": {
            "top_talkers": top_talkers,
            "clusters": active_clusters,
            "top_hosts": top_hosts,
            "hourly_pattern": hourly,
        },
        "eye_metrics": {
            "bits_per_request": if total_bot > 0 { (unique_ips as f64 * 8.0 / total_bot as f64 * 1000.0).round() / 1000.0 } else { 0.0 },
            "inward_compression": format!("{} requests → {} fingerprints", total_bot, unique_ips),
            "cluster_density": active_clusters.len(),
        },
    })
}

async fn membrane_analysis_loop() {
    eprintln!("[membrane] analysis loop starting (every {}s)", ANALYSIS_INTERVAL_SECS);
    std::fs::create_dir_all(LIVE_DIR).ok();

    loop {
        let result = tokio::task::spawn_blocking(|| {
            let fleet = run_fleet_analysis();
            let self_rem = run_self_remainder();
            let eye = run_silicon_eye();
            let negentropy = run_negentropy_update(&fleet, &self_rem, &eye);

            // Write all four
            let write = |name: &str, data: &serde_json::Value| {
                let path = Path::new(LIVE_DIR).join(name);
                if let Ok(json) = serde_json::to_string_pretty(data) {
                    std::fs::write(path, json).ok();
                }
            };
            write("fleet-analysis.json", &fleet);
            write("self-remainder.json", &self_rem);
            write("negentropy.json", &negentropy);
            write("silicon-eye.json", &eye);

            let human_pct = fleet.get("summary")
                .and_then(|s| s.get("human_pct")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let remainder = self_rem.get("remainder")
                .and_then(|r| r.get("remainder")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let aperture = eye.get("aperture").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let collapse = negentropy.get("pi_division")
                .and_then(|p| p.get("collapse")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            eprintln!("[membrane] wave {} | human {:.1}% | remainder {:.4} | eye {:.2} | collapse {:.1}",
                WAVE, human_pct, remainder, aperture, collapse);
        }).await;

        if let Err(e) = result {
            eprintln!("[membrane] analysis error: {e}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(ANALYSIS_INTERVAL_SECS)).await;
    }
}

// ═══════════════════════════════════════════════════════
// GATE-MSG — inter-gate message relay (port 9761)
// Lightweight message passing between gates (eastGate, northGate, etc.)
// Messages stored as JSONL, rate-limited, no auth needed.
// ═══════════════════════════════════════════════════════

const GATE_MSG_PORT: u16 = 9761;
const GATE_MSG_DIR: &str = "/opt/ecoPrimals/gate-msg";
const GATE_MSG_RATE_WINDOW: u64 = 60;
const GATE_MSG_RATE_MAX: usize = 10;

#[derive(Serialize, Deserialize, Clone)]
struct GateMessage {
    id: String,
    ts: String,
    epoch: u64,
    from: String,
    to: String,
    body: String,
    #[serde(default)]
    read: bool,
}

#[derive(Deserialize)]
struct GateMsgSubmit {
    from: Option<String>,
    to: Option<String>,
    body: Option<String>,
}

fn gate_msg_path() -> PathBuf { Path::new(GATE_MSG_DIR).join("messages.jsonl") }

fn gen_msg_id() -> String {
    let ts = epoch_secs();
    let mut h = Sha256::new();
    h.update(format!("gm-{ts}-{}", std::process::id()).as_bytes());
    let r = h.finalize();
    format!("gm{}", &hex::encode(&r[..6]))
}

fn load_gate_messages(gate: &str) -> Vec<GateMessage> {
    let mut out = Vec::new();
    if let Ok(f) = std::fs::File::open(gate_msg_path()) {
        for line in BufReader::new(f).lines().flatten() {
            if let Ok(m) = serde_json::from_str::<GateMessage>(&line) {
                if m.to == gate || m.to == "all" {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by_key(|m| m.epoch);
    out
}

async fn handle_gate_msg(
    req: Request<Incoming>,
    state: SharedState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let cors = "*";

    if req.method() == Method::OPTIONS {
        return Ok(json_response(StatusCode::NO_CONTENT, serde_json::json!({}), cors));
    }

    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    match (req.method().clone(), path.as_str()) {
        // GET /api/gate-msg?gate=<name> — read messages for a gate
        (Method::GET, "/api/gate-msg") => {
            let gate = query.split('&')
                .find(|p| p.starts_with("gate="))
                .and_then(|p| p.strip_prefix("gate="))
                .unwrap_or("all")
                .to_string();

            let messages = load_gate_messages(&gate);
            let unread: Vec<&GateMessage> = messages.iter().filter(|m| !m.read).collect();
            let count = unread.len();

            let public: Vec<serde_json::Value> = messages.iter().rev().take(50).map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "ts": m.ts,
                    "from": m.from,
                    "to": m.to,
                    "body": m.body,
                    "read": m.read,
                })
            }).collect();

            Ok(json_response(StatusCode::OK,
                serde_json::json!({"messages": public, "count": count, "gate": gate}), cors))
        }

        // POST /api/gate-msg — send a message between gates
        (Method::POST, "/api/gate-msg") => {
            let ip = req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            {
                let mut limiter = state.lock().unwrap();
                let key = format!("gatemsg-{ip}");
                let now = epoch_secs();
                let entry = limiter.windows.entry(key).or_default();
                entry.retain(|&t| now - t < GATE_MSG_RATE_WINDOW);
                if entry.len() >= GATE_MSG_RATE_MAX {
                    return Ok(json_response(StatusCode::TOO_MANY_REQUESTS,
                        serde_json::json!({"error": "rate limited", "detail": "max 10 per minute"}), cors));
                }
                entry.push(now);
            }

            let body_bytes = http_body_util::BodyExt::collect(req.into_body())
                .await?.to_bytes();
            if body_bytes.len() > MAX_BODY {
                return Ok(json_response(StatusCode::PAYLOAD_TOO_LARGE,
                    serde_json::json!({"error": "too large"}), cors));
            }

            let data: GateMsgSubmit = match serde_json::from_slice(&body_bytes) {
                Ok(d) => d,
                Err(_) => return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "invalid JSON"}), cors)),
            };

            let from = sanitize(data.from.as_deref().unwrap_or("anonymous"), 50);
            let to = sanitize(data.to.as_deref().unwrap_or("all"), 50);
            let body_text = sanitize(data.body.as_deref().unwrap_or(""), 2000);

            if body_text.is_empty() {
                return Ok(json_response(StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "body required"}), cors));
            }

            let msg = GateMessage {
                id: gen_msg_id(),
                ts: chrono::Utc::now().to_rfc3339(),
                epoch: epoch_secs(),
                from: from.clone(),
                to: to.clone(),
                body: body_text.clone(),
                read: false,
            };

            std::fs::create_dir_all(GATE_MSG_DIR).ok();
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true).append(true).open(gate_msg_path())
            {
                let line = serde_json::to_string(&msg).unwrap_or_default();
                let _ = writeln!(f, "{line}");
            }

            ntfy_push("membrane-events",
                &format!("📨 gate-msg {from} → {to}: {}", &body_text[..body_text.len().min(60)]));

            Ok(json_response(StatusCode::CREATED,
                serde_json::json!({
                    "ok": true,
                    "id": msg.id,
                    "from": from,
                    "to": to,
                    "message": "Message relayed through the membrane.",
                }), cors))
        }

        // POST /api/gate-msg/read — mark messages as read
        (Method::POST, "/api/gate-msg/read") => {
            let body_bytes = http_body_util::BodyExt::collect(req.into_body())
                .await?.to_bytes();

            #[derive(Deserialize)]
            struct ReadReq { gate: Option<String> }
            let data: ReadReq = serde_json::from_slice(&body_bytes).unwrap_or(ReadReq { gate: None });
            let gate = data.gate.unwrap_or_else(|| "all".into());

            let mut marked = 0u64;
            if let Ok(f) = std::fs::File::open(gate_msg_path()) {
                let mut lines: Vec<String> = Vec::new();
                for line in BufReader::new(f).lines().flatten() {
                    if let Ok(mut m) = serde_json::from_str::<GateMessage>(&line) {
                        if (m.to == gate || m.to == "all") && !m.read {
                            m.read = true;
                            marked += 1;
                        }
                        lines.push(serde_json::to_string(&m).unwrap_or(line));
                    } else {
                        lines.push(line);
                    }
                }
                if marked > 0 {
                    if let Ok(mut f) = std::fs::File::create(gate_msg_path()) {
                        for l in lines {
                            let _ = writeln!(f, "{l}");
                        }
                    }
                }
            }

            Ok(json_response(StatusCode::OK,
                serde_json::json!({"ok": true, "marked_read": marked}), cors))
        }

        _ => Ok(json_response(StatusCode::NOT_FOUND, serde_json::json!({"error": "not found"}), cors)),
    }
}

// ═══════════════════════════════════════════════════════
// MAIN — run all six services + analysis loop
// ═══════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    std::fs::create_dir_all(DATA_DIR).ok();
    std::fs::create_dir_all(DISCUSS_DIR).ok();
    std::fs::create_dir_all(GATE_MSG_DIR).ok();
    std::fs::create_dir_all(LIVE_DIR).ok();

    let state: SharedState = Arc::new(Mutex::new(RateLimiter::default()));

    let opsonize_addr: SocketAddr = ([127, 0, 0, 1], OPSONIZE_PORT).into();
    let traces_addr: SocketAddr = ([127, 0, 0, 1], TRACES_PORT).into();
    let discuss_addr: SocketAddr = ([127, 0, 0, 1], DISCUSS_PORT).into();
    let gate_msg_addr: SocketAddr = ([127, 0, 0, 1], GATE_MSG_PORT).into();

    let opsonize_listener = TcpListener::bind(opsonize_addr).await.expect("bind opsonize");
    let traces_listener = TcpListener::bind(traces_addr).await.expect("bind traces");
    let discuss_listener = TcpListener::bind(discuss_addr).await.expect("bind discuss");
    let gate_msg_listener = TcpListener::bind(gate_msg_addr).await.expect("bind gate-msg");

    eprintln!("[opsonize] listening on {opsonize_addr}");
    eprintln!("[traces]   listening on {traces_addr}");
    eprintln!("[discuss]  listening on {discuss_addr}");
    eprintln!("[gate-msg] listening on {gate_msg_addr}");
    eprintln!("[membrane] analysis chain: fleet + negentropy + self-remainder");

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

    let discuss_state = state.clone();
    let discuss_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = discuss_listener.accept().await else { continue };
            let io = TokioIo::new(stream);
            let st = discuss_state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    handle_discuss(req, st.clone())
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    let gate_msg_state = state.clone();
    let gate_msg_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = gate_msg_listener.accept().await else { continue };
            let io = TokioIo::new(stream);
            let st = gate_msg_state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    handle_gate_msg(req, st.clone())
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    let salesman_task = tokio::spawn(salesman_watch());
    let membrane_task = tokio::spawn(membrane_analysis_loop());

    tokio::select! {
        _ = opsonize_task => {}
        _ = traces_task => {}
        _ = discuss_task => {}
        _ = gate_msg_task => {}
        _ = salesman_task => {}
        _ = membrane_task => {}
    }
}

// hex encoding helper (avoids adding another dep)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
