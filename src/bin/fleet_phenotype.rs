//! Fleet phenotype analysis — population genetics of automated visitors.
//!
//! Replaces Python fleet-phenotype.py (294 lines).
//! Reads Caddy access logs, classifies visitors through biological taxonomy,
//! computes genotype×phenotype clusters, allele frequencies, Shannon diversity.
//! Writes JSON snapshot consumable by signal.primals.eco dashboard.
//!
//! Usage: fleet-phenotype [--log /var/log/caddy/access.log] [--out /var/lib/skunky-ingest/fleet-phenotype.json]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde_json::json;
use sha2::{Digest, Sha256};

const DEFAULT_LOG: &str = "/var/log/caddy/access.log";
const DEFAULT_OUT: &str = "/var/lib/skunky-ingest/fleet-phenotype.json";

const SKIP_EXTS: &[&str] = &[".js", ".css", ".svg", ".png", ".woff", ".ico"];

fn classify_ua_type(ua: &str, has_sec: bool, has_ref: bool, ip: &str) -> &'static str {
    let ua_lower = ua.to_lowercase();
    if ua_lower.contains("claudebot") { return "claudebot"; }
    if ua_lower.contains("meta-external") || ip.starts_with("57.141.20.") { return "meta-identified"; }
    if ua_lower.contains("reflectionbot") { return "reflectionbot"; }
    if ua_lower.contains("semrush") { return "semrush"; }
    if ua_lower.contains("exasearch") { return "exa"; }
    if ua_lower.contains("amazonbot") { return "amazon"; }
    if ua_lower.contains("sogou") { return "sogou"; }
    if ua_lower.contains("gptbot") { return "gptbot"; }
    if ua_lower.contains("bytespider") { return "bytespider"; }
    if ua_lower.contains("headlesschrome") { return "headless"; }
    if has_sec && !has_ref { return "browser-no-ref"; }
    if has_sec && has_ref { return "browser-with-ref"; }
    "minimal"
}

fn classify_kingdom(ua_type: &str, has_sec: bool, has_ref: bool) -> &'static str {
    if ua_type == "browser-no-ref" && !has_ref { return "Chimera"; }
    if ua_type == "browser-with-ref" && has_ref { return "Anthropos"; }
    if has_sec && has_ref { return "Anthropos"; }
    "Automata"
}

fn classify_diet(real_pct: f64) -> &'static str {
    if real_pct > 80.0 { "herbivore" }
    else if real_pct > 20.0 { "omnivore" }
    else { "detritivore" }
}

fn shannon(counts: &HashMap<String, u64>) -> f64 {
    let total: f64 = counts.values().sum::<u64>() as f64;
    if total == 0.0 { return 0.0; }
    -counts.values()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

struct Specimen {
    ua: String,
    host: String,
    uri: String,
    sz: u64,
    ae: String,
    al: String,
    sec_plat: String,
    n_hdrs: usize,
    has_sec: bool,
    tls_proto: String,
    referer: String,
}

fn analyze(log_path: &str) -> serde_json::Value {
    let mut specimens: HashMap<String, Vec<Specimen>> = HashMap::new();

    if let Ok(f) = std::fs::File::open(log_path) {
        for line in BufReader::new(f).lines().flatten() {
            let Ok(d) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let Some(req) = d.get("request") else { continue };

            let ip = req.get("remote_ip").and_then(|v| v.as_str()).unwrap_or("?").to_string();
            let hdrs = req.get("headers").cloned().unwrap_or(json!({}));
            let uri = req.get("uri").and_then(|v| v.as_str()).unwrap_or("?").to_string();

            if SKIP_EXTS.iter().any(|ext| uri.ends_with(ext)) || uri.contains("favicon") { continue; }

            let ua = hdrs.get("User-Agent")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ae = hdrs.get("Accept-Encoding")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let al = hdrs.get("Accept-Language")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let sec_plat = hdrs.get("Sec-Ch-Ua-Platform")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let referer = hdrs.get("Referer")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let tls_proto = req.get("tls")
                .and_then(|t| t.get("proto"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let n_hdrs = hdrs.as_object().map(|o| o.len()).unwrap_or(0);
            let has_sec = hdrs.as_object()
                .map(|o| o.keys().any(|k| k.starts_with("Sec-")))
                .unwrap_or(false);
            let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("?").to_string();
            let sz = d.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

            specimens.entry(ip).or_default().push(Specimen {
                ua, host, uri, sz, ae, al, sec_plat, n_hdrs, has_sec, tls_proto, referer,
            });
        }
    }

    let total_ips = specimens.len();
    let total_requests: usize = specimens.values().map(|v| v.len()).sum();

    let mut kingdoms: HashMap<String, u64> = HashMap::new();
    let mut genera: HashMap<String, u64> = HashMap::new();
    let mut species_counter: HashMap<String, u64> = HashMap::new();
    let mut trophic: HashMap<String, u64> = HashMap::new();
    let mut platforms: HashMap<String, u64> = HashMap::new();
    let mut ua_types: HashMap<String, u64> = HashMap::new();
    let mut ae_variants: HashMap<String, u64> = HashMap::new();

    let mut alleles = HashMap::from([
        ("has_sec", 0u64), ("has_ref", 0), ("en_us", 0),
        ("http11", 0), ("h2", 0), ("single_ua", 0), ("rotates_ua", 0),
    ]);

    let mut species_detail: HashMap<String, serde_json::Value> = HashMap::new();

    for (ip, reqs) in &specimens {
        let uas: std::collections::HashSet<String> = reqs.iter().map(|r| r.ua[..r.ua.len().min(80)].to_string()).collect();
        let ua_sample = uas.iter().next().cloned().unwrap_or_default();
        let has_sec = reqs.iter().any(|r| r.has_sec);
        let has_ref = reqs.iter().any(|r| !r.referer.is_empty());
        let ae = reqs.first().map(|r| &r.ae[..r.ae.len().min(30)]).unwrap_or("").to_string();
        let al = reqs.first().map(|r| r.al.clone()).unwrap_or_default();
        let plat = reqs.iter().find(|r| !r.sec_plat.is_empty()).map(|r| r.sec_plat.clone()).unwrap_or_else(|| "none".into());
        let tls_alpn = reqs.first().map(|r| r.tls_proto.clone()).unwrap_or_default();

        let ua_type = classify_ua_type(&ua_sample, has_sec, has_ref, ip);
        let kingdom = classify_kingdom(ua_type, has_sec, has_ref);

        let genus = match ua_type {
            "claudebot" => "Claudius",
            "meta-identified" => "Metacrawler",
            "reflectionbot" => "Reflector",
            "browser-no-ref" | "headless" => "Phantoma",
            "browser-with-ref" => "Homo",
            _ => "incertae_sedis",
        };

        // Species hash (sha256 truncated to match Python's md5[:6])
        let sp_parts = format!("{}|{}|{}|{}", &ae[..ae.len().min(20)], reqs[0].n_hdrs, tls_alpn, plat);
        let mut hasher = Sha256::new();
        hasher.update(sp_parts.as_bytes());
        let sp_hash: String = hasher.finalize()[..3].iter().map(|b| format!("{b:02x}")).collect();
        let sp = format!("{}_{sp_hash}", genus.to_lowercase());

        // Diet classification
        let n_real = reqs.iter().filter(|r| r.uri.contains("ecoPrimals")).count();
        let n_fake = reqs.iter().filter(|r| r.uri.starts_with("/commit/")).count();
        let total_diet = n_real + n_fake;
        let real_pct = if total_diet > 0 { n_real as f64 / total_diet as f64 * 100.0 } else { 0.0 };
        let diet = if total_diet > 0 { classify_diet(real_pct) } else { "non-feeding" };

        let total_bytes: u64 = reqs.iter().map(|r| r.sz).sum();

        *kingdoms.entry(kingdom.to_string()).or_default() += 1;
        *genera.entry(genus.to_string()).or_default() += 1;
        *species_counter.entry(sp.clone()).or_default() += 1;
        *trophic.entry(diet.to_string()).or_default() += 1;
        *platforms.entry(plat.clone()).or_default() += 1;
        *ua_types.entry(ua_type.to_string()).or_default() += 1;
        *ae_variants.entry(ae.clone()).or_default() += 1;

        if has_sec { *alleles.get_mut("has_sec").unwrap() += 1; }
        if has_ref { *alleles.get_mut("has_ref").unwrap() += 1; }
        if al.starts_with("en") { *alleles.get_mut("en_us").unwrap() += 1; }
        if tls_alpn == "http/1.1" || tls_alpn.is_empty() { *alleles.get_mut("http11").unwrap() += 1; }
        if tls_alpn == "h2" { *alleles.get_mut("h2").unwrap() += 1; }
        if uas.len() == 1 { *alleles.get_mut("single_ua").unwrap() += 1; }
        if uas.len() > 1 { *alleles.get_mut("rotates_ua").unwrap() += 1; }

        let sd = species_detail.entry(sp.clone()).or_insert_with(|| json!({
            "genus": genus, "kingdom": kingdom,
            "ae": ae, "platform": plat, "tls_alpn": tls_alpn,
            "ua_sample": &ua_sample[..ua_sample.len().min(90)],
            "ips": 0, "requests": 0, "bytes": 0,
            "diet_real_pct": 0.0,
        }));
        if let Some(obj) = sd.as_object_mut() {
            *obj.entry("ips").or_insert(json!(0)) = json!(obj.get("ips").and_then(|v| v.as_u64()).unwrap_or(0) + 1);
            *obj.entry("requests").or_insert(json!(0)) = json!(obj.get("requests").and_then(|v| v.as_u64()).unwrap_or(0) + reqs.len() as u64);
            *obj.entry("bytes").or_insert(json!(0)) = json!(obj.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0) + total_bytes);
            *obj.entry("diet_real_pct").or_insert(json!(0.0)) = json!((real_pct * 10.0).round() / 10.0);
        }
    }

    // Allele frequencies as percentages
    let n = total_ips.max(1) as f64;
    let allele_freq: HashMap<String, f64> = alleles.iter()
        .map(|(k, v)| (k.to_string(), (*v as f64 / n * 100.0 * 10.0).round() / 10.0))
        .collect();

    // Sort species by request count, take top 20
    let mut species_sorted: Vec<_> = species_counter.iter().collect();
    species_sorted.sort_by(|a, b| b.1.cmp(a.1));
    let top_species: HashMap<String, u64> = species_sorted.iter().take(20).map(|(k, v)| (k.to_string(), **v)).collect();

    let mut detail_sorted: Vec<_> = species_detail.iter().collect();
    detail_sorted.sort_by(|a, b| {
        b.1.get("requests").and_then(|v| v.as_u64()).unwrap_or(0)
            .cmp(&a.1.get("requests").and_then(|v| v.as_u64()).unwrap_or(0))
    });
    let top_detail: HashMap<String, serde_json::Value> = detail_sorted.iter().take(20)
        .map(|(k, v)| (k.to_string(), (*v).clone()))
        .collect();

    json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "total_ips": total_ips,
        "total_requests": total_requests,
        "taxonomy": {
            "kingdoms": kingdoms,
            "genera": genera,
            "species": top_species,
            "species_detail": top_detail,
        },
        "population_genetics": {
            "allele_frequencies": allele_freq,
            "trophic_levels": trophic,
            "platform_karyotype": platforms,
            "ua_morphotypes": ua_types,
            "shannon_diversity": {
                "accept_encoding": { "H": (shannon(&ae_variants) * 1000.0).round() / 1000.0, "alleles": ae_variants.len() },
                "ua_morphotype": { "H": (shannon(&ua_types) * 1000.0).round() / 1000.0, "alleles": ua_types.len() },
                "platform": { "H": (shannon(&platforms) * 1000.0).round() / 1000.0, "alleles": platforms.len() },
            },
            "effective_population_size": {
                "apparent_N": total_ips,
                "estimated_Ne": 5,
                "Ne_N_ratio": (5.0 / total_ips.max(1) as f64 * 10000.0).round() / 10000.0,
            },
        },
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut log_path = DEFAULT_LOG.to_string();
    let mut out_path = DEFAULT_OUT.to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--log" if i + 1 < args.len() => { log_path = args[i + 1].clone(); i += 2; }
            "--out" if i + 1 < args.len() => { out_path = args[i + 1].clone(); i += 2; }
            _ => { i += 1; }
        }
    }

    if !Path::new(&log_path).exists() {
        eprintln!("Log file not found: {log_path}");
        std::process::exit(1);
    }

    let results = analyze(&log_path);

    if let Some(parent) = Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let formatted = serde_json::to_string_pretty(&results).unwrap_or_default();
    std::fs::write(&out_path, &formatted).expect("write output");

    let n = results.get("total_ips").and_then(|v| v.as_u64()).unwrap_or(0);
    let r = results.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(0);
    let kingdoms = results.get("taxonomy").and_then(|t| t.get("kingdoms")).and_then(|k| k.as_object()).map(|o| o.len()).unwrap_or(0);
    let species = results.get("taxonomy").and_then(|t| t.get("species_detail")).and_then(|s| s.as_object()).map(|o| o.len()).unwrap_or(0);

    eprintln!("fleet-phenotype: {n} IPs, {r} requests, {kingdoms} kingdoms, {species} species → {out_path}");
}
