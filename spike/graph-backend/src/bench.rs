use anyhow::{Context, Result};
use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use tracing::{debug, info};

// Query templates (AGE 1.6 openCypher syntax).
// $PRINCIPAL is replaced at runtime with the sampled principal ID.
// Queries are wrapped via: SELECT * FROM ag_catalog.cypher('cloud', $$...$$) AS (r agtype)
const QUERIES: &[(&str, &str)] = &[
    (
        "01-one-hop",
        "MATCH (p:Principal {id: '$PRINCIPAL'})-[r]->(t) RETURN t LIMIT 100",
    ),
    (
        "02-three-hop",
        "MATCH (u:Principal {id: '$PRINCIPAL'})-[:CanAssume]->(r:Principal)-[:HasPermission]->(pol:Policy) RETURN pol LIMIT 100",
    ),
    (
        "03-six-hop-varlen",
        "MATCH path = (s:Principal {id: '$PRINCIPAL'})-[:CanAssume|HasPermission*1..6]->(t) RETURN t LIMIT 50",
    ),
    (
        "04-shortest-path",
        "MATCH path = (s:Principal {id: '$PRINCIPAL'})-[:CanAssume|HasPermission*1..8]-(t:Principal) WHERE t.id <> '$PRINCIPAL' RETURN length(path) ORDER BY length(path) LIMIT 1",
    ),
    (
        "05-subgraph",
        "MATCH (p:Principal {id: '$PRINCIPAL'})-[r:CanAssume|HasPermission*1..3]-(neighbor) RETURN neighbor LIMIT 100",
    ),
];

#[allow(dead_code)]
pub struct BenchmarkResult {
    pub query_name: String,
    pub single_thread_p50: f64,
    pub single_thread_p95: f64,
    pub single_thread_p99: f64,
    pub concurrent_p95: f64,
    pub concurrent_p99: f64,
    pub verdict: String,
}

pub async fn run_benchmarks(
    db_host: &str,
    db_port: u16,
    db_user: &str,
    db_password: &str,
    db_name: &str,
    size: &str,
    pool_size: usize,
    concurrency: usize,
) -> Result<String> {
    info!(
        size = size,
        concurrency = concurrency,
        pool_size = pool_size,
        "Starting benchmarks"
    );

    // Build connection pool
    let mut cfg = Config::new();
    cfg.host = Some(db_host.to_string());
    cfg.port = Some(db_port);
    cfg.user = Some(db_user.to_string());
    cfg.password = Some(db_password.to_string());
    cfg.dbname = Some(db_name.to_string());
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .context("Failed to create connection pool")?;

    info!("Connection pool created (size: {})", pool_size);
    // Note: we do NOT pre-prime search_path here because deadpool-postgres
    // RecyclingMethod::Fast issues DISCARD ALL on checkout which resets search_path.
    // Instead we prefix every SQL statement with the required session setup inline.

    // Sample a principal ID using Cypher so we get a real property value.
    // Each connection needs LOAD 'age' + search_path set before any AGE call.
    let sample_principal = {
        let conn = pool.get().await.context("Failed to get connection for sampling")?;
        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, public;")
            .await
            .context("Failed to configure AGE session for sampling")?;
        let rows = conn
            .query(
                // Cast agtype to text on the SQL side: AGE's agtype is a custom Postgres type
                // that tokio-postgres cannot deserialize as &str/String without an explicit cast.
                // The ::text cast strips the agtype wrapper and returns a plain string.
                "SELECT result::text FROM ag_catalog.cypher('cloud', $$MATCH (n:Principal) RETURN n.id LIMIT 1$$) AS (result agtype)",
                &[],
            )
            .await
            .context("Failed to fetch sample principal via Cypher")?;
        if rows.is_empty() {
            anyhow::bail!("No principals found in graph — was the graph loaded first?");
        }
        let raw: String = rows[0]
            .try_get::<_, String>(0)
            .context("Failed to read principal_id as text")?;
        // agtype string values come back as JSON-quoted strings when cast to text: "value"
        // Strip surrounding quotes if present.
        raw.trim_matches('"').to_string()
    };

    info!(principal = %sample_principal, "Using principal for benchmarks");

    let mut results_md = String::new();
    results_md.push_str("# Graph Backend Spike Results\n\n");
    results_md.push_str(&format!("**Generated:** {}\n\n", OffsetDateTime::now_utc()));
    results_md.push_str(&format!("**Graph Size:** {}\n", size));
    results_md.push_str("**Database:** Postgres+AGE\n");
    results_md.push_str(&format!("**Pool Size:** {}\n", pool_size));
    results_md.push_str(&format!("**Concurrency:** {} tasks × 25 queries\n\n", concurrency));

    results_md.push_str("## Query Latency Percentiles (microseconds)\n\n");
    results_md.push_str("| Query | p50 (µs) | p95 (µs) | p99 (µs) | Concurrent p95 (µs) | Concurrent p99 (µs) | Status |\n");
    results_md.push_str("|-------|----------|----------|----------|---------------------|---------------------|--------|\n");

    let mut verdict_details: Vec<(String, f64, f64, bool)> = Vec::new();
    let mut all_gates_pass = true;

    for (query_name, query_template) in QUERIES {
        // PRODUCTION CAVEAT: sample_principal is substituted verbatim into a
        // PostgreSQL dollar-quoted string. PG dollar-quotes are NOT escapable
        // (no backslash escape); the only terminator is the literal `$$`. For
        // this spike, principal IDs come from a deterministic synthetic
        // generator (`principal_<N>`) — never contain `$$` — so this is safe.
        // Promotion to production (real AWS principal ARNs) MUST escape the
        // value via escape_cypher() AND validate against a strict ID regex
        // like ^[a-zA-Z0-9_:/-]+$ before substitution. Filed as production
        // carryover in docs/system-architecture.md.
        let cypher = query_template.replace("$PRINCIPAL", &sample_principal);

        // Wrap in AGE's cypher() call — no third arg (AGE 1.6 does not require it)
        let sql = format!(
            "SELECT * FROM ag_catalog.cypher('cloud', $${}$$) AS (result agtype)",
            cypher
        );

        // --- Single-threaded warm-up (10 runs) ---
        // Each checkout may be a recycled connection with DISCARD ALL applied,
        // so we must re-establish the AGE session config every time.
        info!(query = query_name, "Warming up (10 runs)");
        for _ in 0..10 {
            let conn = pool.get().await.context("Failed to get connection for warm-up")?;
            conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, public;")
                .await
                .context("Failed to configure AGE session in warm-up")?;
            let _ = conn.query(&sql, &[]).await;
        }

        // --- Single-threaded measurement (100 runs) ---
        // Timer starts AFTER session setup so we measure pure query latency.
        info!(query = query_name, "Measuring single-thread (100 runs)");
        let mut latencies: Vec<f64> = Vec::with_capacity(100);
        for _ in 0..100 {
            let conn = pool.get().await.context("Failed to get connection for measurement")?;
            conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, public;")
                .await
                .context("Failed to configure AGE session in measurement")?;
            let start = Instant::now();
            let _ = conn.query(&sql, &[]).await;
            latencies.push(start.elapsed().as_micros() as f64);
        }

        let p50 = percentile(&latencies, 0.50);
        let p95 = percentile(&latencies, 0.95);
        let p99 = percentile(&latencies, 0.99);

        debug!(
            query = query_name,
            p50 = p50,
            p95 = p95,
            p99 = p99,
            "Single-thread results"
        );

        // --- Tokio concurrent benchmark (concurrent-load measurement) ---
        // 4 tasks × 25 queries = 100 concurrent query executions
        info!(query = query_name, concurrency = concurrency, "Measuring concurrent (tokio) load");
        let concurrent_latencies: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::with_capacity(concurrency * 25)));

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let pool = pool.clone();
            let sql = sql.clone();
            let latencies = concurrent_latencies.clone();

            let handle = tokio::spawn(async move {
                for _ in 0..25 {
                    match pool.get().await {
                        Ok(conn) => {
                            // Re-establish AGE session config after pool checkout
                            if conn
                                .batch_execute("LOAD 'age'; SET search_path = ag_catalog, public;")
                                .await
                                .is_err()
                            {
                                latencies.lock().await.push(10_000_000.0);
                                continue;
                            }
                            let start = Instant::now();
                            let _ = conn.query(&sql, &[]).await;
                            let elapsed = start.elapsed().as_micros() as f64;
                            latencies.lock().await.push(elapsed);
                        }
                        Err(e) => {
                            // Pool exhaustion is a real finding — record it as a
                            // worst-case latency of 10s to surface in p95/p99
                            eprintln!("Pool checkout failed: {}", e);
                            latencies.lock().await.push(10_000_000.0);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let concurrent_latencies_vec = concurrent_latencies.lock().await;
        let concurrent_p95 = percentile(&concurrent_latencies_vec, 0.95);
        let concurrent_p99 = percentile(&concurrent_latencies_vec, 0.99);
        let concurrent_samples = concurrent_latencies_vec.len();

        debug!(
            query = query_name,
            concurrent_p95 = concurrent_p95,
            concurrent_p99 = concurrent_p99,
            samples = concurrent_samples,
            "Concurrent results"
        );
        drop(concurrent_latencies_vec);

        // --- Verdict gate evaluation ---
        let (status, gate_pass) = evaluate_gate(query_name, p95, concurrent_p95);
        if !gate_pass {
            all_gates_pass = false;
        }
        verdict_details.push((query_name.to_string(), p95, concurrent_p95, gate_pass));

        results_md.push_str(&format!(
            "| {} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {} |\n",
            query_name, p50, p95, p99, concurrent_p95, concurrent_p99, status
        ));
    }

    // Emit threshold legend so readers can evaluate borderline numbers
    results_md.push_str("\n**Thresholds:** 6-hop single p95 < 2 000 000 µs (2s) · 6-hop concurrent p95 < 2 500 000 µs (2.5s) · shortest-path single p95 < 3 000 000 µs (3s)\n");

    // --- Verdict section ---
    results_md.push_str("\n## Verdict\n\n");

    let six_hop = verdict_details
        .iter()
        .find(|(n, _, _, _)| n == "03-six-hop-varlen");
    let shortest = verdict_details
        .iter()
        .find(|(n, _, _, _)| n == "04-shortest-path");

    if all_gates_pass {
        results_md.push_str("**GO** — PG+AGE meets all performance thresholds:\n");
        if let Some((_, p95, conc_p95, _)) = six_hop {
            results_md.push_str(&format!(
                "- 6-hop var-len single-thread p95 = {:.0} µs < 2 000 000 µs ✓\n",
                p95
            ));
            results_md.push_str(&format!(
                "- 6-hop var-len concurrent p95 = {:.0} µs < 2 500 000 µs ✓\n",
                conc_p95
            ));
        }
        if let Some((_, p95, _, _)) = shortest {
            results_md.push_str(&format!(
                "- Shortest-path single-thread p95 = {:.0} µs < 3 000 000 µs ✓\n",
                p95
            ));
        }
        results_md.push_str("\nPG+AGE is suitable as the graph backend. Proceed with production schema implementation.\n");
    } else {
        results_md.push_str("**NO-GO** — PG+AGE fails one or more performance gates:\n\n");
        for (query, p95, conc_p95, passed) in &verdict_details {
            if !passed {
                results_md.push_str(&format!(
                    "- {} single-thread p95 = {:.0} µs  concurrent p95 = {:.0} µs ✗\n",
                    query, p95, conc_p95
                ));
            }
        }
        results_md.push_str(
            "\nEscalate to user for decision: continue with PG+AGE + Trendyol fixed-depth UNION workaround, or pivot to Vela-Kuzu.\n",
        );
    }

    results_md.push_str("\n## Notes\n\n");
    results_md.push_str("- Single-thread: 10 warm-up + 100 measurement runs per query.\n");
    results_md.push_str("- Concurrent: 4 tokio tasks × 25 queries = 100 total query executions.\n");
    results_md.push_str("- Pool exhaustion events recorded as 10 000 000 µs to surface in p95/p99.\n");
    results_md.push_str("- AGE version: 1.6.0 · Postgres: 16.10.\n");

    info!("Benchmarks complete");
    Ok(results_md)
}

/// Evaluate the per-query verdict gate.
/// Returns (display status string, pass bool).
fn evaluate_gate(query_name: &str, single_p95: f64, concurrent_p95: f64) -> (String, bool) {
    match query_name {
        "03-six-hop-varlen" => {
            let single_ok = single_p95 < 2_000_000.0;
            let concurrent_ok = concurrent_p95 < 2_500_000.0;
            let borderline = (!single_ok && single_p95 < 2_400_000.0)
                || (!concurrent_ok && concurrent_p95 < 3_000_000.0);
            if single_ok && concurrent_ok {
                ("GO ✓".to_string(), true)
            } else if borderline {
                ("BORDERLINE ⚠".to_string(), false)
            } else {
                ("NO-GO ✗".to_string(), false)
            }
        }
        "04-shortest-path" => {
            let ok = single_p95 < 3_000_000.0;
            let borderline = !ok && single_p95 < 3_600_000.0;
            if ok {
                ("GO ✓".to_string(), true)
            } else if borderline {
                ("BORDERLINE ⚠".to_string(), false)
            } else {
                ("NO-GO ✗".to_string(), false)
            }
        }
        _ => ("—".to_string(), true),
    }
}

pub fn verdict_gate(results: &str) -> i32 {
    if results.contains("**GO**") && !results.contains("**NO-GO**") {
        info!("Verdict: GO. Exit code 0.");
        0
    } else if results.contains("**NO-GO**") {
        info!("Verdict: NO-GO. Exit code 1.");
        1
    } else {
        info!("Verdict: BORDERLINE or UNCLEAR. Exit code 2.");
        2
    }
}

fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((p * (sorted.len() - 1) as f64).ceil()) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── percentile() ─────────────────────────────────────────────────────────

    /// Empty slice returns 0.0 (documented behaviour; not NaN, not panic).
    #[test]
    fn percentile_empty_returns_zero() {
        assert_eq!(percentile(&[], 0.50), 0.0);
        assert_eq!(percentile(&[], 0.95), 0.0);
        assert_eq!(percentile(&[], 0.99), 0.0);
    }

    /// Single sample: p50 == p95 == p99 == that sample.
    #[test]
    fn percentile_single_sample() {
        let v = vec![42.0];
        assert_eq!(percentile(&v, 0.50), 42.0);
        assert_eq!(percentile(&v, 0.95), 42.0);
        assert_eq!(percentile(&v, 0.99), 42.0);
    }

    /// Sorted and unsorted input must produce the same result.
    #[test]
    fn percentile_sorted_vs_unsorted_same_result() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let unsorted = vec![10.0, 3.0, 7.0, 1.0, 5.0, 9.0, 2.0, 6.0, 4.0, 8.0];
        assert_eq!(
            percentile(&sorted, 0.50),
            percentile(&unsorted, 0.50)
        );
        assert_eq!(
            percentile(&sorted, 0.95),
            percentile(&unsorted, 0.95)
        );
        assert_eq!(
            percentile(&sorted, 0.99),
            percentile(&unsorted, 0.99)
        );
    }

    /// p99 of 100 samples: formula is ceil(0.99 * 99) = ceil(98.01) = 99.
    /// Index 99 in 0-based sorted array of 100 elements is the last element (100.0).
    #[test]
    fn percentile_p99_of_100_samples_picks_last() {
        // Samples 1..=100; sorted order is 1.0..100.0.
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        // ceil(0.99 * 99) = ceil(98.01) = 99 → sorted[99] = 100.0
        assert_eq!(percentile(&v, 0.99), 100.0);
    }

    /// p95 of 100 samples: ceil(0.95 * 99) = ceil(94.05) = 95 → sorted[95] = 96.0
    #[test]
    fn percentile_p95_of_100_samples() {
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(percentile(&v, 0.95), 96.0);
    }

    /// Pool-exhaustion sentinel (10_000_000 µs) surfaces in p95/p99 when present.
    /// If 10% of samples are sentinel, they appear at the top of the distribution.
    #[test]
    fn percentile_pool_exhaustion_sentinel_surfaces_in_p99() {
        // 90 normal samples (1–90 µs) + 10 sentinel (10_000_000 µs).
        let mut v: Vec<f64> = (1..=90).map(|x| x as f64).collect();
        v.extend(std::iter::repeat(10_000_000.0).take(10));
        // p99: ceil(0.99 * 99) = 99 → sorted[99] is one of the sentinels.
        assert_eq!(percentile(&v, 0.99), 10_000_000.0);
        // p95: ceil(0.95 * 99) = 95 → sorted[95] is also a sentinel (index 90–99 are sentinels).
        assert_eq!(percentile(&v, 0.95), 10_000_000.0);
        // p50 is within the normal range (not a sentinel).
        assert!(percentile(&v, 0.50) < 100.0);
    }

    /// p50 of an even-length slice uses ceil convention (not floor or midpoint).
    #[test]
    fn percentile_p50_ceil_convention() {
        // 4 elements: [1, 2, 3, 4]; ceil(0.5 * 3) = ceil(1.5) = 2 → sorted[2] = 3.0
        let v = vec![4.0, 1.0, 3.0, 2.0];
        assert_eq!(percentile(&v, 0.50), 3.0);
    }

    // ── evaluate_gate() ───────────────────────────────────────────────────────

    #[test]
    fn evaluate_gate_six_hop_go() {
        let (status, pass) = evaluate_gate("03-six-hop-varlen", 1_000_000.0, 1_500_000.0);
        assert!(pass);
        assert!(status.contains("GO"));
    }

    #[test]
    fn evaluate_gate_six_hop_borderline_single() {
        // single_p95 = 2_200_000 (between 2_000_000 and 2_400_000) → BORDERLINE
        let (status, pass) = evaluate_gate("03-six-hop-varlen", 2_200_000.0, 1_500_000.0);
        assert!(!pass);
        assert!(status.contains("BORDERLINE"));
    }

    #[test]
    fn evaluate_gate_six_hop_borderline_concurrent() {
        // concurrent_p95 = 2_700_000 (between 2_500_000 and 3_000_000) → BORDERLINE
        let (status, pass) = evaluate_gate("03-six-hop-varlen", 1_000_000.0, 2_700_000.0);
        assert!(!pass);
        assert!(status.contains("BORDERLINE"));
    }

    #[test]
    fn evaluate_gate_six_hop_no_go() {
        // Both fail and beyond borderline thresholds
        let (status, pass) = evaluate_gate("03-six-hop-varlen", 3_000_000.0, 4_000_000.0);
        assert!(!pass);
        assert!(status.contains("NO-GO"));
    }

    #[test]
    fn evaluate_gate_shortest_path_go() {
        let (status, pass) = evaluate_gate("04-shortest-path", 2_000_000.0, 0.0);
        assert!(pass);
        assert!(status.contains("GO"));
    }

    #[test]
    fn evaluate_gate_shortest_path_borderline() {
        // single_p95 = 3_200_000 (between 3_000_000 and 3_600_000) → BORDERLINE
        let (status, pass) = evaluate_gate("04-shortest-path", 3_200_000.0, 0.0);
        assert!(!pass);
        assert!(status.contains("BORDERLINE"));
    }

    #[test]
    fn evaluate_gate_shortest_path_no_go() {
        let (status, pass) = evaluate_gate("04-shortest-path", 4_000_000.0, 0.0);
        assert!(!pass);
        assert!(status.contains("NO-GO"));
    }

    #[test]
    fn evaluate_gate_other_queries_always_pass() {
        // Queries other than 03/04 are always "—" / pass=true regardless of latency.
        for name in &["01-one-hop", "02-three-hop", "05-subgraph"] {
            let (status, pass) = evaluate_gate(name, 99_999_999.0, 99_999_999.0);
            assert!(pass, "Expected pass for {}", name);
            assert_eq!(status, "—");
        }
    }

    // ── verdict_gate() ────────────────────────────────────────────────────────

    #[test]
    fn verdict_gate_go_returns_zero() {
        let md = "## Verdict\n\n**GO** — PG+AGE meets all performance thresholds:\n";
        assert_eq!(verdict_gate(md), 0);
    }

    #[test]
    fn verdict_gate_no_go_returns_one() {
        let md = "## Verdict\n\n**NO-GO** — PG+AGE fails one or more performance gates:\n";
        assert_eq!(verdict_gate(md), 1);
    }

    /// When both **GO** and **NO-GO** appear (e.g. combined multi-size output), NO-GO wins.
    #[test]
    fn verdict_gate_both_go_and_no_go_returns_one() {
        let md = "**GO** something\n**NO-GO** something else";
        assert_eq!(verdict_gate(md), 1);
    }

    #[test]
    fn verdict_gate_borderline_returns_two() {
        let md = "## Verdict\n\nBORDERLINE results detected.\n";
        assert_eq!(verdict_gate(md), 2);
    }

    #[test]
    fn verdict_gate_empty_returns_two() {
        assert_eq!(verdict_gate(""), 2);
    }
}
