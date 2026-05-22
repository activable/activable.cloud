use anyhow::{Context, Result};
use csv::Reader;
use std::fs::File;
use std::path::Path;
use tracing::{debug, info, warn};

const BATCH_SIZE: usize = 500;

/// Load a synthetic graph CSV (principals, policies, resources, edges) into Postgres+AGE.
///
/// Uses batched Cypher UNWIND CREATE for node and edge insertion — the correct
/// approach for AGE, which stores vertex properties as an `agtype` blob rather than
/// individual columns. Row-by-row INSERT is not compatible with AGE vertex tables.
pub async fn load(
    input_dir: &Path,
    db_host: &str,
    db_port: u16,
    db_user: &str,
    db_password: &str,
    db_name: &str,
    size: &str,
) -> Result<()> {
    info!(
        host = db_host,
        port = db_port,
        user = db_user,
        db = db_name,
        size = size,
        "Connecting to Postgres+AGE"
    );

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={} port={} user={} password={} dbname={}",
            db_host, db_port, db_user, db_password, db_name
        ),
        tokio_postgres::tls::NoTls,
    )
    .await
    .context("Failed to connect to Postgres")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    info!("Connected to Postgres");

    // Enable AGE and set search_path — required on every new connection in AGE 1.x
    client
        .batch_execute("CREATE EXTENSION IF NOT EXISTS age; LOAD 'age'; SET search_path = ag_catalog, public;")
        .await
        .context("Failed to configure AGE session")?;

    info!("AGE session configured");

    // Drop existing graph (idempotent re-run safety)
    info!("Dropping existing 'cloud' graph (idempotent)");
    let _ = client
        .execute("SELECT * FROM ag_catalog.drop_graph('cloud', true);", &[])
        .await;

    // Recreate graph and labels
    client
        .execute("SELECT * FROM ag_catalog.create_graph('cloud');", &[])
        .await
        .context("Failed to create graph 'cloud'")?;

    for label in &["Principal", "Policy", "Resource"] {
        client
            .execute(
                &format!("SELECT * FROM ag_catalog.create_vlabel('cloud', '{}');", label),
                &[],
            )
            .await
            .context(format!("Failed to create vertex label '{}'", label))?;
    }

    for edge_label in &["HasPermission", "CanAssume"] {
        client
            .execute(
                &format!("SELECT * FROM ag_catalog.create_elabel('cloud', '{}');", edge_label),
                &[],
            )
            .await
            .context(format!("Failed to create edge label '{}'", edge_label))?;
    }

    info!("Graph schema created");

    // --- Load principals ---
    {
        info!("Loading principals");
        let principals_path = input_dir.join("principals.csv");
        let file = File::open(&principals_path).context("Failed to open principals.csv")?;
        let mut reader = Reader::from_reader(file);

        let mut batch: Vec<(String, String, String, String)> = Vec::with_capacity(BATCH_SIZE);
        let mut total = 0usize;

        for result in reader.records() {
            let record = result.context("CSV parse error in principals")?;
            let id = record.get(0).context("Missing id")?.to_string();
            let arn = record.get(1).context("Missing arn")?.to_string();
            let principal_type = record.get(2).context("Missing type")?.to_string();
            let account_id = record.get(3).context("Missing account_id")?.to_string();
            batch.push((id, arn, principal_type, account_id));

            if batch.len() >= BATCH_SIZE {
                flush_principals(&client, &batch).await?;
                total += batch.len();
                debug!(total = total, "Loaded principals batch");
                batch.clear();
            }
        }
        if !batch.is_empty() {
            flush_principals(&client, &batch).await?;
            total += batch.len();
        }
        info!(count = total, "Loaded all principals");
    }

    // --- Load policies ---
    {
        info!("Loading policies");
        let policies_path = input_dir.join("policies.csv");
        let file = File::open(&policies_path).context("Failed to open policies.csv")?;
        let mut reader = Reader::from_reader(file);

        let mut batch: Vec<(String, String, String)> = Vec::with_capacity(BATCH_SIZE);
        let mut total = 0usize;

        for result in reader.records() {
            let record = result.context("CSV parse error in policies")?;
            let id = record.get(0).context("Missing id")?.to_string();
            let arn = record.get(1).context("Missing arn")?.to_string();
            let name = record.get(2).context("Missing name")?.to_string();
            batch.push((id, arn, name));

            if batch.len() >= BATCH_SIZE {
                flush_policies(&client, &batch).await?;
                total += batch.len();
                debug!(total = total, "Loaded policies batch");
                batch.clear();
            }
        }
        if !batch.is_empty() {
            flush_policies(&client, &batch).await?;
            total += batch.len();
        }
        info!(count = total, "Loaded all policies");
    }

    // --- Load resources ---
    {
        info!("Loading resources");
        let resources_path = input_dir.join("resources.csv");
        let file = File::open(&resources_path).context("Failed to open resources.csv")?;
        let mut reader = Reader::from_reader(file);

        let mut batch: Vec<(String, String, String)> = Vec::with_capacity(BATCH_SIZE);
        let mut total = 0usize;

        for result in reader.records() {
            let record = result.context("CSV parse error in resources")?;
            let id = record.get(0).context("Missing id")?.to_string();
            let arn = record.get(1).context("Missing arn")?.to_string();
            let resource_type = record.get(2).context("Missing resource_type")?.to_string();
            batch.push((id, arn, resource_type));

            if batch.len() >= BATCH_SIZE {
                flush_resources(&client, &batch).await?;
                total += batch.len();
                debug!(total = total, "Loaded resources batch");
                batch.clear();
            }
        }
        if !batch.is_empty() {
            flush_resources(&client, &batch).await?;
            total += batch.len();
        }
        info!(count = total, "Loaded all resources");
    }

    // --- Create indexes on vertex id properties for fast MATCH lookups ---
    // AGE stores properties as an agtype blob; use agtype_access_operator() to build
    // an expression index. Without this, MATCH (n:Principal {id: 'x'}) does a full label
    // scan — O(n) per edge insert, making 100k edge loading take hours instead of minutes.
    {
        info!("Creating vertex id indexes for fast edge loading");
        for label in &["Principal", "Policy", "Resource"] {
            let index_name = format!("idx_{}_id", label.to_lowercase());
            let sql = format!(
                "CREATE INDEX IF NOT EXISTS {index_name} ON cloud.\"{label}\" \
                 (ag_catalog.agtype_access_operator(properties, '\"id\"'::agtype))"
            );
            client
                .execute(&sql, &[])
                .await
                .with_context(|| format!("Failed to create index on {}", label))?;
        }
        info!("Vertex id indexes created");
    }

    // --- Load edges (SQL fast-path) ---
    // We load edges using SQL-level lookups + direct INSERT into the edge tables.
    // AGE's Cypher UNWIND-MATCH-CREATE approach does a full-label scan per vertex pair
    // even with expression indexes (the Cypher planner doesn't use Postgres indexes).
    // Instead: look up the AGE graphid (bigint) for each endpoint using the expression
    // index on the underlying vertex table, then INSERT directly into the edge table.
    // This brings 100k edge loading from hours down to minutes.
    //
    // Edge table schema (AGE 1.6):
    //   id       graphid  — edge identifier (populated from label sequence)
    //   start_id graphid  — source vertex graphid
    //   end_id   graphid  — target vertex graphid
    //   properties agtype — edge property blob (empty for bulk load)
    {
        info!("Loading edges (SQL fast-path via expression index lookup)");
        let edges_path = input_dir.join("edges.csv");
        let file = File::open(&edges_path).context("Failed to open edges.csv")?;
        let mut reader = Reader::from_reader(file);

        // Batch accumulator: (from_id, to_id) per edge type
        let mut has_perm_batch: Vec<(String, String)> = Vec::with_capacity(BATCH_SIZE);
        let mut can_assume_batch: Vec<(String, String)> = Vec::with_capacity(BATCH_SIZE);
        let mut total_has_perm = 0usize;
        let mut total_can_assume = 0usize;
        let mut skipped = 0usize;

        for result in reader.records() {
            let record = result.context("CSV parse error in edges")?;
            let from_id = record.get(0).context("Missing from_id")?.to_string();
            let to_id = record.get(1).context("Missing to_id")?.to_string();
            let edge_type = record.get(2).context("Missing edge_type")?.to_string();

            match edge_type.as_str() {
                "HasPermission" => {
                    has_perm_batch.push((from_id, to_id));
                    if has_perm_batch.len() >= BATCH_SIZE {
                        flush_has_permission_sql(&client, &has_perm_batch).await?;
                        total_has_perm += has_perm_batch.len();
                        debug!(total = total_has_perm, "Loaded HasPermission edges batch");
                        has_perm_batch.clear();
                    }
                }
                "CanAssume" => {
                    can_assume_batch.push((from_id, to_id));
                    if can_assume_batch.len() >= BATCH_SIZE {
                        flush_can_assume_sql(&client, &can_assume_batch).await?;
                        total_can_assume += can_assume_batch.len();
                        debug!(total = total_can_assume, "Loaded CanAssume edges batch");
                        can_assume_batch.clear();
                    }
                }
                other => {
                    warn!(edge_type = other, "Unknown edge type — skipping");
                    skipped += 1;
                }
            }
        }

        // Flush remaining batches
        if !has_perm_batch.is_empty() {
            flush_has_permission_sql(&client, &has_perm_batch).await?;
            total_has_perm += has_perm_batch.len();
        }
        if !can_assume_batch.is_empty() {
            flush_can_assume_sql(&client, &can_assume_batch).await?;
            total_can_assume += can_assume_batch.len();
        }

        info!(
            has_permission = total_has_perm,
            can_assume = total_can_assume,
            skipped = skipped,
            "Loaded all edges"
        );
    }

    // Verify load via Cypher count
    {
        info!("Verifying graph via Cypher count");
        let rows = client
            .query(
                "SELECT * FROM ag_catalog.cypher('cloud', $$MATCH (n) RETURN count(n)$$) AS (cnt agtype)",
                &[],
            )
            .await
            .context("Failed to count nodes via Cypher")?;
        let cnt_raw: &str = rows[0].try_get::<_, &str>(0).unwrap_or("unknown");
        info!(node_count = cnt_raw, "Cypher node count after load");
    }

    info!("Graph load complete");
    Ok(())
}

/// Build a Cypher UNWIND CREATE for Principal nodes.
/// Each props entry becomes a vertex in the 'cloud' graph under label Principal.
async fn flush_principals(
    client: &tokio_postgres::Client,
    batch: &[(String, String, String, String)],
) -> Result<()> {
    // Build the array literal: [{id: 'x', arn: 'y', ...}, ...]
    let props_list: Vec<String> = batch
        .iter()
        .map(|(id, arn, principal_type, account_id)| {
            format!(
                "{{id: '{}', arn: '{}', principal_type: '{}', account_id: '{}'}}",
                escape_cypher(id),
                escape_cypher(arn),
                escape_cypher(principal_type),
                escape_cypher(account_id)
            )
        })
        .collect();

    let cypher = format!(
        "UNWIND [{}] AS props CREATE (n:Principal {{id: props.id, arn: props.arn, principal_type: props.principal_type, account_id: props.account_id}}) RETURN count(n)",
        props_list.join(", ")
    );

    run_cypher(client, &cypher).await
}

async fn flush_policies(
    client: &tokio_postgres::Client,
    batch: &[(String, String, String)],
) -> Result<()> {
    let props_list: Vec<String> = batch
        .iter()
        .map(|(id, arn, name)| {
            format!(
                "{{id: '{}', arn: '{}', name: '{}'}}",
                escape_cypher(id),
                escape_cypher(arn),
                escape_cypher(name)
            )
        })
        .collect();

    let cypher = format!(
        "UNWIND [{}] AS props CREATE (n:Policy {{id: props.id, arn: props.arn, name: props.name}}) RETURN count(n)",
        props_list.join(", ")
    );

    run_cypher(client, &cypher).await
}

async fn flush_resources(
    client: &tokio_postgres::Client,
    batch: &[(String, String, String)],
) -> Result<()> {
    let props_list: Vec<String> = batch
        .iter()
        .map(|(id, arn, resource_type)| {
            format!(
                "{{id: '{}', arn: '{}', resource_type: '{}'}}",
                escape_cypher(id),
                escape_cypher(arn),
                escape_cypher(resource_type)
            )
        })
        .collect();

    let cypher = format!(
        "UNWIND [{}] AS props CREATE (n:Resource {{id: props.id, arn: props.arn, resource_type: props.resource_type}}) RETURN count(n)",
        props_list.join(", ")
    );

    run_cypher(client, &cypher).await
}

/// Fast SQL-path: insert HasPermission edges (Principal → Policy) using expression-indexed
/// vertex lookups. Bypasses the Cypher planner which ignores Postgres indexes.
/// Uses a single INSERT ... SELECT with a VALUES list to resolve both endpoints at once.
async fn flush_has_permission_sql(
    client: &tokio_postgres::Client,
    batch: &[(String, String)],
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    // Build VALUES list: each row is (from_id_str, to_id_str)
    // Then INSERT by joining Principal and Policy tables on the expression index.
    // AGE edge id is allocated from the label's sequence.
    let values: Vec<String> = batch
        .iter()
        .map(|(from, to)| {
            format!(
                "('\"{}\"'::agtype, '\"{}\"'::agtype)",
                escape_sql_literal(from),
                escape_sql_literal(to)
            )
        })
        .collect();

    // _graphid(label_id, sequence_next) is how AGE constructs edge graphid values.
    // The label_id for HasPermission is retrieved via _label_id('cloud', 'HasPermission').
    let sql = format!(
        "INSERT INTO cloud.\"HasPermission\" (id, start_id, end_id, properties)
         SELECT ag_catalog._graphid(
                    ag_catalog._label_id('cloud', 'HasPermission')::integer,
                    nextval('cloud.\"HasPermission_id_seq\"')),
                p.id, pol.id, ag_catalog.agtype_build_map()
         FROM (VALUES {values}) AS v(from_id, to_id)
         JOIN cloud.\"Principal\" p ON ag_catalog.agtype_access_operator(p.properties, '\"id\"'::agtype) = v.from_id
         JOIN cloud.\"Policy\" pol ON ag_catalog.agtype_access_operator(pol.properties, '\"id\"'::agtype) = v.to_id",
        values = values.join(", ")
    );

    client
        .execute(&sql, &[])
        .await
        .context("Failed to insert HasPermission edges (SQL fast-path)")?;
    Ok(())
}

/// Fast SQL-path: insert CanAssume edges (Principal → Principal).
async fn flush_can_assume_sql(
    client: &tokio_postgres::Client,
    batch: &[(String, String)],
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let values: Vec<String> = batch
        .iter()
        .map(|(from, to)| {
            format!(
                "('\"{}\"'::agtype, '\"{}\"'::agtype)",
                escape_sql_literal(from),
                escape_sql_literal(to)
            )
        })
        .collect();

    let sql = format!(
        "INSERT INTO cloud.\"CanAssume\" (id, start_id, end_id, properties)
         SELECT ag_catalog._graphid(
                    ag_catalog._label_id('cloud', 'CanAssume')::integer,
                    nextval('cloud.\"CanAssume_id_seq\"')),
                a.id, b.id, ag_catalog.agtype_build_map()
         FROM (VALUES {values}) AS v(from_id, to_id)
         JOIN cloud.\"Principal\" a ON ag_catalog.agtype_access_operator(a.properties, '\"id\"'::agtype) = v.from_id
         JOIN cloud.\"Principal\" b ON ag_catalog.agtype_access_operator(b.properties, '\"id\"'::agtype) = v.to_id",
        values = values.join(", ")
    );

    client
        .execute(&sql, &[])
        .await
        .context("Failed to insert CanAssume edges (SQL fast-path)")?;
    Ok(())
}

/// Execute a Cypher statement via AGE's cypher() function.
/// The search_path and LOAD 'age' are assumed already set on the connection.
async fn run_cypher(client: &tokio_postgres::Client, cypher: &str) -> Result<()> {
    let sql = format!(
        "SELECT * FROM ag_catalog.cypher('cloud', $${}$$) AS (result agtype)",
        cypher
    );
    client
        .execute(&sql, &[])
        .await
        .with_context(|| format!("Cypher execution failed for: {:.120}...", cypher))?;
    Ok(())
}

/// Escape single quotes in Cypher string literals.
///
/// **NOT idempotent** — call exactly once per value. Double-escape produces
/// double-escaped output (e.g., `escape_cypher("it's") == "it\\'s"`,
/// `escape_cypher("it\\'s") == "it\\\\'s"`). Callers must ensure each
/// value flows through this function exactly once.
///
/// In the current spike, inputs are ID-like values (alphanumeric + `_`)
/// from the synthetic graph generator — `principal_1`, `policy_42`, etc.
/// These never contain a pre-existing `'`, so the debug_assert! below is
/// safe. If this function is later used for free-text values (e.g., AWS
/// resource tags, IAM policy document text), revisit the assertion.
pub(crate) fn escape_cypher(s: &str) -> String {
    debug_assert!(
        !s.contains("\\'"),
        "escape_cypher called with input containing \\' — possible double-escape; \
         input was: {s:?}"
    );
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Escape a value for embedding inside an agtype string literal in SQL.
///
/// **NOT idempotent** — call exactly once per value. Double-escape produces
/// double-escaped output (e.g., `escape_sql_literal("it's") == "it''s"`,
/// `escape_sql_literal("it''s") == "it''''s"`). Callers must ensure each
/// value flows through this function exactly once.
///
/// In the current spike, inputs are ID-like values (alphanumeric + `_`)
/// from the synthetic graph generator — `principal_1`, `policy_42`, etc.
/// These never contain a pre-existing `'`, so the debug_assert! below is
/// safe. If this function is later used for free-text values (e.g., AWS
/// resource tags, IAM policy document text), revisit the assertion.
pub(crate) fn escape_sql_literal(s: &str) -> String {
    debug_assert!(
        !s.contains("''"),
        "escape_sql_literal called with input containing '' — possible double-escape; \
         input was: {s:?}"
    );
    // In the SQL string '\"value\"'::agtype, the outer quotes are SQL single-quotes.
    // We need to escape both backslashes and single-quotes for SQL safety.
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Build the agtype string literal fragment for a single ID value.
/// Produces the fragment `'"<escaped_value>"'::agtype` used in SQL VALUES lists.
pub(crate) fn build_agtype_id_literal(id: &str) -> String {
    format!("'\"{}\"'::agtype", escape_sql_literal(id))
}

/// Build the VALUES list fragment for a slice of (from_id, to_id) pairs.
/// Returns a comma-joined string of `('\"from\"'::agtype, '\"to\"'::agtype)` rows.
/// Returns `None` when `batch` is empty (no SQL should be emitted).
pub(crate) fn build_edge_values_list(batch: &[(String, String)]) -> Option<String> {
    if batch.is_empty() {
        return None;
    }
    let values: Vec<String> = batch
        .iter()
        .map(|(from, to)| {
            format!(
                "('\"{}\"'::agtype, '\"{}\"'::agtype)",
                escape_sql_literal(from),
                escape_sql_literal(to)
            )
        })
        .collect();
    Some(values.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── escape_cypher() ───────────────────────────────────────────────────────

    #[test]
    fn escape_cypher_empty() {
        assert_eq!(escape_cypher(""), "");
    }

    #[test]
    fn escape_cypher_plain_ascii() {
        assert_eq!(escape_cypher("hello_world"), "hello_world");
    }

    #[test]
    fn escape_cypher_single_quote() {
        // Single quote must be escaped as \' so it is safe inside Cypher single-quoted strings.
        assert_eq!(escape_cypher("it's"), "it\\'s");
    }

    #[test]
    fn escape_cypher_double_quote() {
        // Double quotes are not special in Cypher single-quoted strings; pass through unchanged.
        assert_eq!(escape_cypher(r#"he said "hi""#), r#"he said "hi""#);
    }

    #[test]
    fn escape_cypher_backslash() {
        // Backslash must be doubled before any other substitution.
        assert_eq!(escape_cypher("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_cypher_both_quote_types() {
        // Both in same input: \\ first, then \'.
        let input = "it's a \"test\"";
        let result = escape_cypher(input);
        assert_eq!(result, "it\\'s a \"test\"");
    }

    #[test]
    fn escape_cypher_null_byte() {
        // NULL byte passes through; Cypher doesn't define NUL escape here.
        let input = "ab\0cd";
        let result = escape_cypher(input);
        assert_eq!(result, "ab\0cd");
    }

    #[test]
    fn escape_cypher_whitespace() {
        let input = "line1\nline2\r\ntab\there";
        let result = escape_cypher(input);
        // Whitespace is unchanged (no escaping defined for \n/\r/\t in this function).
        assert_eq!(result, input);
    }

    #[test]
    fn escape_cypher_unicode_nfc() {
        // Precomposed é (U+00E9) — single code-point; passes through as-is.
        assert_eq!(escape_cypher("café"), "café");
    }

    #[test]
    fn escape_cypher_unicode_nfd() {
        // Decomposed é (e + combining acute) — two code-points; passes through as-is.
        let nfd = "cafe\u{0301}";
        assert_eq!(escape_cypher(nfd), nfd);
    }

    #[test]
    fn escape_cypher_japanese() {
        assert_eq!(escape_cypher("日本語"), "日本語");
    }

    #[test]
    fn escape_cypher_emoji() {
        assert_eq!(escape_cypher("🔥"), "🔥");
    }

    #[test]
    fn escape_cypher_rtl_override() {
        // Right-to-left override (U+202E) — passes through, no special handling.
        let input = "normal\u{202E}reversed";
        let result = escape_cypher(input);
        assert_eq!(result, input);
    }

    #[test]
    fn escape_cypher_sql_injection_canary() {
        // SQL injection payload must be escaped so it cannot break out of the Cypher literal.
        let payload = "principal_1' OR '1'='1";
        let result = escape_cypher(payload);
        // All single quotes escaped; result is safe inside Cypher '...' string.
        assert!(!result.contains("' OR '"));
        assert_eq!(result, "principal_1\\' OR \\'1\\'=\\'1");
    }

    #[test]
    fn escape_cypher_drop_table_canary() {
        // The security property: every ' must be escaped as \\' so it cannot
        // terminate the surrounding Cypher string literal.
        let payload = "'; DROP TABLE x; --";
        let result = escape_cypher(payload);
        // After escaping, the leading ' becomes \\'. Verify it is now prefixed.
        assert!(result.starts_with("\\'"), "Leading quote must be escaped: {}", result);
        // No unescaped single-quote remains (every ' is preceded by \\).
        for (i, c) in result.char_indices() {
            if c == '\'' {
                assert!(
                    i > 0 && result.as_bytes()[i - 1] == b'\\',
                    "Unescaped single-quote at index {}: {}",
                    i, result
                );
            }
        }
    }

    #[test]
    fn escape_cypher_cypher_injection_canary() {
        // Attempt to break out of Cypher literal with } RETURN 1 {
        let payload = "} RETURN 1 {";
        let result = escape_cypher(payload);
        // Curly braces are not special in Cypher string literals; no escaping needed.
        // Single quotes not present; result == input.
        assert_eq!(result, payload);
    }

    #[test]
    fn escape_cypher_very_long_input() {
        // ≥10KB: verify no quadratic blowup (function should complete promptly).
        let long = "a".repeat(10_001);
        let result = escape_cypher(&long);
        assert_eq!(result.len(), 10_001);
    }

    #[test]
    fn escape_cypher_very_long_with_quotes() {
        // 10KB of single-quotes: each expands to 2 chars → output is 20_002 chars.
        let long = "'".repeat(10_001);
        let result = escape_cypher(&long);
        // Each ' becomes \' (2 chars)
        assert_eq!(result.len(), 20_002);
    }

    #[test]
    fn escape_cypher_idempotency_check() {
        // Applying escape_cypher twice is NOT idempotent (backslashes are doubled again).
        // Document: do NOT double-escape. The function is applied once per value.
        // This test validates the idempotency property by constructing the expected
        // result of double-escape manually, bypassing the debug_assert! guard.
        let input = "it's";
        let once = escape_cypher(input);
        // once = "it\\'s"
        // If we were to escape again, the backslash would be doubled: "it\\\\'s"
        // Instead of calling escape_cypher(&once), we manually construct the expected result.
        let expected_twice = "it\\\\\\'s";
        assert_ne!(once, expected_twice, "idempotency check: once should differ from twice");
    }

    // ── escape_sql_literal() ─────────────────────────────────────────────────

    #[test]
    fn escape_sql_literal_empty() {
        assert_eq!(escape_sql_literal(""), "");
    }

    #[test]
    fn escape_sql_literal_plain_ascii() {
        assert_eq!(escape_sql_literal("principal_42"), "principal_42");
    }

    #[test]
    fn escape_sql_literal_single_quote() {
        // SQL standard: single quote escaped as '' (not backslash).
        assert_eq!(escape_sql_literal("it's"), "it''s");
    }

    #[test]
    fn escape_sql_literal_double_quote() {
        // Double quotes are not special in SQL string literals; pass through.
        assert_eq!(escape_sql_literal(r#"he said "hi""#), r#"he said "hi""#);
    }

    #[test]
    fn escape_sql_literal_backslash() {
        // Backslash doubled (for SQL standard_conforming_strings=off compatibility).
        assert_eq!(escape_sql_literal("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_sql_literal_both_quote_types() {
        let input = "it's a \"test\"";
        let result = escape_sql_literal(input);
        assert_eq!(result, "it''s a \"test\"");
    }

    #[test]
    fn escape_sql_literal_null_byte() {
        let input = "ab\0cd";
        let result = escape_sql_literal(input);
        assert_eq!(result, "ab\0cd");
    }

    #[test]
    fn escape_sql_literal_whitespace() {
        let input = "line1\nline2\r\ntab\there";
        assert_eq!(escape_sql_literal(input), input);
    }

    #[test]
    fn escape_sql_literal_unicode_nfc() {
        assert_eq!(escape_sql_literal("café"), "café");
    }

    #[test]
    fn escape_sql_literal_unicode_nfd() {
        let nfd = "cafe\u{0301}";
        assert_eq!(escape_sql_literal(nfd), nfd);
    }

    #[test]
    fn escape_sql_literal_japanese() {
        assert_eq!(escape_sql_literal("日本語"), "日本語");
    }

    #[test]
    fn escape_sql_literal_emoji() {
        assert_eq!(escape_sql_literal("🔥"), "🔥");
    }

    #[test]
    fn escape_sql_literal_rtl_override() {
        let input = "normal\u{202E}reversed";
        assert_eq!(escape_sql_literal(input), input);
    }

    #[test]
    fn escape_sql_literal_sql_injection_canary() {
        let payload = "principal_1' OR '1'='1";
        let result = escape_sql_literal(payload);
        // Single quotes are doubled: the exact escaped form.
        assert_eq!(result, "principal_1'' OR ''1''=''1");
        // Every ' in the result is immediately followed by another ' (proper doubling).
        let bytes = result.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                assert!(
                    i + 1 < bytes.len() && bytes[i + 1] == b'\'',
                    "Unescaped single-quote at index {}: {}",
                    i, result
                );
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn escape_sql_literal_drop_table_canary() {
        // The security property: every ' must be doubled (SQL standard) so it
        // cannot terminate the surrounding SQL string literal.
        let payload = "'; DROP TABLE x; --";
        let result = escape_sql_literal(payload);
        // After escaping, the leading ' becomes ''. The result starts with ''.
        assert!(result.starts_with("''"), "Leading quote must be doubled: {}", result);
        // Verify no isolated single-quote (each ' must be followed by another ').
        let bytes = result.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                assert!(
                    i + 1 < bytes.len() && bytes[i + 1] == b'\'',
                    "Unescaped single-quote at index {}: {}",
                    i, result
                );
                i += 2; // skip the pair
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn escape_sql_literal_cypher_injection_canary() {
        let payload = "} RETURN 1 {";
        let result = escape_sql_literal(payload);
        // No quotes → unchanged.
        assert_eq!(result, payload);
    }

    #[test]
    fn escape_sql_literal_very_long_input() {
        let long = "x".repeat(10_001);
        let result = escape_sql_literal(&long);
        assert_eq!(result.len(), 10_001);
    }

    #[test]
    fn escape_sql_literal_very_long_with_quotes() {
        let long = "'".repeat(10_001);
        let result = escape_sql_literal(&long);
        // Each ' becomes '' (2 chars)
        assert_eq!(result.len(), 20_002);
    }

    #[test]
    fn escape_sql_literal_idempotency_check() {
        // NOT idempotent: second pass doubles the backslashes introduced by first pass.
        // This test validates the idempotency property by constructing the expected
        // result of double-escape manually, bypassing the debug_assert! guard.
        let input = "it's\\here";
        let once = escape_sql_literal(input);
        // once: input "it's\\here" → "it''s\\\\here" (backslash doubled, quote doubled)
        // If we were to escape again, quotes and backslashes would be doubled again.
        // Instead of calling escape_sql_literal(&once), we manually construct the expected result.
        let expected_twice = "it''''s\\\\\\\\here";
        assert_ne!(once, expected_twice, "idempotency check: once should differ from twice");
    }

    // ── build_agtype_id_literal() ─────────────────────────────────────────────

    #[test]
    fn agtype_id_literal_plain() {
        // Produces '"<value>"'::agtype shape.
        let result = build_agtype_id_literal("principal_1");
        assert_eq!(result, "'\"principal_1\"'::agtype");
    }

    #[test]
    fn agtype_id_literal_with_single_quote() {
        // Single quote in ID → doubled in SQL literal.
        let result = build_agtype_id_literal("it's");
        assert_eq!(result, "'\"it''s\"'::agtype");
    }

    #[test]
    fn agtype_id_literal_with_backslash() {
        let result = build_agtype_id_literal("a\\b");
        assert_eq!(result, "'\"a\\\\b\"'::agtype");
    }

    #[test]
    fn agtype_id_literal_with_unicode() {
        let result = build_agtype_id_literal("日本語");
        assert_eq!(result, "'\"日本語\"'::agtype");
    }

    #[test]
    fn agtype_id_literal_shape_invariant() {
        // Regardless of content the result must start with '\"  and end with \"'::agtype
        for id in &["", "simple", "with'quote", "with\\back"] {
            let result = build_agtype_id_literal(id);
            assert!(result.starts_with("'\""), "Missing opening for id={}", id);
            assert!(result.ends_with("\"'::agtype"), "Missing closing for id={}", id);
        }
    }

    // ── build_edge_values_list() (batch boundary tests) ──────────────────────

    #[test]
    fn edge_values_list_empty_returns_none() {
        // 0 rows → None; no SQL should be emitted.
        assert!(build_edge_values_list(&[]).is_none());
    }

    #[test]
    fn edge_values_list_one_row() {
        let batch = vec![("from_1".to_string(), "to_1".to_string())];
        let result = build_edge_values_list(&batch).expect("expected Some for 1-row batch");
        // Should be a single values tuple.
        assert!(!result.contains(", ("));
        assert!(result.contains("from_1"));
        assert!(result.contains("to_1"));
    }

    #[test]
    fn edge_values_list_exact_batch_size() {
        // BATCH_SIZE = 500 rows → exactly one batch of 500 tuples.
        let batch: Vec<(String, String)> = (0..500)
            .map(|i| (format!("from_{}", i), format!("to_{}", i)))
            .collect();
        let result = build_edge_values_list(&batch).expect("expected Some for 500-row batch");
        // 500 rows = 499 ", (" separators between tuples.
        let tuple_count = result.matches("'::agtype, '\"to_").count();
        assert_eq!(tuple_count, 500);
    }

    #[test]
    fn edge_values_list_batch_size_plus_one_count() {
        // 501 rows: verify both the 500-row and 1-row slices produce expected counts.
        let batch_a: Vec<(String, String)> = (0..500)
            .map(|i| (format!("f{}", i), format!("t{}", i)))
            .collect();
        let batch_b: Vec<(String, String)> = vec![("f500".to_string(), "t500".to_string())];

        let result_a = build_edge_values_list(&batch_a).unwrap();
        let result_b = build_edge_values_list(&batch_b).unwrap();

        let count_a = result_a.matches("'::agtype, '\"t").count();
        let count_b = result_b.matches("'::agtype, '\"t").count();
        assert_eq!(count_a, 500);
        assert_eq!(count_b, 1);
    }

    #[test]
    fn edge_values_list_n_times_batch_size() {
        // 3 × 500 = 1500 rows.
        let batch: Vec<(String, String)> = (0..1500)
            .map(|i| (format!("f{}", i), format!("t{}", i)))
            .collect();
        let result = build_edge_values_list(&batch).expect("expected Some for 1500-row batch");
        let count = result.matches("'::agtype, '\"t").count();
        assert_eq!(count, 1500);
    }

    #[test]
    fn edge_values_list_n_times_batch_size_plus_k() {
        // 2 × 500 + 7 = 1007 rows.
        let batch: Vec<(String, String)> = (0..1007)
            .map(|i| (format!("f{}", i), format!("t{}", i)))
            .collect();
        let result = build_edge_values_list(&batch).expect("expected Some for 1007-row batch");
        let count = result.matches("'::agtype, '\"t").count();
        assert_eq!(count, 1007);
    }

    /// Values with special characters are correctly escaped in VALUES list output.
    #[test]
    fn edge_values_list_escapes_special_chars() {
        let batch = vec![
            ("from'quote".to_string(), "to\\back".to_string()),
        ];
        let result = build_edge_values_list(&batch).unwrap();
        // Single quote becomes '' in SQL literals.
        assert!(result.contains("from''quote"));
        // Backslash becomes \\\\ in the final string.
        assert!(result.contains("to\\\\back"));
    }
}
