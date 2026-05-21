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
/// AGE uses single-quoted strings; escape ' as \'.
fn escape_cypher(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Escape a value for embedding inside an agtype string literal in SQL.
/// Used in the SQL fast-path edge loader where values appear inside '\"...\"'::agtype.
fn escape_sql_literal(s: &str) -> String {
    // In the SQL string '\"value\"'::agtype, the outer quotes are SQL single-quotes.
    // We need to escape both backslashes and single-quotes for SQL safety.
    s.replace('\\', "\\\\").replace('\'', "''")
}
