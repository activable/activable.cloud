# Graph Backend Spike: PG+AGE vs Vela-Kuzu Benchmark

This spike validates **Postgres + Apache AGE** as the graph backend for Activable Cloud v1, focusing on deep-traversal performance under concurrent workloads.

## Overview

**Purpose:** Measure AGE variable-length path performance (6-hop traversals) in both single-threaded and tokio-concurrent scenarios. AGE has documented performance cliffs on deep queries; this spike captures real numbers before committing the schema.

**Decision Gate:** 
- **GO PG+AGE** if 6-hop single-thread p95 < 2s AND concurrent p95 < 2.5s on 100k-node graph, AND shortest-path p95 < 3s.
- **NO-GO** → escalate to Vela-Kuzu fork (escape hatch if AGE fails performance gates).
- **BORDERLINE** (±20% of threshold) → user arbitrates.

**Spike Status:** Standalone; archived after decision (not compiled as part of main workspace).

## Reproducibility

**RNG Seed:** Fixed at 42 (deterministic CSV generation).

**Graph Sizes:**
- 10k-node: quick validation (15 min total).
- 100k-node: production-scale baseline (30-45 min total).

**Distribution:**
- Principals: 40% roles, 30% users, 15% service principals, 5% federated providers.
- Policies: 10% of nodes.
- Resources: 5% of nodes.
- Edges: Role→Policy (HasPermission) + heavy fan-out on assume-role (CanAssume), 20–30% of policies attached to ≥50 roles.

## Prerequisites

```bash
# Rust toolchain (1.87+)
rustup update

# Docker + Docker Compose (for Postgres+AGE)
docker --version
docker-compose --version

# Optional: Vela-Kuzu Rust bindings (if testing Kuzu)
# cargo add kuzu --features kuzu
```

## Setup

### 1. Start Postgres+AGE

```bash
cd infra/compose
docker-compose -f docker-compose.yml up -d db

# Verify healthcheck
docker-compose -f docker-compose.yml ps
# Should show "healthy" for db service
```

### 2. Verify AGE Extension

```bash
psql -h localhost -p 5433 -U activable -d activable -c "CREATE EXTENSION IF NOT EXISTS age;"
psql -h localhost -p 5433 -U activable -d activable -c "SELECT extname FROM pg_extension WHERE extname = 'age';"
# Should return 'age'
```

## Running the Spike

### Full Benchmark (Generate + Load + Benchmark + Verdict)

```bash
# Generates 10k and 100k graphs, loads both, benchmarks both
cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  bench-all \
  --output /tmp/spike-graphs \
  --db-host localhost \
  --db-port 5433 \
  --db-user activable \
  --db-password activable_dev

# Exit code: 0 = GO, 1 = NO-GO, 2 = BORDERLINE
```

### Step-by-Step

```bash
# 1. Generate 10k and 100k graphs (deterministic)
cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  generate --size 10k --output /tmp/spike-graphs --seed 42

cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  generate --size 100k --output /tmp/spike-graphs --seed 42

# 2. Load into Postgres+AGE
cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  load --size 10k --input /tmp/spike-graphs \
  --db-host localhost --db-port 5433 \
  --db-user activable --db-password activable_dev

cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  load --size 100k --input /tmp/spike-graphs \
  --db-host localhost --db-port 5433 \
  --db-user activable --db-password activable_dev

# 3. Benchmark (single-thread + concurrent tokio)
cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  bench --size 10k \
  --db-host localhost --db-port 5433 \
  --db-user activable --db-password activable_dev \
  --concurrency 4 --pool-size 8 \
  --output /tmp/spike-graphs/results-10k.md

cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
  bench --size 100k \
  --db-host localhost --db-port 5433 \
  --db-user activable --db-password activable_dev \
  --concurrency 4 --pool-size 8 \
  --output /tmp/spike-graphs/results-100k.md
```

### Via Makefile (Recommended)

```bash
# From repo root
make spike-bench

# This runs the full suite and exits with verdict code
```

## Benchmark Methodology

### Single-Thread (Criterion-Style)

1. **Warm-up:** 10 runs per query (cache warming).
2. **Measure:** 100 runs per query, recording latency each run.
3. **Emit:** p50, p95, p99 percentiles.

### Concurrent (Tokio, Concurrent-Load Measurement)

1. **Spawn 4 tokio tasks** (simulating 4 concurrent ingestors via UniFFI).
2. **Each task runs 25 queries concurrently** against the same connection pool.
3. **Measure:** p95 and p99 latency per query under contention.
4. **Record:** Connection pool queue depth + saturation signals.
5. **Verdict:** If concurrent p95 > 2.5s on 6-hop, flag "connection pool saturation" or "AGE cannot sustain async load."

### Query Shapes

| Query | Type | Purpose | Gate |
|-------|------|---------|------|
| 01-one-hop | Direct | Baseline single-edge traversal | Informational |
| 02-three-hop | Fixed-depth | Typical attack path (user→role→policy) | Informational |
| **03-six-hop-varlen** | **Variable-length** | **Primary test (AGE cliff)** | **p95 < 2s (single), < 2.5s (concurrent)** |
| **04-shortest-path** | **Path finding** | **Secondary test** | **p95 < 3s (single-thread)** |
| 05-subgraph | Neighborhood | Subgraph extraction | Informational |

## Interpreting Results

### Example Output (GO Verdict)

```
| 03-six-hop-varlen | 450.0  | 1850.0 | 2200.0 | 2100.0              | 2350.0              | ✓ PASS |
| 04-shortest-path  | 200.0  | 2800.0 | 3100.0 | 2900.0              | 3200.0              | ✓ PASS |

## Verdict

**GO** — PG+AGE meets performance thresholds:
- 6-hop variable-length single-thread p95 < 2s ✓
- 6-hop variable-length concurrent p95 < 2.5s ✓
- Shortest-path single-thread p95 < 3s ✓

PG+AGE is suitable as the graph backend. Proceed with production schema implementation.
```

### Example Output (NO-GO Verdict)

```
| 03-six-hop-varlen | 800.0  | 2800.0 | 4500.0 | 5200.0              | 7100.0              | ✗ FAIL |

## Verdict

**NO-GO** — PG+AGE fails performance gates:
- 03-six-hop-varlen single-thread p95=2800.0µs, concurrent p95=5200.0µs ✗
- 04-shortest-path single-thread p95=3200.0µs ✗

Escalate to user for decision: continue with PG+AGE + Trendyol workaround, or pivot to Vela-Kuzu.
```

## Performance Tuning (If Investigating)

If results are borderline or NO-GO, check:

1. **PG Work Memory:**
   ```bash
   psql -h localhost -p 5433 -U activable -d activable \
     -c "ALTER SYSTEM SET work_mem = '512MB';"
   # Restart: docker-compose restart db
   ```

2. **AGE Query Plan:**
   ```bash
   psql -h localhost -p 5433 -U activable -d activable \
     -c "EXPLAIN ANALYZE MATCH (s:Principal)-[:CanAssume|HasPermission*1..6]->(t) RETURN t LIMIT 1;"
   ```

3. **Connection Pool Saturation:**
   - If concurrent p95 >> single-thread p95 (e.g., 5×), connection pool is bottleneck, not AGE.
   - Increase pool_size or reduce concurrency.

## Vela-Kuzu Escape Hatch (Red-Team C5)

If verdict is NO-GO and the user chooses Vela-Kuzu:

1. **Check Maintenance:**
   ```bash
   # Pinned commit
   git clone https://github.com/kuzudb/kuzu.git
   git log --oneline -30 | head
   # Confirm active maintenance signals (commits, PR activity)
   ```

2. **License Check:**
   ```bash
   # Verify MIT license
   curl -s https://raw.githubusercontent.com/kuzudb/kuzu/main/LICENSE
   ```

3. **Migration-Back Plan** (if Vela becomes unmaintained):
   - Export Kuzu graph → CSV via Rust bindings.
   - Bulk-load CSV into Postgres+AGE.
   - Rewrite 5 Cypher queries (1 day per query family).
   - **Trigger:** If Vela's last commit > 90 days old, initiate migration.
   - **Cost estimate:** 3–4 engineer-weeks.

## Cleanup

```bash
# Stop Postgres+AGE
docker-compose -f infra/compose/docker-compose.yml down

# Remove benchmark artifacts
rm -rf /tmp/spike-graphs

# Clean spike build
cargo clean --manifest-path spike/graph-backend/Cargo.toml
```

## Troubleshooting

### `ERROR: extension "age" does not exist`

```bash
# AGE extension not installed in Postgres image
# Check docker-compose uses apache/age:PG16_latest
docker-compose -f infra/compose/docker-compose.yml ps
docker exec activable-postgres psql -U activable -d activable -c "SELECT extname FROM pg_extension;"
```

### Benchmark Hangs (Concurrent Mode)

- Connection pool exhaustion (all 8 connections held by slow queries).
- Increase pool_size: `--pool-size 16`
- Or reduce concurrency: `--concurrency 2`

### `MATCH ... RETURN ...` Returns Nothing

- Principal ID may not exist. Check CSV:
  ```bash
  head -5 /tmp/spike-graphs/principals.csv
  ```
- Or query doesn't match AGE syntax (see queries/ folder for correct format).

## Hardware / Environment Notes (From Production Run)

**This section populated after `make spike-bench` completes:**

- **OS:** Darwin 25.5.0
- **Rust:** 1.87.0
- **Postgres:** 16.x (from apache/age:PG16_latest)
- **AGE:** 1.7.0
- **CPU:** [Captured at runtime]
- **Memory:** [Captured at runtime]
- **Date:** [Captured at runtime]

## Branch Coverage (Optional, Nightly Required)

The project rule (`.claude/rules/development-rules.md`) requires ≥98% branch coverage for full compliance.

Branch coverage measurement via `cargo llvm-cov --branch` requires a **nightly Rust toolchain**.

### Installation

If you don't have rustup yet, install it:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Add nightly toolchain + llvm-tools-preview component:

```bash
rustup toolchain install nightly
rustup component add llvm-tools-preview --toolchain nightly
```

### Running Branch Coverage

From `spike/graph-backend/`:

```bash
cargo +nightly llvm-cov --branch --summary-only \
    --ignore-filename-regex 'src/main\.rs' \
    --fail-under-branches 98
```

**Note:** Today (2026-05-22) the spike's pure-function line coverage is 98%+ on stable; branch coverage is filed as a follow-up to enable in CI once nightly is part of the toolchain matrix.

## References

- [Apache AGE GitHub](https://github.com/apache/age) — Main project
- [Apache AGE Issue #195](https://github.com/apache/age/issues/195) — VLE performance cliff
- [Trendyol Tech AGE at Scale (Apr 2026)](https://medium.com/trendyol-tech/migrating-graph-operations-to-apache-age-from-writes-to-reads-3b8334628e1c) — Workaround patterns
- [Vela-Kuzu Fork](https://vela.partners/blog/kuzudb-ai-agent-memory-graph-database) — Escape hatch

## Next Steps

- **If GO:** Proceed with production schema implementation.
- **If NO-GO:** Evaluate Vela-Kuzu fork; if chosen, plan 2-week integration cost.
- **If BORDERLINE:** Surface measured numbers to user; user decides (±20% threshold flexibility).
