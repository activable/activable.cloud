# Apache AGE — index migration limitations

**Date:** 2026-05-24
**Discovered during:** ingester-surface live verification
**Status:** Known limitation; workaround deferred to load-test phase

## What we tried

Ingester startup attempts the following Cypher (intended to create idempotent indexes for the per-label `id` property — needed for the 1000-principal performance SLO):

```sql
SELECT * FROM cypher('activable', $$
  CREATE INDEX IF NOT EXISTS ON :Principal(id)
$$) AS (r agtype);
```

…repeated for `:Permission`, `:Bucket`, `:KmsKey`, `:Policy`.

## What happened

All five statements return `db error` from `tokio_postgres`. The runtime catches the error and logs a `WARN` line per statement, then continues — the server boots fine and ingestion works. The indexes are simply not created.

```
WARN  index migration skipped — label table may not exist yet
      error="db error"
      stmt="SELECT * FROM cypher('activable', $$ CREATE INDEX IF NOT EXISTS ON :Principal(id) $$) AS (r agtype)"
```

## Why

Apache AGE's Cypher implementation does not accept the openCypher `CREATE INDEX` syntax. AGE indexes have to be created at the underlying Postgres level on AGE's vertex-storage tables, e.g.:

```sql
CREATE INDEX IF NOT EXISTS principal_id_idx
  ON activable."Principal" USING BTREE ((properties->>'id'));
```

…but those tables only exist after AGE has created at least one node of that label. On a fresh cluster, the tables don't exist yet, so the index DDL fails.

## Workaround options (any later phase)

1. **Two-phase migration:** create label tables explicitly via `SELECT create_vlabel('activable', 'Principal');` before the index DDL, then run the Postgres `CREATE INDEX`. AGE provides `create_vlabel`/`create_elabel` for exactly this case.
2. **On-write indexing:** drop the explicit index migration; rely on AGE's built-in label-table indexing, which covers the `_ag_label_id` column. Measure query latency on a 1000-principal graph; if it meets the SLO, indexes are not needed.
3. **JSONB GIN index** on the properties column: `CREATE INDEX ... USING GIN(properties)` — index hits any property key, not just `id`. Higher write cost but fewer per-property indexes.

## Decision

Defer the workaround to the load-test phase (Phase 4 carries the 1000-principal SLO). The current ingester-surface dispatch ships the WARN-and-continue fallback so the server doesn't crash. If the load test fails the SLO, revisit option (1) or (3) above.

## Acceptance for now

The WARN logs are visible in ops dashboards. The function call chain still terminates with `info!("index migrations complete")` so the no-op state is observable.
