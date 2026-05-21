# Profiling Guide

**Stub** — not yet implemented.

This document will cover:
- Cross-FFI flame graphs (Rust + Go combined)
- pprof analysis of Go goroutines and memory
- perf tracing of Postgres+AGE queries
- Identifying bottlenecks in the ingestion pipeline

Profiling walkthrough will be added after ingestion is implemented, when there is meaningful performance-critical code to measure.

---

See [System Architecture](./system-architecture.md) for runtime topology and [Deployment Guide](./deployment-guide.md) for binary optimization.
