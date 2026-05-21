# Code Standards

This document defines naming, style, and formatting conventions across the Activable codebase (Rust + Go + docs).

## Naming Conventions — Full Words

Use **full English words**. Code is read 100× more often than typed; clarity wins.

### Banned Shortenings

| Banned | Use Instead |
|--------|------------|
| `tmpl` | `template` |
| `mgr` | `manager` |
| `svc` | `service` |
| `cfg` | `config` |
| `pwd` | `password` |
| `req`/`res` | `request`/`response` |
| `evt` | `event` |
| `addr` | `address` |
| `db` | `database` |
| `op` | `operation` |
| `auth` | `authentication` / `authorization` |

### Allowed Abbreviations

These are standard and acceptable:
- UID, URL, URI, JWT, API, SDK, JSON, YAML, XML, HTTP, TCP, IP, TLS, SSL, DNS, UUID, SHA256, RBAC, CRUD
- `ctx` (context — idiomatic in Rust/Go), `err` (error), `i`/`j`/`k` (loop indices), `t` (test receiver), `buf` (buffer), `n` (count)

### Applies To

- Variable names, function names, type names
- Schema table and column names
- HTTP route names
- CLI subcommands
- RBAC permissions
- Audit-event types
- Commit messages and PR titles
- File and directory names (see below)

## File Naming

Use **kebab-case** with long, descriptive names. File names are self-documenting for LLM tools.

### Rust

```rust
// ❌ Bad
src/arn.rs
src/graph_driver.rs

// ✅ Good
src/arn-parser.rs                     // Long descriptive name
src/graph-postgres-age-driver.rs      // Includes technology
```

### Go

```go
// ❌ Bad
internal/ingest/ingester.go
internal/telemetry/setup.go

// ✅ Good (if > 200 lines, split further)
internal/ingest/aws-ingestor.go
internal/ingest/aws-ingestor_test.go
internal/telemetry/otel-setup.go
```

### Scripts & Docs

```bash
# ✅ Good
scripts/check-dco.sh
scripts/test-ffi-stability.sh
scripts/size-check.sh

docs/deployment-guide.md
docs/debugging.md
docs/code-standards.md
```

## Rust Conventions

### Formatting

- **Formatter**: `cargo fmt` (enforce with pre-commit hook)
- **Line length**: 100 characters (default rustfmt)
- **Naming**: `snake_case` for functions, variables, modules; `PascalCase` for types, traits

### Linting

- **Linter**: `cargo clippy --all-targets -- -D warnings`
- **Config**: `Cargo.toml` `[workspace.lints]` section
- **Workspace pedantic**: enabled with reasonable opt-outs (see `Cargo.toml`)

### Documentation

- Every public module should have a module-level doc comment (`//!`)
- Every public function should have a doc comment (`///`)
- Examples in doc comments are encouraged
- Use `# Errors` sections for functions that return `Result<T, E>`

```rust
/// Parses an ARN into canonical form.
///
/// # Arguments
/// * `arn_string` — the raw ARN to parse
///
/// # Errors
/// Returns an error if the ARN format is invalid.
///
/// # Example
/// ```
/// let arn = parse_arn("arn:aws:iam::123456789012:user/Test")?;
/// assert_eq!(arn.service, "iam");
/// ```
pub fn parse_arn(arn_string: &str) -> Result<Arn, ParseError> {
    // ...
}
```

## Go Conventions

### Formatting

- **Formatter**: `gofmt` (enforce with pre-commit hook)
- **Linter**: `golangci-lint` (`.golangci.yml` if custom config)
- **Naming**: `camelCase` for functions, variables; `PascalCase` for exported types; `ALL_CAPS` for constants

### Imports

Use `gofmt` organization:
```go
import (
    // stdlib
    "context"
    "encoding/json"
    "fmt"

    // third-party (alphabetical)
    "github.com/spf13/cobra"
    "go.opentelemetry.io/otel"

    // internal
    "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)
```

### Error Handling

- Always check errors explicitly; no silent failures
- Use `fmt.Errorf` for context-rich errors
- Wrap errors with context: `fmt.Errorf("ingest AWS account: %w", err)`

```go
// ❌ Bad
data, _ := fetchFromAWS()

// ✅ Good
data, err := fetchFromAWS()
if err != nil {
    return fmt.Errorf("fetch from AWS: %w", err)
}
```

### Testing

- Test files: `*_test.go` in same package
- Table-driven tests for multiple scenarios
- Use `t.Run()` for subtests

```go
func TestIngestor(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        wantErr bool
    }{
        {"valid", "arn:aws:iam::123456789012:role/MyRole", false},
        {"invalid", "not-an-arn", true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // ...
        })
    }
}
```

## Documentation

- **Markdown** (`.md`) files use GFM (GitHub Flavored Markdown)
- **Code blocks** include language: ` ```go `, ` ```rust `, ` ```bash `
- **Architecture diagrams** use Mermaid or ASCII art
- **Examples** are copy-paste-ready

## File Size Management

- **Rust modules**: keep under 200 lines; split along logical boundaries
- **Go packages**: keep under 200 lines per file; extract utility funcs to separate files
- **Exception**: config files (Makefile, YAML, toml) may exceed 200 lines

## Comments & Docstrings

- **Rust**: use `///` for public items, `//!` for module docs
- **Go**: use `//` (single-line) or `/* */` (multi-line) comments above the declaration
- Every public symbol should be documented
- Comments explain *why*, not *what* (code should be self-documenting)

```rust
// ❌ Bad
// Increment x
x += 1;

// ✅ Good
// Advance to the next edge in the traversal
x += 1;
```

## Pre-Commit Hooks

Before every commit:

1. **Rust**: `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings`
2. **Go**: `gofmt -l ./go && golangci-lint run ./go/...`
3. **DCO**: commit message must contain `Signed-off-by:` trailer (use `git commit -s`)

Install hooks with `make setup`.

## CI Checks

All of the above are enforced in GitHub Actions CI. PRs must pass:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `go test -race ./go/...`
- `gofmt` (no formatting issues)
- `golangci-lint run ./go/...`
- DCO sign-off on every commit
- Binary size check (≤ 50MB stripped)
- FFI stability test (concurrent goroutines calling Rust)

## Exceptions

- SPDX license headers in source files (Apache 2.0)
- Ignored code inside conditional compilation (`#[cfg(...)]`) can have TODO comments for deferred work
- Slice-B-stub crate (`activable-iam-eval`) can have unimplemented!() in stub functions **only** — marked with `// SLICE-B-STUB:` comment

## Questions?

See [CLAUDE.md](../CLAUDE.md) §0.5 (Naming convention) for the source of truth.
