use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod bench;
mod generate_synthetic_graph;
mod load_pg_age;

use generate_synthetic_graph::{GeneratorConfig, output_dir_for_size};

#[derive(Parser)]
#[command(name = "spike")]
#[command(about = "Graph backend spike: benchmark PG+AGE vs Vela-Kuzu")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(global = true, long, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate synthetic graph CSV files
    Generate {
        /// Output directory for CSV files
        #[arg(short, long, default_value = "/tmp/spike-graphs")]
        output: PathBuf,

        /// Graph size: "10k" or "100k"
        #[arg(short, long, value_parser = ["10k", "100k"])]
        size: String,

        /// RNG seed for reproducibility
        #[arg(long, default_value = "42")]
        seed: u64,

        /// Print graph statistics instead of generating
        #[arg(long)]
        stats_only: bool,
    },

    /// Load synthetic graph into Postgres+AGE
    Load {
        /// Graph CSV input directory
        #[arg(short, long, default_value = "/tmp/spike-graphs")]
        input: PathBuf,

        /// Database host
        #[arg(long, default_value = "localhost")]
        db_host: String,

        /// Database port
        #[arg(long, default_value = "5433")]
        db_port: u16,

        /// Database user
        #[arg(long, default_value = "activable")]
        db_user: String,

        /// Database password
        #[arg(long, default_value = "activable_dev")]
        db_password: String,

        /// Database name
        #[arg(long, default_value = "activable")]
        db_name: String,

        /// Graph size label (used to locate size-specific CSV files)
        #[arg(short, long, value_parser = ["10k", "100k"])]
        size: String,
    },

    /// Run benchmarks (single-thread + concurrent) against a loaded graph
    Bench {
        /// Graph size (used for labelling output only)
        #[arg(short, long, value_parser = ["10k", "100k"])]
        size: String,

        /// Database host
        #[arg(long, default_value = "localhost")]
        db_host: String,

        /// Database port
        #[arg(long, default_value = "5433")]
        db_port: u16,

        /// Database user
        #[arg(long, default_value = "activable")]
        db_user: String,

        /// Database password
        #[arg(long, default_value = "activable_dev")]
        db_password: String,

        /// Database name
        #[arg(long, default_value = "activable")]
        db_name: String,

        /// Connection pool size
        #[arg(long, default_value = "8")]
        pool_size: usize,

        /// Number of concurrent tokio tasks (each runs 25 queries)
        #[arg(long, default_value = "4")]
        concurrency: usize,

        /// Write results to this file (in addition to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Run the full spike pipeline: generate → load → bench for both 10k and 100k.
    /// Writes spike/graph-backend/results.md (relative to current working directory).
    BenchAll {
        /// Temporary directory for graph CSV files
        #[arg(short, long, default_value = "/tmp/spike-graphs")]
        output: PathBuf,

        /// Database host
        #[arg(long, default_value = "localhost")]
        db_host: String,

        /// Database port
        #[arg(long, default_value = "5433")]
        db_port: u16,

        /// Database user
        #[arg(long, default_value = "activable")]
        db_user: String,

        /// Database password
        #[arg(long, default_value = "activable_dev")]
        db_password: String,

        /// Database name
        #[arg(long, default_value = "activable")]
        db_name: String,

        /// RNG seed for reproducible graph generation
        #[arg(long, default_value = "42")]
        seed: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(cli.log_level)
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Generate {
            output,
            size,
            seed,
            stats_only,
        } => {
            info!(size = %size, seed = seed, "Generating synthetic graph");
            std::fs::create_dir_all(&output).context("Failed to create output directory")?;
            let config = GeneratorConfig::from_size_string(&size, seed);
            generate_synthetic_graph::generate(&output, &config, stats_only)
                .context("Failed to generate graph")?;
        }

        Commands::Load {
            input,
            db_host,
            db_port,
            db_user,
            db_password,
            db_name,
            size,
        } => {
            info!(
                host = %db_host,
                port = db_port,
                user = %db_user,
                db = %db_name,
                size = %size,
                "Loading graph into Postgres+AGE"
            );
            load_pg_age::load(
                &input,
                &db_host,
                db_port,
                &db_user,
                &db_password,
                &db_name,
                &size,
            )
            .await
            .context("Failed to load graph")?;
            info!("Graph loaded successfully");
        }

        Commands::Bench {
            size,
            db_host,
            db_port,
            db_user,
            db_password,
            db_name,
            pool_size,
            concurrency,
            output,
        } => {
            info!(
                size = %size,
                concurrency = concurrency,
                pool_size = pool_size,
                "Running benchmarks (single-thread + concurrent)"
            );
            let results = bench::run_benchmarks(
                &db_host,
                db_port,
                &db_user,
                &db_password,
                &db_name,
                &size,
                pool_size,
                concurrency,
            )
            .await
            .context("Benchmarks failed")?;

            println!("\n{}", results);

            if let Some(output_path) = output {
                std::fs::write(&output_path, &results)
                    .context("Failed to write results")?;
                info!(path = ?output_path, "Results written");
            }

            let exit_code = bench::verdict_gate(&results);
            std::process::exit(exit_code);
        }

        Commands::BenchAll {
            output,
            db_host,
            db_port,
            db_user,
            db_password,
            db_name,
            seed,
        } => {
            info!("Running full spike: generate + load + benchmark for 10k and 100k");
            std::fs::create_dir_all(&output).context("Failed to create output directory")?;

            // Collect system metadata for results.md header
            let host_info = collect_host_info();

            // Generate each graph size into its own subdirectory so the 100k run
            // does not overwrite the 10k CSVs before the 10k load step executes.
            for size in ["10k", "100k"] {
                let size_dir = output_dir_for_size(&output, size);
                std::fs::create_dir_all(&size_dir)
                    .context(format!("Failed to create output directory for {} graph", size))?;
                info!("=== Generating {}-node graph → {} ===", size, size_dir.display());
                let config = GeneratorConfig::from_size_string(size, seed);
                generate_synthetic_graph::generate(&size_dir, &config, false)
                    .context(format!("Failed to generate {} graph", size))?;
            }

            let mut combined_md = String::new();
            combined_md.push_str("# Graph Backend Spike — Full Results\n\n");
            combined_md.push_str(&host_info);
            combined_md.push_str("\n\n");
            combined_md.push_str("**Backend:** Postgres+AGE  \n");
            combined_md.push_str("**PG version:** 16.10  \n");
            combined_md.push_str("**AGE version:** 1.6.0  \n\n");
            combined_md.push_str("---\n\n");

            let mut final_verdict = String::new();

            for size in ["10k", "100k"] {
                // Each size reads from its own subdirectory, preventing cross-contamination.
                let size_dir = output_dir_for_size(&output, size);
                info!("=== Loading {}-node graph from {} ===", size, size_dir.display());
                load_pg_age::load(
                    &size_dir,
                    &db_host,
                    db_port,
                    &db_user,
                    &db_password,
                    &db_name,
                    size,
                )
                .await
                .context(format!("Failed to load {} graph", size))?;

                info!("=== Benchmarking {}-node graph ===", size);
                let results = bench::run_benchmarks(
                    &db_host,
                    db_port,
                    &db_user,
                    &db_password,
                    &db_name,
                    size,
                    8,
                    4,
                )
                .await
                .context(format!("Benchmarks failed for {} graph", size))?;

                println!("\n{}", results);

                // Write per-size results file into the size-scoped subdirectory.
                let size_dir = output_dir_for_size(&output, size);
                let results_path = size_dir.join(format!("results-{}.md", size));
                std::fs::write(&results_path, &results)
                    .context(format!("Failed to write {} results", size))?;
                info!(path = ?results_path, "Per-size results written");

                combined_md.push_str(&format!("## {} Graph\n\n", size.to_uppercase()));
                combined_md.push_str(&results);
                combined_md.push_str("\n---\n\n");

                // Save 100k verdict for the canonical summary
                if size == "100k" {
                    final_verdict = extract_verdict_section(&results);
                }
            }

            // Append canonical verdict summary (100k numbers are the gate)
            combined_md.push_str("## Canonical Verdict (100k graph, gate thresholds)\n\n");
            combined_md.push_str(&final_verdict);

            // Write canonical results.md in spike/graph-backend/ relative to CWD.
            // The bench-all pipeline is always invoked from the repo root, so this
            // resolves to activable.cloud/spike/graph-backend/results.md.
            let canonical_path = PathBuf::from("spike/graph-backend/results.md");
            std::fs::write(&canonical_path, &combined_md)
                .context("Failed to write spike/graph-backend/results.md")?;
            info!(path = ?canonical_path, "Canonical results.md written");

            println!("\n=== Spike complete. Canonical results: {} ===", canonical_path.display());

            let exit_code = bench::verdict_gate(&combined_md);
            std::process::exit(exit_code);
        }
    }

    Ok(())
}

/// Collect hostname, OS, CPU, and RAM for the results header.
/// Uses /proc/cpuinfo + /proc/meminfo on Linux; sysctl on macOS (container is Linux).
fn collect_host_info() -> String {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let os = std::fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("PRETTY_NAME="))
        .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown OS".to_string());

    // CPU: first model name line from /proc/cpuinfo
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("model name"))
        .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_else(|| {
            // macOS fallback (Docker host)
            std::process::Command::new("sysctl")
                .args(["-n", "machdep.cpu.brand_string"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .unwrap_or_else(|| "unknown CPU".to_string())
                .trim()
                .to_string()
        });

    // RAM: MemTotal from /proc/meminfo in GiB
    let ram_gib = std::fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| format!("{:.1} GiB", kb as f64 / 1_048_576.0))
        .unwrap_or_else(|| "unknown".to_string());

    // CPU count
    let cpu_count = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();

    format!(
        "**Host:** {}  \n**OS:** {}  \n**CPU:** {} × {}  \n**RAM:** {}",
        hostname, os, cpu_count, cpu, ram_gib
    )
}

/// Extract the ## Verdict section from a results markdown string.
fn extract_verdict_section(results_md: &str) -> String {
    let mut in_verdict = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in results_md.lines() {
        if line.starts_with("## Verdict") {
            in_verdict = true;
        }
        if in_verdict {
            // Stop at the next ## heading (other than Verdict itself)
            if line.starts_with("## ") && !line.starts_with("## Verdict") {
                break;
            }
            lines.push(line);
        }
    }
    if lines.is_empty() {
        "Verdict section not found in benchmark output.\n".to_string()
    } else {
        lines.join("\n") + "\n"
    }
}
