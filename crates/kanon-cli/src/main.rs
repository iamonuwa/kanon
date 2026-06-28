//! Kanon command line.
//!
//! A thin wrapper over `kanon-core` (the verifier) and `kanon-gen` (the generator). It parses
//! arguments, resolves the system clock for bare payloads, calls the library half, and maps the
//! outcome to a stable exit code. It contains no verification logic of its own.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use kanon_cli::{check_corpus, generate_corpus, verify_json, BareOptions};

const DEFAULT_OUT: &str = "vectors/x402/exact/evm/eip3009";
const DEFAULT_CORPUS_DIR: &str = "vectors";

/// Generate and verify Kanon x402 v2 exact / EVM / EIP-3009 test vectors.
#[derive(Parser)]
#[command(name = "kanon", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write the test vector corpus to disk.
    Generate(GenerateArgs),
    /// Verify a vector file or a bare x402 payload and print the verdict.
    Verify(VerifyArgs),
    /// Verify every vector in a directory against its declared verdict.
    CheckCorpus(CheckCorpusArgs),
}

#[derive(Args)]
struct GenerateArgs {
    /// Output directory for the vector files.
    #[arg(long, default_value = DEFAULT_OUT)]
    out: PathBuf,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to a vector file or bare payload JSON, or `-` for stdin.
    path: String,
    /// Verification time in unix seconds (bare payloads only). Defaults to the system clock.
    #[arg(long, conflicts_with = "no_time")]
    now: Option<i64>,
    /// Omit the verification time entirely, skipping temporal checks (bare payloads only).
    #[arg(long)]
    no_time: bool,
    /// A consumed nonce for the replay check, repeatable (bare payloads only).
    #[arg(long = "seen-nonce")]
    seen_nonce: Vec<String>,
    /// File of newline delimited consumed nonces (bare payloads only).
    #[arg(long = "seen-nonces")]
    seen_nonces: Option<PathBuf>,
    /// Target CAIP-2 network for the network mismatch check (bare payloads only).
    #[arg(long)]
    network: Option<String>,
}

#[derive(Args)]
struct CheckCorpusArgs {
    /// Directory of vectors to check, searched recursively.
    #[arg(long, default_value = DEFAULT_CORPUS_DIR)]
    dir: PathBuf,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Generate(args) => run_generate(&args.out),
        Command::Verify(args) => run_verify(args),
        Command::CheckCorpus(args) => run_check_corpus(&args.dir),
    }
}

/// Writes the corpus, printing each path. Exit 0 on success, 1 on failure.
fn run_generate(out: &Path) -> ExitCode {
    match generate_corpus(out) {
        Ok(paths) => {
            for path in paths {
                println!("wrote {}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Verifies one document. Exit 0 valid, 1 invalid, 2 malformed input.
fn run_verify(args: VerifyArgs) -> ExitCode {
    let text = match read_source(&args.path) {
        Ok(text) => text,
        Err(err) => return malformed(&err),
    };
    let seen_nonces = match collect_seen_nonces(&args) {
        Ok(nonces) => nonces,
        Err(err) => return malformed(&err),
    };

    // The clock default for bare payloads is applied here so kanon-core stays clock free.
    let verification_time = if args.no_time {
        None
    } else {
        Some(args.now.unwrap_or_else(system_now))
    };
    let options = BareOptions {
        verification_time,
        seen_nonces,
        target_network: args.network.clone(),
    };

    match verify_json(&text, &options) {
        Ok(outcome) => {
            if outcome.was_vector && args.now.is_some() {
                eprintln!("warning: --now is ignored for vector input; using the vector's context");
            }
            match serde_json::to_string(&outcome.verdict) {
                Ok(json) => println!("{json}"),
                Err(err) => return malformed(&anyhow::Error::new(err)),
            }
            if outcome.verdict.valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => malformed(&err),
    }
}

/// Checks every vector under `dir`. Exit 0 all match, 1 any mismatch, 2 malformed.
fn run_check_corpus(dir: &Path) -> ExitCode {
    match check_corpus(dir) {
        Ok(outcome) => {
            for entry in &outcome.entries {
                let status = if entry.matched { "ok" } else { "MISMATCH" };
                eprintln!(
                    "{status}: {} (declared {:?}, actual {:?})",
                    entry.path.display(),
                    entry.declared.reason_code,
                    entry.actual.reason_code
                );
            }
            let passed = outcome.entries.iter().filter(|e| e.matched).count();
            println!(
                "{{\"checked\":{},\"passed\":{}}}",
                outcome.entries.len(),
                passed
            );
            if outcome.all_matched() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => malformed(&err),
    }
}

/// Prints a malformed-input error to stderr and returns exit code 2.
fn malformed(err: &anyhow::Error) -> ExitCode {
    eprintln!("error: {err:#}");
    ExitCode::from(2)
}

/// Reads the document text from a path, or stdin when the path is `-`.
fn read_source(path: &str) -> anyhow::Result<String> {
    use anyhow::Context as _;
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
    }
}

/// Collects the consumed-nonce set from repeated flags and an optional file.
fn collect_seen_nonces(args: &VerifyArgs) -> anyhow::Result<Vec<String>> {
    use anyhow::Context as _;
    let mut nonces = args.seen_nonce.clone();
    if let Some(path) = &args.seen_nonces {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                nonces.push(trimmed.to_string());
            }
        }
    }
    Ok(nonces)
}

/// The current unix time in seconds, or 0 if the clock is before the epoch.
fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
