//! Kanon command line.
//!
//! Wraps the generator and the verifier. It writes the corpus and verifies individual vectors.
//! It adds no verification logic of its own, the generator and verifier meet only at the JSON.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};

const DEFAULT_OUT: &str = "vectors/x402/exact/evm/eip3009";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    let rest: Vec<String> = args.collect();

    let result = match command.as_deref() {
        Some("generate") => generate(&rest),
        Some("verify") => verify_file(&rest),
        other => {
            usage(other);
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Prints usage to stderr.
fn usage(unknown: Option<&str>) {
    if let Some(cmd) = unknown {
        eprintln!("unknown command `{cmd}`");
    }
    eprintln!("usage:");
    eprintln!("  kanon generate [--out <dir>]   write the corpus (default dir: {DEFAULT_OUT})");
    eprintln!("  kanon verify <file>            verify one vector and print its verdict");
}

/// Generates the corpus and writes one JSON file per vector.
fn generate(rest: &[String]) -> Result<()> {
    let out = out_dir(rest);
    let corpus = kanon_gen::build_corpus().map_err(|e| anyhow!("building corpus: {e}"))?;
    std::fs::create_dir_all(&out)
        .with_context(|| format!("creating output directory {}", out.display()))?;

    for vector in &corpus {
        let path = out.join(format!("{}.json", vector.id));
        let mut json = serde_json::to_string_pretty(vector)
            .with_context(|| format!("serializing {}", vector.id))?;
        json.push('\n');
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// Verifies a single vector file and prints the verdict as JSON.
fn verify_file(rest: &[String]) -> Result<()> {
    let file = rest
        .iter()
        .next()
        .ok_or_else(|| anyhow!("verify: missing <file> argument"))?;
    let path = Path::new(file);
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let vector: kanon_core::Vector =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

    let verdict = kanon_core::verify(&vector.network, &vector.input, &vector.context)
        .with_context(|| format!("verifying {}", path.display()))?;

    println!("{}", serde_json::to_string(&verdict)?);
    Ok(())
}

/// Resolves the output directory from the arguments, defaulting to `vectors`.
fn out_dir(rest: &[String]) -> PathBuf {
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        if arg == "--out" {
            if let Some(dir) = it.next() {
                return PathBuf::from(dir);
            }
        }
    }
    PathBuf::from(DEFAULT_OUT)
}
