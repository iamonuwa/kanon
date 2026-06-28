//! Library half of the Kanon CLI.
//!
//! This holds the pure, testable logic: normalizing an input document to the verifier's `Input`,
//! building the verification context, and running the corpus check. The binary (`src/main.rs`)
//! parses arguments, resolves the system clock, and maps outcomes to exit codes. No verification
//! logic lives here beyond calling `kanon_core::verify`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _, Result};
use kanon_core::{Context, Expected, Input, Vector};

/// Resolved options for verifying a bare x402 payload.
///
/// The clock default for `verification_time` is applied by the caller, so this type carries an
/// already-resolved value and stays free of any clock access.
#[derive(Debug, Default)]
pub struct BareOptions {
    /// The verification time, or `None` to skip temporal checks.
    pub verification_time: Option<i64>,
    /// The consumed-nonce set for the replay check.
    pub seen_nonces: Vec<String>,
    /// The target network for the network-mismatch check, or `None` to skip it.
    pub target_network: Option<String>,
}

/// The result of verifying one JSON document.
pub struct VerifyOutcome {
    /// The verifier's verdict.
    pub verdict: Expected,
    /// Whether the document was a vector file (true) or a bare payload (false).
    pub was_vector: bool,
}

/// Verifies a JSON document that is either a vector file or a bare x402 payment object.
///
/// Detection is structural: a top-level `input` field means a vector file, whose embedded
/// `context` and target `network` are used and `bare` is ignored. Otherwise the document must be
/// a bare payment object (top-level `payload` and `accepted`), verified with `bare`.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed, matches neither shape, or the verifier rejects
/// the document as unparseable.
pub fn verify_json(text: &str, bare: &BareOptions) -> Result<VerifyOutcome> {
    let value: serde_json::Value = serde_json::from_str(text).context("parsing JSON")?;

    if value.get("input").is_some() {
        let vector: Vector = serde_json::from_value(value).context("parsing vector")?;
        let verdict = kanon_core::verify(&vector.input, &vector.context, Some(&vector.network))?;
        Ok(VerifyOutcome {
            verdict,
            was_vector: true,
        })
    } else if value.get("payload").is_some() && value.get("accepted").is_some() {
        let input: Input = serde_json::from_value(value).context("parsing payload")?;
        let ctx = Context {
            verification_time: bare.verification_time,
            seen_nonces: bare.seen_nonces.clone(),
        };
        let verdict = kanon_core::verify(&input, &ctx, bare.target_network.as_deref())?;
        Ok(VerifyOutcome {
            verdict,
            was_vector: false,
        })
    } else {
        Err(anyhow!(
            "JSON matches neither a vector (top-level `input`) nor a bare payload (top-level `payload` and `accepted`)"
        ))
    }
}

/// Builds the corpus and writes one pretty JSON file per vector under `out`.
///
/// # Errors
///
/// Returns an error if building the corpus, creating the directory, or writing a file fails.
pub fn generate_corpus(out: &Path) -> Result<Vec<PathBuf>> {
    let corpus = kanon_gen::build_corpus().map_err(|e| anyhow!("building corpus: {e}"))?;
    std::fs::create_dir_all(out)
        .with_context(|| format!("creating output directory {}", out.display()))?;

    let mut written = Vec::new();
    for vector in &corpus {
        let path = out.join(format!("{}.json", vector.id));
        let json = kanon_gen::vector_to_json(vector)
            .with_context(|| format!("serializing {}", vector.id))?;
        std::fs::write(&path, &json).with_context(|| format!("writing {}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

/// One vector's result within a corpus check.
pub struct CorpusEntry {
    /// The vector file path.
    pub path: PathBuf,
    /// Whether the actual verdict matched the declared one.
    pub matched: bool,
    /// The verdict the verifier returned.
    pub actual: Expected,
    /// The verdict the vector declares.
    pub declared: Expected,
}

/// The result of checking every vector in a directory.
pub struct CorpusOutcome {
    /// One entry per vector, in sorted path order.
    pub entries: Vec<CorpusEntry>,
}

impl CorpusOutcome {
    /// Whether every vector's actual verdict matched its declared verdict.
    pub fn all_matched(&self) -> bool {
        self.entries.iter().all(|entry| entry.matched)
    }
}

/// Verifies every `*.json` vector under `dir` (searched recursively) against its declared verdict.
///
/// Each vector is verified with its own embedded `context` and target `network`, never the system
/// clock, so the check is reproducible.
///
/// # Errors
///
/// Returns an error if the directory cannot be read, or a file cannot be read, parsed, or verified.
pub fn check_corpus(dir: &Path) -> Result<CorpusOutcome> {
    let mut files = Vec::new();
    collect_json_files(dir, &mut files)?;
    files.sort();

    let mut entries = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        // The corpus directory is vectors-only by contract. A `*.json` that does not parse as a
        // vector is an error, never silently skipped: skipping could drop a real vector while the
        // gate stayed green.
        let vector: Vector = serde_json::from_str(&text).with_context(|| {
            format!(
                "{} could not be parsed as a vector; only vector JSON may live under the corpus directory",
                path.display()
            )
        })?;
        let actual = kanon_core::verify(&vector.input, &vector.context, Some(&vector.network))
            .with_context(|| format!("verifying {}", path.display()))?;
        let declared = vector.expected;
        entries.push(CorpusEntry {
            matched: actual == declared,
            path,
            actual,
            declared,
        });
    }
    Ok(CorpusOutcome { entries })
}

/// Recursively collects `*.json` file paths under `dir`.
fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let reader =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in reader {
        let entry = entry.with_context(|| format!("reading an entry in {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspecting {}", path.display()))?;
        if file_type.is_dir() {
            collect_json_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    Ok(())
}
