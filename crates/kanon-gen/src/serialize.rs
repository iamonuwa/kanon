//! Canonical serialization of a vector to its on-disk form.
//!
//! This is the single source of truth for how the generator renders a vector to JSON, so the
//! writer and the reproducibility test agree byte for byte. It is generator-internal formatting,
//! not verification logic.

use crate::model::Vector;

/// Renders a vector to its committed file form: pretty JSON with a trailing newline.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] if serialization fails (not expected for the typed model).
pub fn vector_to_json(vector: &Vector) -> serde_json::Result<String> {
    let mut json = serde_json::to_string_pretty(vector)?;
    json.push('\n');
    Ok(json)
}
