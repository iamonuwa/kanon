//! Feeds arbitrary bytes through vector parsing and verification.
//!
//! The verifier processes adversarial input by design, so any panic here is a bug: malformed
//! input must resolve to a parse error, a typed `VerifyError`, or a verdict. The committed
//! vectors under `vectors/` make a useful seed corpus.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(vector) = serde_json::from_slice::<kanon_core::Vector>(data) {
        let _ = kanon_core::verify(&vector.input, &vector.context, Some(&vector.network));
        let _ = kanon_core::verify(&vector.input, &vector.context, None);
    }
});
