fn main() {
    let directive = std::env::var("SVC_DIRECTIVE")
        .unwrap_or_else(|_| r#"{"tiers":[],"persistence":[],"uninstall":false,"rate_limit_ms":0}"#.to_string());
    std::env::remove_var("SVC_DIRECTIVE");
    svc_payload::run(directive.as_bytes());
}
